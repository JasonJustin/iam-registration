const express = require("express");
const bcrypt = require("bcryptjs");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");

const store = require("./store");
const { generateOtp, hashOtp, verifyOtpHash, simulateSend } = require("./otp");

const JWT_SECRET = process.env.JWT_SECRET || "dev-only-secret-change-me";
const JWT_TTL_SECONDS = 15 * 60; // short-lived, 15 minutes
const SESSION_TTL_MS = 24 * 60 * 60 * 1000; // 1 day
const SESSION_TTL_REMEMBER_MS = 30 * 24 * 60 * 60 * 1000; // 30 days
const SESSION_COOKIE = "sid";
const IS_PROD = process.env.NODE_ENV === "production";

const app = express();
app.use(express.json());
app.use(cookieParser());

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function isValidEmail(email) {
  return typeof email === "string" && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function passwordScore(password) {
  if (typeof password !== "string") return 0;
  const checks = [
    password.length >= 8,
    /[A-Z]/.test(password),
    /[a-z]/.test(password),
    /[0-9]/.test(password),
    /[^A-Za-z0-9]/.test(password),
  ];
  return checks.filter(Boolean).length;
}

function issueOtpChallenge({ userId, channel, purpose, destination }) {
  const otp = generateOtp();
  // Create the challenge first (need its id to salt the hash), then patch the hash in.
  const challenge = store.createChallenge({ userId, channel, purpose, otpHash: "pending" });
  challenge.otpHash = hashOtp(otp, challenge.challengeId);
  simulateSend(channel, destination, otp);
  store.setDevOtp(challenge.challengeId, otp);
  return challenge;
}

// result: { ok: true } | { ok: false, reason: 'not_found'|'already_used'|'expired'|'max_attempts'|'invalid_code' }
function checkOtp(challengeId, code, expectedPurpose) {
  const challenge = store.getChallenge(challengeId);
  if (!challenge) return { ok: false, reason: "not_found" };
  if (expectedPurpose && challenge.purpose !== expectedPurpose) return { ok: false, reason: "not_found" };
  if (challenge.consumed) return { ok: false, reason: "already_used" };
  if (challenge.expiresAt < Date.now()) return { ok: false, reason: "expired" };
  if (challenge.attempts >= challenge.maxAttempts) return { ok: false, reason: "max_attempts" };

  const valid = verifyOtpHash(String(code || ""), challengeId, challenge.otpHash);
  if (!valid) {
    challenge.attempts += 1;
    const reason = challenge.attempts >= challenge.maxAttempts ? "max_attempts" : "invalid_code";
    return { ok: false, reason, attemptsRemaining: Math.max(challenge.maxAttempts - challenge.attempts, 0) };
  }

  challenge.consumed = true;
  return { ok: true, challenge };
}

function requireSession(req, res, next) {
  const sessionId = req.cookies[SESSION_COOKIE];
  const session = sessionId ? store.getSession(sessionId) : null;
  if (!session) return res.status(401).json({ error: "Not authenticated." });
  const user = store.getUserById(session.userId);
  if (!user) return res.status(401).json({ error: "Not authenticated." });
  req.user = user;
  req.session = session;
  next();
}

function requireJwt(req, res, next) {
  const header = req.headers.authorization || "";
  const [scheme, token] = header.split(" ");
  if (scheme !== "Bearer" || !token) {
    return res.status(401).json({ error: "Missing or malformed Authorization header." });
  }
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.jwtPayload = payload;
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid or expired token." });
  }
}

function publicUser(user) {
  return { id: user.id, name: user.name, email: user.email, phone: user.phone, mfaEnabled: user.mfaEnabled };
}

// ---------------------------------------------------------------------------
// 1. Registration
// ---------------------------------------------------------------------------

app.post("/api/register", async (req, res) => {
  const { name, email, phone, password } = req.body || {};

  if (!name || !name.trim()) return res.status(400).json({ error: "Name is required." });
  if (!isValidEmail(email)) return res.status(400).json({ error: "A valid email is required." });
  if (!phone || !/^\+?[0-9]{7,15}$/.test(phone)) {
    return res.status(400).json({ error: "A valid phone number is required." });
  }
  if (passwordScore(password) < 4) {
    return res.status(400).json({ error: "Password is too weak." });
  }
  if (store.getUserByEmail(email)) {
    return res.status(409).json({ error: "An account with this email already exists." });
  }

  const passwordHash = await bcrypt.hash(password, 10);
  const user = store.createUser({ name: name.trim(), email: email.trim(), phone: phone.trim(), passwordHash });

  const challenge = issueOtpChallenge({
    userId: user.id,
    channel: "email",
    purpose: "registration",
    destination: user.email,
  });

  res.status(201).json({
    userId: user.id,
    challengeId: challenge.challengeId,
    channel: "email",
    expiresAt: challenge.expiresAt,
    message: "Account created. Verify your email to continue.",
  });
});

app.post("/api/send-email-otp", (req, res) => {
  const { userId, purpose = "registration" } = req.body || {};
  const user = store.getUserById(userId);
  if (!user) return res.status(404).json({ error: "User not found." });

  const challenge = issueOtpChallenge({ userId, channel: "email", purpose, destination: user.email });
  res.json({ challengeId: challenge.challengeId, channel: "email", expiresAt: challenge.expiresAt });
});

app.post("/api/verify-email-otp", (req, res) => {
  const { challengeId, otp } = req.body || {};
  const result = checkOtp(challengeId, otp, "registration");

  if (!result.ok) {
    const statusMap = { not_found: 404, already_used: 409, expired: 410, max_attempts: 429, invalid_code: 400 };
    return res.status(statusMap[result.reason] || 400).json({
      success: false,
      reason: result.reason,
      attemptsRemaining: result.attemptsRemaining,
    });
  }

  store.updateUser(result.challenge.userId, { emailVerified: true });
  res.json({ success: true, next: "sms-otp" });
});

app.post("/api/send-sms-otp", (req, res) => {
  const { userId } = req.body || {};
  const user = store.getUserById(userId);
  if (!user) return res.status(404).json({ error: "User not found." });
  if (!user.emailVerified) return res.status(400).json({ error: "Verify email before requesting an SMS code." });

  const challenge = issueOtpChallenge({ userId, channel: "sms", purpose: "registration", destination: user.phone });
  res.json({ challengeId: challenge.challengeId, channel: "sms", expiresAt: challenge.expiresAt });
});

app.post("/api/verify-sms-otp", (req, res) => {
  const { challengeId, otp } = req.body || {};
  const result = checkOtp(challengeId, otp, "registration");

  if (!result.ok) {
    const statusMap = { not_found: 404, already_used: 409, expired: 410, max_attempts: 429, invalid_code: 400 };
    return res.status(statusMap[result.reason] || 400).json({
      success: false,
      reason: result.reason,
      attemptsRemaining: result.attemptsRemaining,
    });
  }

  const user = store.updateUser(result.challenge.userId, { phoneVerified: true, mfaEnabled: true });
  res.json({ success: true, message: "Registration complete.", user: publicUser(user) });
});

// ---------------------------------------------------------------------------
// Test-only: retrieve a generated OTP (simulated delivery, no real inbox/SMS)
// ---------------------------------------------------------------------------

app.get("/api/test/get-otp/:challengeId", (req, res) => {
  const otp = store.getDevOtp(req.params.challengeId);
  if (!otp) return res.status(404).json({ error: "No OTP found for this challenge." });
  res.json({ otp });
});

// ---------------------------------------------------------------------------
// 3. Login
// ---------------------------------------------------------------------------

app.post("/api/login", async (req, res) => {
  const { email, password, rememberMe, method } = req.body || {};

  if (!isValidEmail(email) || !password) {
    return res.status(400).json({ error: "Email and password are required." });
  }

  if (store.isLockedOut(email)) {
    const state = store.getLoginState(email);
    const retryInSeconds = Math.ceil((state.lockedUntil - Date.now()) / 1000);
    return res.status(423).json({ error: "Account temporarily locked due to failed attempts.", retryInSeconds });
  }

  const user = store.getUserByEmail(email);
  const dummyHash = "$2a$10$invalidinvalidinvalidinvalidinvalidinvalid";
  const matches = await bcrypt.compare(password, user ? user.passwordHash : dummyHash);

  if (!user || !matches) {
    const state = store.registerFailedLogin(email);
    if (state.lockedUntil && state.lockedUntil > Date.now()) {
      const retryInSeconds = Math.ceil((state.lockedUntil - Date.now()) / 1000);
      return res.status(423).json({ error: "Account temporarily locked due to failed attempts.", retryInSeconds });
    }
    const attemptsRemaining = Math.max(store.MAX_LOGIN_ATTEMPTS - state.count, 0);
    return res.status(401).json({ error: "Incorrect email or password.", attemptsRemaining });
  }

  store.resetLoginState(email);

  if (!user.mfaEnabled) {
    // Shouldn't normally happen since registration always enables MFA,
    // but handle gracefully rather than assuming.
    const ttl = rememberMe ? SESSION_TTL_REMEMBER_MS : SESSION_TTL_MS;
    const sessionId = store.createSession(user.id, ttl);
    res.cookie(SESSION_COOKIE, sessionId, { httpOnly: true, secure: IS_PROD, sameSite: "lax", maxAge: ttl });
    return res.json({ mfaRequired: false, user: publicUser(user) });
  }

  const channel = method === "sms" ? "sms" : "email";
  const destination = channel === "sms" ? user.phone : user.email;
  const challenge = issueOtpChallenge({ userId: user.id, channel, purpose: "login", destination });

  res.json({
    mfaRequired: true,
    method: channel,
    challengeId: challenge.challengeId,
    expiresAt: challenge.expiresAt,
    rememberMe: !!rememberMe,
  });
});

app.post("/api/verify-login-otp", (req, res) => {
  const { challengeId, otp, rememberMe } = req.body || {};
  const result = checkOtp(challengeId, otp, "login");

  if (!result.ok) {
    const statusMap = { not_found: 404, already_used: 409, expired: 410, max_attempts: 429, invalid_code: 400 };
    return res.status(statusMap[result.reason] || 400).json({
      success: false,
      reason: result.reason,
      attemptsRemaining: result.attemptsRemaining,
    });
  }

  const user = store.getUserById(result.challenge.userId);
  const ttl = rememberMe ? SESSION_TTL_REMEMBER_MS : SESSION_TTL_MS;
  const sessionId = store.createSession(user.id, ttl);

  res.cookie(SESSION_COOKIE, sessionId, {
    httpOnly: true,
    secure: IS_PROD,
    sameSite: "lax",
    maxAge: ttl,
  });

  res.json({ success: true, user: publicUser(user) });
});

// ---------------------------------------------------------------------------
// 4. Session-based auth
// ---------------------------------------------------------------------------

app.get("/api/me", requireSession, (req, res) => {
  res.json({ user: publicUser(req.user) });
});

app.post("/api/logout", (req, res) => {
  const sessionId = req.cookies[SESSION_COOKIE];
  if (sessionId) store.destroySession(sessionId);
  res.clearCookie(SESSION_COOKIE, { httpOnly: true, secure: IS_PROD, sameSite: "lax" });
  res.json({ success: true });
});

// ---------------------------------------------------------------------------
// 4b. JWT-based auth (separate, independent protected flow)
// ---------------------------------------------------------------------------

app.post("/api/token", async (req, res) => {
  const { email, password } = req.body || {};
  if (!isValidEmail(email) || !password) {
    return res.status(400).json({ error: "Email and password are required." });
  }

  if (store.isLockedOut(email)) {
    const state = store.getLoginState(email);
    const retryInSeconds = Math.ceil((state.lockedUntil - Date.now()) / 1000);
    return res.status(423).json({ error: "Account temporarily locked due to failed attempts.", retryInSeconds });
  }

  const user = store.getUserByEmail(email);
  const dummyHash = "$2a$10$invalidinvalidinvalidinvalidinvalidinvalid";
  const matches = await bcrypt.compare(password, user ? user.passwordHash : dummyHash);

  if (!user || !matches) {
    store.registerFailedLogin(email);
    return res.status(401).json({ error: "Incorrect email or password." });
  }

  store.resetLoginState(email);

  const token = jwt.sign({ sub: user.id, email: user.email }, JWT_SECRET, { expiresIn: JWT_TTL_SECONDS });
  res.json({ token, expiresIn: JWT_TTL_SECONDS });
});

app.get("/api/protected", requireJwt, (req, res) => {
  const user = store.getUserById(req.jwtPayload.sub);
  res.json({
    message: "Access granted to protected resource.",
    user: user ? publicUser(user) : null,
    tokenIssuedAt: req.jwtPayload.iat,
    tokenExpiresAt: req.jwtPayload.exp,
  });
});

// ---------------------------------------------------------------------------

app.get("/api/health", (req, res) => res.json({ ok: true }));

module.exports = app;
