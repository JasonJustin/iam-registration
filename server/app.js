const express = require("express");
const bcrypt = require("bcryptjs");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

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

async function issueOtpChallenge({ userId, channel, purpose, destination }) {
  const challengeId = crypto.randomUUID();
  const otp = generateOtp();
  const otpHash = hashOtp(otp, challengeId);
  const challenge = await store.createChallenge({ challengeId, userId, channel, purpose, otpHash });
  simulateSend(channel, destination, otp);
  await store.setDevOtp(challengeId, otp);
  return challenge;
}

// result: { ok: true } | { ok: false, reason: 'not_found'|'already_used'|'expired'|'max_attempts'|'invalid_code' }
async function checkOtp(challengeId, code, expectedPurpose) {
  const challenge = await store.getChallenge(challengeId);
  if (!challenge) return { ok: false, reason: "not_found" };
  if (expectedPurpose && challenge.purpose !== expectedPurpose) return { ok: false, reason: "not_found" };
  if (challenge.consumed) return { ok: false, reason: "already_used" };
  if (challenge.expiresAt < Date.now()) return { ok: false, reason: "expired" };
  if (challenge.attempts >= challenge.maxAttempts) return { ok: false, reason: "max_attempts" };

  const valid = verifyOtpHash(String(code || ""), challengeId, challenge.otpHash);
  if (!valid) {
    const attempts = challenge.attempts + 1;
    await store.updateChallenge(challengeId, { attempts });
    const reason = attempts >= challenge.maxAttempts ? "max_attempts" : "invalid_code";
    return { ok: false, reason, attemptsRemaining: Math.max(challenge.maxAttempts - attempts, 0) };
  }

  const updated = await store.updateChallenge(challengeId, { consumed: true });
  return { ok: true, challenge: updated };
}

async function requireSession(req, res, next) {
  try {
    const sessionId = req.cookies[SESSION_COOKIE];
    const session = sessionId ? await store.getSession(sessionId) : null;
    if (!session) return res.status(401).json({ error: "Not authenticated." });
    const user = await store.getUserById(session.userId);
    if (!user) return res.status(401).json({ error: "Not authenticated." });
    req.user = user;
    req.session = session;
    next();
  } catch (err) {
    res.status(500).json({ error: "Internal error checking session." });
  }
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

const otpErrorStatus = { not_found: 404, already_used: 409, expired: 410, max_attempts: 429, invalid_code: 400 };

// ---------------------------------------------------------------------------
// 1. Registration
// ---------------------------------------------------------------------------

app.post("/api/register", async (req, res) => {
  try {
    const { name, email, phone, password } = req.body || {};

    if (!name || !name.trim()) return res.status(400).json({ error: "Name is required." });
    if (!isValidEmail(email)) return res.status(400).json({ error: "A valid email is required." });
    const normalizedPhone = typeof phone === "string" ? phone.replace(/[\s-]/g, "") : "";
    if (!normalizedPhone || !/^\+?[0-9]{7,15}$/.test(normalizedPhone)) {
      return res.status(400).json({ error: "A valid phone number is required." });
    }
    if (passwordScore(password) < 4) {
      return res.status(400).json({ error: "Password is too weak." });
    }
    if (await store.getUserByEmail(email)) {
      return res.status(409).json({ error: "An account with this email already exists." });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const user = await store.createUser({ name: name.trim(), email: email.trim(), phone: normalizedPhone, passwordHash });

    const challenge = await issueOtpChallenge({
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
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal error during registration." });
  }
});

app.post("/api/send-email-otp", async (req, res) => {
  try {
    const { userId, purpose = "registration" } = req.body || {};
    const user = await store.getUserById(userId);
    if (!user) return res.status(404).json({ error: "User not found." });

    const challenge = await issueOtpChallenge({ userId, channel: "email", purpose, destination: user.email });
    res.json({ challengeId: challenge.challengeId, channel: "email", expiresAt: challenge.expiresAt });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal error sending email OTP." });
  }
});

app.post("/api/verify-email-otp", async (req, res) => {
  try {
    const { challengeId, otp } = req.body || {};
    const result = await checkOtp(challengeId, otp, "registration");

    if (!result.ok) {
      return res.status(otpErrorStatus[result.reason] || 400).json({
        success: false,
        reason: result.reason,
        attemptsRemaining: result.attemptsRemaining,
      });
    }

    await store.updateUser(result.challenge.userId, { emailVerified: true });
    res.json({ success: true, next: "sms-otp" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal error verifying email OTP." });
  }
});

app.post("/api/send-sms-otp", async (req, res) => {
  try {
    const { userId } = req.body || {};
    const user = await store.getUserById(userId);
    if (!user) return res.status(404).json({ error: "User not found." });
    if (!user.emailVerified) return res.status(400).json({ error: "Verify email before requesting an SMS code." });

    const challenge = await issueOtpChallenge({ userId, channel: "sms", purpose: "registration", destination: user.phone });
    res.json({ challengeId: challenge.challengeId, channel: "sms", expiresAt: challenge.expiresAt });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal error sending SMS OTP." });
  }
});

app.post("/api/verify-sms-otp", async (req, res) => {
  try {
    const { challengeId, otp } = req.body || {};
    const result = await checkOtp(challengeId, otp, "registration");

    if (!result.ok) {
      return res.status(otpErrorStatus[result.reason] || 400).json({
        success: false,
        reason: result.reason,
        attemptsRemaining: result.attemptsRemaining,
      });
    }

    const user = await store.updateUser(result.challenge.userId, { phoneVerified: true, mfaEnabled: true });
    res.json({ success: true, message: "Registration complete.", user: publicUser(user) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal error verifying SMS OTP." });
  }
});

// ---------------------------------------------------------------------------
// Test-only: retrieve a generated OTP (simulated delivery, no real inbox/SMS)
// ---------------------------------------------------------------------------

app.get("/api/test/get-otp/:challengeId", async (req, res) => {
  try {
    const otp = await store.getDevOtp(req.params.challengeId);
    if (!otp) return res.status(404).json({ error: "No OTP found for this challenge." });
    res.json({ otp });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal error retrieving test OTP." });
  }
});

// ---------------------------------------------------------------------------
// 3. Login
// ---------------------------------------------------------------------------

app.post("/api/login", async (req, res) => {
  try {
    const { email, password, rememberMe, method } = req.body || {};

    if (!isValidEmail(email) || !password) {
      return res.status(400).json({ error: "Email and password are required." });
    }

    if (await store.isLockedOut(email)) {
      const state = await store.getLoginState(email);
      const retryInSeconds = Math.ceil((state.lockedUntil - Date.now()) / 1000);
      return res.status(423).json({ error: "Account temporarily locked due to failed attempts.", retryInSeconds });
    }

    const user = await store.getUserByEmail(email);
    const dummyHash = "$2a$10$invalidinvalidinvalidinvalidinvalidinvalid";
    const matches = await bcrypt.compare(password, user ? user.passwordHash : dummyHash);

    if (!user || !matches) {
      const state = await store.registerFailedLogin(email);
      if (state.lockedUntil && state.lockedUntil > Date.now()) {
        const retryInSeconds = Math.ceil((state.lockedUntil - Date.now()) / 1000);
        return res.status(423).json({ error: "Account temporarily locked due to failed attempts.", retryInSeconds });
      }
      const attemptsRemaining = Math.max(store.MAX_LOGIN_ATTEMPTS - state.count, 0);
      return res.status(401).json({ error: "Incorrect email or password.", attemptsRemaining });
    }

    await store.resetLoginState(email);

    if (!user.mfaEnabled) {
      // Shouldn't normally happen since registration always enables MFA,
      // but handle gracefully rather than assuming.
      const ttl = rememberMe ? SESSION_TTL_REMEMBER_MS : SESSION_TTL_MS;
      const sessionId = await store.createSession(user.id, ttl);
      res.cookie(SESSION_COOKIE, sessionId, { httpOnly: true, secure: IS_PROD, sameSite: "lax", maxAge: ttl });
      return res.json({ mfaRequired: false, user: publicUser(user) });
    }

    const channel = method === "sms" ? "sms" : "email";
    const destination = channel === "sms" ? user.phone : user.email;
    const challenge = await issueOtpChallenge({ userId: user.id, channel, purpose: "login", destination });

    res.json({
      mfaRequired: true,
      method: channel,
      challengeId: challenge.challengeId,
      expiresAt: challenge.expiresAt,
      rememberMe: !!rememberMe,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal error during login." });
  }
});

app.post("/api/verify-login-otp", async (req, res) => {
  try {
    const { challengeId, otp, rememberMe } = req.body || {};
    const result = await checkOtp(challengeId, otp, "login");

    if (!result.ok) {
      return res.status(otpErrorStatus[result.reason] || 400).json({
        success: false,
        reason: result.reason,
        attemptsRemaining: result.attemptsRemaining,
      });
    }

    const user = await store.getUserById(result.challenge.userId);
    const ttl = rememberMe ? SESSION_TTL_REMEMBER_MS : SESSION_TTL_MS;
    const sessionId = await store.createSession(user.id, ttl);

    res.cookie(SESSION_COOKIE, sessionId, {
      httpOnly: true,
      secure: IS_PROD,
      sameSite: "lax",
      maxAge: ttl,
    });

    res.json({ success: true, user: publicUser(user) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal error verifying login OTP." });
  }
});

// ---------------------------------------------------------------------------
// 4. Session-based auth
// ---------------------------------------------------------------------------

app.get("/api/me", requireSession, (req, res) => {
  res.json({ user: publicUser(req.user) });
});

app.post("/api/logout", async (req, res) => {
  try {
    const sessionId = req.cookies[SESSION_COOKIE];
    if (sessionId) await store.destroySession(sessionId);
    res.clearCookie(SESSION_COOKIE, { httpOnly: true, secure: IS_PROD, sameSite: "lax" });
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal error during logout." });
  }
});

// ---------------------------------------------------------------------------
// 4b. JWT-based auth (separate, independent protected flow)
// ---------------------------------------------------------------------------

app.post("/api/token", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!isValidEmail(email) || !password) {
      return res.status(400).json({ error: "Email and password are required." });
    }

    if (await store.isLockedOut(email)) {
      const state = await store.getLoginState(email);
      const retryInSeconds = Math.ceil((state.lockedUntil - Date.now()) / 1000);
      return res.status(423).json({ error: "Account temporarily locked due to failed attempts.", retryInSeconds });
    }

    const user = await store.getUserByEmail(email);
    const dummyHash = "$2a$10$invalidinvalidinvalidinvalidinvalidinvalid";
    const matches = await bcrypt.compare(password, user ? user.passwordHash : dummyHash);

    if (!user || !matches) {
      await store.registerFailedLogin(email);
      return res.status(401).json({ error: "Incorrect email or password." });
    }

    await store.resetLoginState(email);

    const token = jwt.sign({ sub: user.id, email: user.email }, JWT_SECRET, { expiresIn: JWT_TTL_SECONDS });
    res.json({ token, expiresIn: JWT_TTL_SECONDS });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal error issuing token." });
  }
});

app.get("/api/protected", requireJwt, async (req, res) => {
  try {
    const user = await store.getUserById(req.jwtPayload.sub);
    res.json({
      message: "Access granted to protected resource.",
      user: user ? publicUser(user) : null,
      tokenIssuedAt: req.jwtPayload.iat,
      tokenExpiresAt: req.jwtPayload.exp,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal error accessing protected resource." });
  }
});

// ---------------------------------------------------------------------------

app.get("/api/health", (req, res) => res.json({ ok: true, storage: process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL ? "redis" : "memory" }));

module.exports = app;
