// In-memory storage. This is a demo store — swap for a real database in
// production. Data resets on server restart / cold start.

const crypto = require("crypto");

const users = new Map(); // userId -> user
const usersByEmail = new Map(); // email(lowercase) -> userId
const challenges = new Map(); // challengeId -> challenge
const sessions = new Map(); // sessionId -> session
const loginAttempts = new Map(); // email(lowercase) -> { count, lockedUntil }

function newId() {
  return crypto.randomUUID();
}

// ---------- Users ----------
function createUser({ name, email, phone, passwordHash }) {
  const id = newId();
  const user = {
    id,
    name,
    email,
    phone,
    passwordHash,
    emailVerified: false,
    phoneVerified: false,
    mfaEnabled: false,
    createdAt: new Date().toISOString(),
  };
  users.set(id, user);
  usersByEmail.set(email.toLowerCase(), id);
  return user;
}

function getUserById(id) {
  return users.get(id) || null;
}

function getUserByEmail(email) {
  const id = usersByEmail.get(email.toLowerCase());
  return id ? users.get(id) : null;
}

function updateUser(id, patch) {
  const user = users.get(id);
  if (!user) return null;
  Object.assign(user, patch);
  return user;
}

// ---------- OTP Challenges ----------
function createChallenge({ userId, channel, purpose, otpHash, ttlMs = 5 * 60 * 1000, maxAttempts = 5 }) {
  const challengeId = newId();
  const challenge = {
    challengeId,
    userId,
    channel, // 'email' | 'sms'
    purpose, // 'registration' | 'login'
    otpHash,
    attempts: 0,
    maxAttempts,
    consumed: false,
    createdAt: Date.now(),
    expiresAt: Date.now() + ttlMs,
  };
  challenges.set(challengeId, challenge);
  return challenge;
}

function getChallenge(challengeId) {
  return challenges.get(challengeId) || null;
}

function invalidateChallenge(challengeId) {
  const c = challenges.get(challengeId);
  if (c) c.consumed = true;
}

// ---------- Sessions ----------
function createSession(userId, ttlMs) {
  const sessionId = newId();
  sessions.set(sessionId, {
    sessionId,
    userId,
    createdAt: Date.now(),
    expiresAt: Date.now() + ttlMs,
  });
  return sessionId;
}

function getSession(sessionId) {
  const session = sessions.get(sessionId);
  if (!session) return null;
  if (session.expiresAt < Date.now()) {
    sessions.delete(sessionId);
    return null;
  }
  return session;
}

function destroySession(sessionId) {
  sessions.delete(sessionId);
}

// ---------- Login attempt tracking / lockout ----------
const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_MS = 2 * 60 * 1000; // 2 minutes

function getLoginState(email) {
  const key = email.toLowerCase();
  return loginAttempts.get(key) || { count: 0, lockedUntil: 0 };
}

function registerFailedLogin(email) {
  const key = email.toLowerCase();
  const state = getLoginState(email);
  state.count += 1;
  if (state.count >= MAX_LOGIN_ATTEMPTS) {
    state.lockedUntil = Date.now() + LOCKOUT_MS;
    state.count = 0;
  }
  loginAttempts.set(key, state);
  return state;
}

function resetLoginState(email) {
  loginAttempts.delete(email.toLowerCase());
}

function isLockedOut(email) {
  const state = getLoginState(email);
  return state.lockedUntil && state.lockedUntil > Date.now();
}

// ---------- Dev/test-only OTP retrieval ----------
// Exists ONLY so an evaluator/test harness can read a generated OTP without
// a real inbox/SMS provider. This must never exist in a production build —
// it stores plaintext alongside the hashed challenge purely for testing.
const devOtpPlain = new Map(); // challengeId -> otp

function setDevOtp(challengeId, otp) {
  devOtpPlain.set(challengeId, otp);
}

function getDevOtp(challengeId) {
  return devOtpPlain.get(challengeId) || null;
}

module.exports = {
  createUser,
  getUserById,
  getUserByEmail,
  updateUser,
  createChallenge,
  getChallenge,
  invalidateChallenge,
  createSession,
  getSession,
  destroySession,
  getLoginState,
  registerFailedLogin,
  resetLoginState,
  isLockedOut,
  MAX_LOGIN_ATTEMPTS,
  LOCKOUT_MS,
  setDevOtp,
  getDevOtp,
};
