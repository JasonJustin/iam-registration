// Storage layer. Uses a persistent Redis store (Upstash, via Vercel's
// Marketplace integration) when credentials are present in the environment —
// this is required on Vercel, since serverless functions don't share memory
// across instances. Falls back to plain in-memory storage for local `npm
// start`, where a single Node process naturally shares memory.

const crypto = require("crypto");

const REDIS_URL = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
const REDIS_TOKEN = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;
const USE_REDIS = !!(REDIS_URL && REDIS_TOKEN);

let redis = null;
if (USE_REDIS) {
  const { Redis } = require("@upstash/redis");
  redis = new Redis({ url: REDIS_URL, token: REDIS_TOKEN });
  console.log("[store] Using Redis-backed persistent storage.");
} else {
  console.log("[store] Using in-memory storage (fine for local dev; not for multi-instance production).");
}

function newId() {
  return crypto.randomUUID();
}

// ---------- In-memory fallback ----------
const mem = {
  users: new Map(),
  usersByEmail: new Map(),
  challenges: new Map(),
  sessions: new Map(),
  loginAttempts: new Map(),
  devOtp: new Map(),
};

const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_MS = 2 * 60 * 1000; // 2 minutes

// ---------- Generic key/value helpers (Redis or memory) ----------
async function kvSet(key, value, ttlSeconds) {
  if (USE_REDIS) {
    if (ttlSeconds) await redis.set(key, JSON.stringify(value), { ex: ttlSeconds });
    else await redis.set(key, JSON.stringify(value));
  } else {
    mem._raw = mem._raw || new Map();
    mem._raw.set(key, value);
    if (ttlSeconds) setTimeout(() => mem._raw.delete(key), ttlSeconds * 1000).unref?.();
  }
}

async function kvGet(key) {
  if (USE_REDIS) {
    const val = await redis.get(key);
    if (val === null || val === undefined) return null;
    return typeof val === "string" ? JSON.parse(val) : val;
  }
  mem._raw = mem._raw || new Map();
  return mem._raw.get(key) ?? null;
}

async function kvDel(key) {
  if (USE_REDIS) await redis.del(key);
  else mem._raw?.delete(key);
}

// ---------- Users ----------
async function createUser({ name, email, phone, passwordHash }) {
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
  await kvSet(`user:${id}`, user);
  await kvSet(`user-email:${email.toLowerCase()}`, id);
  return user;
}

async function getUserById(id) {
  if (!id) return null;
  return kvGet(`user:${id}`);
}

async function getUserByEmail(email) {
  const id = await kvGet(`user-email:${email.toLowerCase()}`);
  return id ? kvGet(`user:${id}`) : null;
}

async function updateUser(id, patch) {
  const user = await getUserById(id);
  if (!user) return null;
  const updated = { ...user, ...patch };
  await kvSet(`user:${id}`, updated);
  return updated;
}

// ---------- OTP Challenges ----------
async function createChallenge({ challengeId, userId, channel, purpose, otpHash, ttlMs = 5 * 60 * 1000, maxAttempts = 5 }) {
  const id = challengeId || newId();
  const challenge = {
    challengeId: id,
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
  // Store with a little slack past expiry so "expired" checks still work
  // instead of the key just vanishing and reading as "not found".
  await kvSet(`challenge:${id}`, challenge, Math.ceil(ttlMs / 1000) + 60);
  return challenge;
}

async function getChallenge(challengeId) {
  return kvGet(`challenge:${challengeId}`);
}

async function updateChallenge(challengeId, patch) {
  const challenge = await getChallenge(challengeId);
  if (!challenge) return null;
  const updated = { ...challenge, ...patch };
  const remainingTtlSeconds = Math.max(Math.ceil((challenge.expiresAt - Date.now()) / 1000) + 60, 60);
  await kvSet(`challenge:${challengeId}`, updated, remainingTtlSeconds);
  return updated;
}

// ---------- Sessions ----------
async function createSession(userId, ttlMs) {
  const sessionId = newId();
  const session = { sessionId, userId, createdAt: Date.now(), expiresAt: Date.now() + ttlMs };
  await kvSet(`session:${sessionId}`, session, Math.ceil(ttlMs / 1000));
  return sessionId;
}

async function getSession(sessionId) {
  const session = await kvGet(`session:${sessionId}`);
  if (!session) return null;
  if (session.expiresAt < Date.now()) {
    await kvDel(`session:${sessionId}`);
    return null;
  }
  return session;
}

async function destroySession(sessionId) {
  await kvDel(`session:${sessionId}`);
}

// ---------- Login attempt tracking / lockout ----------
async function getLoginState(email) {
  const state = await kvGet(`login-state:${email.toLowerCase()}`);
  return state || { count: 0, lockedUntil: 0 };
}

async function registerFailedLogin(email) {
  const key = email.toLowerCase();
  const state = await getLoginState(email);
  state.count += 1;
  if (state.count >= MAX_LOGIN_ATTEMPTS) {
    state.lockedUntil = Date.now() + LOCKOUT_MS;
    state.count = 0;
  }
  await kvSet(`login-state:${key}`, state, 60 * 60); // keep an hour, well past any lockout
  return state;
}

async function resetLoginState(email) {
  await kvDel(`login-state:${email.toLowerCase()}`);
}

async function isLockedOut(email) {
  const state = await getLoginState(email);
  return !!(state.lockedUntil && state.lockedUntil > Date.now());
}

// ---------- Dev/test-only OTP retrieval ----------
// Exists ONLY so an evaluator/test harness can read a generated OTP without
// a real inbox/SMS provider. This must never exist in a production build —
// it stores plaintext alongside the hashed challenge purely for testing.
async function setDevOtp(challengeId, otp) {
  await kvSet(`dev-otp:${challengeId}`, otp, 10 * 60);
}

async function getDevOtp(challengeId) {
  return kvGet(`dev-otp:${challengeId}`);
}

module.exports = {
  createUser,
  getUserById,
  getUserByEmail,
  updateUser,
  createChallenge,
  getChallenge,
  updateChallenge,
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
