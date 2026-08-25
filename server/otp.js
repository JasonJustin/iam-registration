const crypto = require("crypto");

function generateOtp() {
  // 6-digit numeric OTP
  return String(crypto.randomInt(0, 1000000)).padStart(6, "0");
}

function hashOtp(otp, challengeId) {
  // Salted with the challengeId so identical OTPs don't hash identically.
  return crypto.createHash("sha256").update(`${challengeId}:${otp}`).digest("hex");
}

function verifyOtpHash(otp, challengeId, storedHash) {
  const candidate = hashOtp(otp, challengeId);
  const a = Buffer.from(candidate);
  const b = Buffer.from(storedHash);
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

function simulateSend(channel, destination, otp) {
  if (channel === "email") {
    console.log(`\n[SIMULATED EMAIL]\nTo: ${destination}\nOTP: ${otp}\n`);
  } else {
    console.log(`\n[SIMULATED SMS]\nTo: ${destination}\nOTP: ${otp}\n`);
  }
}

module.exports = { generateOtp, hashOtp, verifyOtpHash, simulateSend };
