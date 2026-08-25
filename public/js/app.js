const $ = (id) => document.getElementById(id);

const state = {
  userId: null,
  email: null,
  phone: null,
  regChallengeId: null,
  smsChallengeId: null,
  loginChallengeId: null,
  rememberMe: false,
};

function showScreen(id) {
  document.querySelectorAll(".screen").forEach((el) => el.classList.remove("active"));
  $(id).classList.add("active");
}

async function api(path, body, method = "POST") {
  const res = await fetch(path, {
    method,
    headers: body ? { "Content-Type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined,
    credentials: "include",
  });
  let data = {};
  try {
    data = await res.json();
  } catch (_) {
    /* no body */
  }
  return { ok: res.ok, status: res.status, data };
}

function setError(elId, message) {
  const el = $(elId);
  if (!message) {
    el.style.display = "none";
    el.textContent = "";
    return;
  }
  el.textContent = message;
  el.style.display = "block";
}

function setFieldError(id, message) {
  const el = $(id);
  el.textContent = message || "";
  el.classList.toggle("visible", !!message);
}

function otpErrorMessage(reason) {
  switch (reason) {
    case "expired":
      return "This code has expired. Request a new one.";
    case "max_attempts":
      return "Too many incorrect attempts. Request a new code.";
    case "already_used":
      return "This code has already been used. Request a new one.";
    case "not_found":
      return "This code is no longer valid. Request a new one.";
    case "invalid_code":
    default:
      return "Incorrect code. Try again.";
  }
}

async function fetchDevOtp(challengeId, valueElId) {
  const { ok, data } = await api(`/api/test/get-otp/${challengeId}`, null, "GET");
  if (ok && data.otp) $(valueElId).textContent = data.otp;
}

// ---------------------------------------------------------------------------
// Navigation
// ---------------------------------------------------------------------------

document.querySelectorAll("[data-goto]").forEach((btn) => {
  btn.addEventListener("click", () => showScreen(btn.dataset.goto));
});

document.querySelectorAll(".toggle-visibility").forEach((btn) => {
  btn.addEventListener("click", () => {
    const input = $(btn.dataset.target);
    const isHidden = input.type === "password";
    input.type = isHidden ? "text" : "password";
    btn.textContent = isHidden ? "Hide" : "Show";
  });
});

$("forgot-password").addEventListener("click", () => {
  setError("login-error", "Password reset isn't implemented in this demo.");
});

// ---------------------------------------------------------------------------
// Password strength meter (registration)
// ---------------------------------------------------------------------------

function passwordScore(pw) {
  const checks = [pw.length >= 8, /[A-Z]/.test(pw), /[a-z]/.test(pw), /[0-9]/.test(pw), /[^A-Za-z0-9]/.test(pw)];
  return checks.filter(Boolean).length;
}

$("reg-password").addEventListener("input", (e) => {
  const score = passwordScore(e.target.value);
  const segs = $("reg-strength-bars").querySelectorAll(".strength-seg");
  segs.forEach((seg, i) => {
    if (i >= score) {
      seg.style.background = "";
      return;
    }
    seg.style.background = score <= 2 ? "var(--danger)" : score <= 3 ? "var(--amber)" : "var(--teal)";
  });
});

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

$("register-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  setError("register-error", "");
  ["reg-name", "reg-email", "reg-phone", "reg-password", "reg-confirm"].forEach((id) =>
    setFieldError(`err-${id}`, "")
  );

  const name = $("reg-name").value.trim();
  const email = $("reg-email").value.trim();
  const phone = $("reg-phone").value.trim();
  const password = $("reg-password").value;
  const confirm = $("reg-confirm").value;

  let valid = true;
  if (!name) { setFieldError("err-reg-name", "Enter your full name."); valid = false; }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) { setFieldError("err-reg-email", "Enter a valid email."); valid = false; }
  if (!/^\+?[0-9]{7,15}$/.test(phone)) { setFieldError("err-reg-phone", "Enter a valid phone number."); valid = false; }
  if (passwordScore(password) < 4) { setFieldError("err-reg-password", "Password is too weak."); valid = false; }
  if (confirm !== password) { setFieldError("err-reg-confirm", "Passwords don't match."); valid = false; }
  if (!valid) return;

  const submitBtn = $("register-submit");
  submitBtn.disabled = true;
  submitBtn.textContent = "Creating account…";

  const { ok, data } = await api("/api/register", { name, email, phone, password });

  submitBtn.disabled = false;
  submitBtn.textContent = "Create account";

  if (!ok) {
    setError("register-error", data.error || "Something went wrong.");
    return;
  }

  state.userId = data.userId;
  state.regChallengeId = data.challengeId;
  state.email = email;
  state.phone = phone;

  $("email-otp-dest").textContent = email;
  $("email-otp-input").value = "";
  setError("email-otp-error", "");
  $("email-otp-attempts").textContent = "";
  fetchDevOtp(data.challengeId, "email-otp-value");
  showScreen("screen-email-otp");
});

// ---------------------------------------------------------------------------
// Email OTP
// ---------------------------------------------------------------------------

$("email-otp-copy").addEventListener("click", () => {
  const v = $("email-otp-value").textContent;
  if (v && v !== "------") $("email-otp-input").value = v;
});

$("email-otp-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  setError("email-otp-error", "");
  const otp = $("email-otp-input").value.trim();

  const submitBtn = $("email-otp-submit");
  submitBtn.disabled = true;
  const { ok, data } = await api("/api/verify-email-otp", { challengeId: state.regChallengeId, otp });
  submitBtn.disabled = false;

  if (!ok || !data.success) {
    setError("email-otp-error", otpErrorMessage(data.reason));
    $("email-otp-attempts").textContent =
      typeof data.attemptsRemaining === "number" ? `${data.attemptsRemaining} attempt(s) remaining.` : "";
    return;
  }

  const sms = await api("/api/send-sms-otp", { userId: state.userId });
  if (!sms.ok) {
    setError("email-otp-error", sms.data.error || "Couldn't send SMS code.");
    return;
  }

  state.smsChallengeId = sms.data.challengeId;
  $("sms-otp-dest").textContent = state.phone;
  $("sms-otp-input").value = "";
  setError("sms-otp-error", "");
  $("sms-otp-attempts").textContent = "";
  fetchDevOtp(sms.data.challengeId, "sms-otp-value");
  showScreen("screen-sms-otp");
});

$("email-otp-resend").addEventListener("click", async () => {
  const { ok, data } = await api("/api/send-email-otp", { userId: state.userId, purpose: "registration" });
  if (!ok) return setError("email-otp-error", data.error || "Couldn't resend code.");
  state.regChallengeId = data.challengeId;
  setError("email-otp-error", "");
  $("email-otp-attempts").textContent = "";
  $("email-otp-input").value = "";
  fetchDevOtp(data.challengeId, "email-otp-value");
});

// ---------------------------------------------------------------------------
// SMS OTP
// ---------------------------------------------------------------------------

$("sms-otp-copy").addEventListener("click", () => {
  const v = $("sms-otp-value").textContent;
  if (v && v !== "------") $("sms-otp-input").value = v;
});

$("sms-otp-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  setError("sms-otp-error", "");
  const otp = $("sms-otp-input").value.trim();

  const submitBtn = $("sms-otp-submit");
  submitBtn.disabled = true;
  const { ok, data } = await api("/api/verify-sms-otp", { challengeId: state.smsChallengeId, otp });
  submitBtn.disabled = false;

  if (!ok || !data.success) {
    setError("sms-otp-error", otpErrorMessage(data.reason));
    $("sms-otp-attempts").textContent =
      typeof data.attemptsRemaining === "number" ? `${data.attemptsRemaining} attempt(s) remaining.` : "";
    return;
  }

  showScreen("screen-mfa-enabled");
  setTimeout(() => showScreen("screen-success"), 1100);
});

$("sms-otp-resend").addEventListener("click", async () => {
  const { ok, data } = await api("/api/send-sms-otp", { userId: state.userId });
  if (!ok) return setError("sms-otp-error", data.error || "Couldn't resend code.");
  state.smsChallengeId = data.challengeId;
  setError("sms-otp-error", "");
  $("sms-otp-attempts").textContent = "";
  $("sms-otp-input").value = "";
  fetchDevOtp(data.challengeId, "sms-otp-value");
});

$("go-to-login").addEventListener("click", () => {
  $("login-email").value = state.email || "";
  showScreen("screen-login");
});

// ---------------------------------------------------------------------------
// Login
// ---------------------------------------------------------------------------

$("login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  setError("login-error", "");

  const email = $("login-email").value.trim();
  const password = $("login-password").value;
  const rememberMe = $("login-remember").checked;

  if (!email || !password) {
    setError("login-error", "Enter your email and password.");
    return;
  }

  const submitBtn = $("login-submit");
  submitBtn.disabled = true;
  submitBtn.textContent = "Verifying…";
  const { ok, status, data } = await api("/api/login", { email, password, rememberMe });
  submitBtn.disabled = false;
  submitBtn.textContent = "Sign in";

  if (!ok) {
    if (status === 423) {
      setError("login-error", `Account locked. Try again in ${data.retryInSeconds}s.`);
    } else {
      const extra = typeof data.attemptsRemaining === "number" ? ` (${data.attemptsRemaining} attempt(s) left)` : "";
      setError("login-error", (data.error || "Sign-in failed.") + extra);
    }
    return;
  }

  if (!data.mfaRequired) {
    window.location.href = "/dashboard.html";
    return;
  }

  state.loginChallengeId = data.challengeId;
  state.rememberMe = rememberMe;
  $("login-otp-subtitle").textContent =
    data.method === "sms" ? "A code was sent to your registered phone." : "A code was sent to your registered email.";
  $("login-otp-input").value = "";
  setError("login-otp-error", "");
  $("login-otp-attempts").textContent = "";
  fetchDevOtp(data.challengeId, "login-otp-value");
  showScreen("screen-login-otp");
});

$("login-otp-copy").addEventListener("click", () => {
  const v = $("login-otp-value").textContent;
  if (v && v !== "------") $("login-otp-input").value = v;
});

$("login-otp-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  setError("login-otp-error", "");
  const otp = $("login-otp-input").value.trim();

  const submitBtn = $("login-otp-submit");
  submitBtn.disabled = true;
  const { ok, data } = await api("/api/verify-login-otp", {
    challengeId: state.loginChallengeId,
    otp,
    rememberMe: state.rememberMe,
  });
  submitBtn.disabled = false;

  if (!ok || !data.success) {
    setError("login-otp-error", otpErrorMessage(data.reason));
    $("login-otp-attempts").textContent =
      typeof data.attemptsRemaining === "number" ? `${data.attemptsRemaining} attempt(s) remaining.` : "";
    return;
  }

  window.location.href = "/dashboard.html";
});
