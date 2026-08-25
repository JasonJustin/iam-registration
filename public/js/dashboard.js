const $ = (id) => document.getElementById(id);

// JWT is kept only in memory for this page's lifetime — never in
// localStorage/sessionStorage, per the assignment's security requirement.
let jwtToken = null;
let jwtExpiresAt = null;

async function api(path, body, method = "POST", headers = {}) {
  const res = await fetch(path, {
    method,
    headers: body ? { "Content-Type": "application/json", ...headers } : headers,
    body: body ? JSON.stringify(body) : undefined,
    credentials: "include",
  });
  let data = {};
  try {
    data = await res.json();
  } catch (_) {}
  return { ok: res.ok, status: res.status, data };
}

async function loadSession() {
  const { ok, data } = await api("/api/me", null, "GET");
  if (!ok) {
    window.location.href = "/index.html";
    return;
  }
  const u = data.user;
  $("welcome-name").textContent = `Welcome, ${u.name.split(" ")[0]}`;
  $("d-name").textContent = u.name;
  $("d-email").textContent = u.email;
  $("d-phone").textContent = u.phone;
  $("d-id").textContent = u.id;
  $("d-mfa").textContent = u.mfaEnabled ? "Enabled" : "Disabled";
  $("jwt-password").dataset.email = u.email;
  $("dashboard-card").style.display = "block";
}

document.querySelectorAll(".toggle-visibility").forEach((btn) => {
  btn.addEventListener("click", () => {
    const input = $(btn.dataset.target);
    const isHidden = input.type === "password";
    input.type = isHidden ? "text" : "password";
    btn.textContent = isHidden ? "Hide" : "Show";
  });
});

$("logout-btn").addEventListener("click", async () => {
  await api("/api/logout", {});
  window.location.href = "/index.html";
});

$("get-token-btn").addEventListener("click", async () => {
  const email = $("jwt-password").dataset.email;
  const password = $("jwt-password").value;
  if (!password) {
    $("jwt-output").textContent = "Enter your password first.";
    return;
  }

  const { ok, data } = await api("/api/token", { email, password });
  if (!ok) {
    $("jwt-output").textContent = `Error: ${data.error || "Couldn't issue token."}`;
    return;
  }

  jwtToken = data.token;
  jwtExpiresAt = Date.now() + data.expiresIn * 1000;
  $("call-protected-btn").disabled = false;
  $("jwt-output").textContent =
    `Token issued (kept in memory only, expires in ${data.expiresIn}s):\n${jwtToken}`;
});

$("call-protected-btn").addEventListener("click", async () => {
  if (!jwtToken) return;
  const { ok, status, data } = await api("/api/protected", null, "GET", {
    Authorization: `Bearer ${jwtToken}`,
  });

  if (!ok) {
    $("jwt-output").textContent = `(${status}) Error: ${data.error}`;
    return;
  }

  $("jwt-output").textContent = `(${status}) ${JSON.stringify(data, null, 2)}`;
});

loadSession();
