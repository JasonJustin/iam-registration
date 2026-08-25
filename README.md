# IAM Registration & Login Journey

A full registration → MFA → login → session/JWT flow, built with a
Node.js/Express backend and a vanilla HTML/CSS/JS frontend — no framework,
no build step.

## Flow implemented

```
Registration → Email OTP → SMS OTP → MFA enabled → Registration Success → Login
Login → Credentials valid → MFA required → OTP → Session created → Dashboard
```

## Endpoints

| Method | Path                    | Purpose                                  |
|--------|-------------------------|-------------------------------------------|
| POST   | /api/register           | Create account, hash password, send email OTP |
| POST   | /api/send-email-otp     | (Re)issue an email OTP challenge          |
| POST   | /api/verify-email-otp   | Verify email OTP                          |
| POST   | /api/send-sms-otp       | Issue an SMS OTP challenge                |
| POST   | /api/verify-sms-otp     | Verify SMS OTP, enable MFA, finish registration |
| POST   | /api/login              | Validate credentials, check lockout, issue login OTP |
| POST   | /api/verify-login-otp   | Verify login OTP, create session (cookie) |
| GET    | /api/me                 | Return authenticated user (session cookie) |
| POST   | /api/logout             | Destroy session                           |
| POST   | /api/token              | Issue a short-lived JWT (separate flow)   |
| GET    | /api/protected          | Requires `Authorization: Bearer <jwt>`    |
| GET    | /api/test/get-otp/:id   | **Test-only** — returns the generated OTP for a challenge |

## Security notes

- Passwords are hashed with bcrypt before storage.
- OTPs are generated server-side, 6-digit, hashed (salted with the
  challenge id) before storage — never returned in the normal API
  response. Each has a 5-minute expiry and a 5-attempt limit, and is
  single-use (`consumed` flag).
- Login has a failed-attempt counter with a temporary lockout (5 attempts
  → 2-minute lockout), applied to both password login and JWT issuance.
- Sessions use an `HttpOnly`, `SameSite=Lax` cookie; `Secure` is enabled
  automatically in production (`NODE_ENV=production`, e.g. on Vercel).
- JWTs are short-lived (15 minutes) and are **never** stored in
  localStorage/sessionStorage — the dashboard keeps the token only in a
  JS variable for the page's lifetime, per the assignment's requirement.
- Delivery is simulated: OTPs are printed to the server console as
  `[SIMULATED EMAIL]` / `[SIMULATED SMS]`, and are also retrievable via
  the test-only `/api/test/get-otp/:challengeId` endpoint so an evaluator
  (or the demo UI itself) doesn't need a real inbox.

## Run locally

```bash
npm install
npm start
```

Visit http://localhost:4000

## Deploy to Vercel

This is a plain Node/Express app (not Next.js), so the layout is:
- `/public` — static frontend, served automatically by Vercel
- `/api/index.js` — serverless function wrapping the Express API
- `vercel.json` — rewrites `/api/*` to that function

**Steps:**
1. Push this folder to a new GitHub repo.
2. Go to https://vercel.com/new and import the repo.
3. Vercel should detect it as a generic/Node project — no framework
   preset needed. Leave build settings blank (there's no build step).
4. Click **Deploy**.

> Note: storage is in-memory, scoped to a single serverless function
> instance. That's fine for demoing/testing this flow, but data isn't
> guaranteed to persist indefinitely between requests on Vercel's
> serverless platform — for real use, swap `server/store.js` for a
> database (that's the only file with storage logic).

## Project structure

```
server/
  app.js      Express app — all API routes
  store.js    In-memory users / OTP challenges / sessions / lockouts
  otp.js      OTP generation, hashing, simulated delivery
api/
  index.js    Vercel serverless entry point (re-exports server/app.js)
public/
  index.html       Registration + login screens (SPA-style, JS-driven)
  dashboard.html   Authenticated dashboard + JWT demo panel
  css/styles.css
  js/app.js        Registration/login state machine
  js/dashboard.js  Session check, logout, JWT demo
server.js     Local dev entry point (static files + API on one port)
vercel.json   Routes /api/* to the serverless function
```
