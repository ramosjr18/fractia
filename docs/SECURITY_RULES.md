# Security Rules for AI Coding Agents

> These rules are derived from the security auditors in this project. Every AI agent generating code for this codebase **must** follow them. Violations will be flagged automatically by the auditor pipeline.
>
> As of v3.0.0, Fractia enforces two rule sets: **Code Rules** (Node.js/Express) and **Infrastructure Rules** (Linux servers via IronBase Engine).

---

# Part 1 — Code Rules (Node.js / Express)

## 1. Authentication & JWT

- **Never** use a hardcoded fallback for `JWT_SECRET`: `process.env.JWT_SECRET || 'some-secret'` is forbidden. Throw an error at startup if the variable is missing.
- Always pass `{ algorithms: ['HS256'] }` (or the chosen algorithm) to `jwt.verify()`. Never allow the `none` algorithm.
- JWT expiry must not exceed **7 days**. Use short-lived access tokens + refresh tokens.
- Store tokens in `httpOnly`, `secure` cookies — **never** in query parameters or `localStorage`.
- Password hashing must use **bcrypt with ≥ 10 rounds** (12 recommended). Never use `createHash()` for passwords.
- Enforce a minimum password length of **12 characters** in all schemas and validators.
- Implement account **lockout** after repeated failed login attempts.
- Implement **token revocation** via a blacklist or JTI tracking when logout is required.
- Always null-check `req.user` before accessing its properties. Never assume it is populated.
- If MFA is a requirement, use a TOTP library (e.g., `speakeasy`, `otplib`) and enforce OTP expiry.

---

## 2. HTTP Headers & CORS

- Always use **Helmet.js** (or equivalent) to set security headers.
- Never set `CORS origin: "*"` — always allowlist specific origins from environment variables.
- Never use `credentials: true` together with a wildcard origin — this is an invalid and dangerous combination.
- Do not set `Cross-Origin-Resource-Policy: cross-origin` unless explicitly required and reviewed.
- Define a strict **Content-Security-Policy** — do not rely on the Helmet default alone.
- Do not disable **HSTS** (`Strict-Transport-Security`).
- Set `Referrer-Policy` to `no-referrer` or `strict-origin-when-cross-origin` to prevent token leakage via the Referer header.
- Set `Permissions-Policy` to restrict unused browser APIs (camera, microphone, geolocation).
- **Remove** the `X-Powered-By` header — never fingerprint the framework.
- All cookies must have `httpOnly: true` and `secure: true`.

---

## 3. Input Validation & XSS / CSRF

- **Never** reflect `req.body`, `req.params`, or `req.query` directly into `res.send()` or `res.end()` without sanitization.
- Always sanitize HTML output with a library such as DOMPurify, `validator.escape`, or `express-validator`.
- **Never** pass user input directly to a template engine (EJS, Handlebars, Pug) — always escape values.
- **Never** use `innerHTML` with user-controlled data. Prefer `textContent` or a sanitized render.
- **Never** use `document.write()`.
- **Never** use `eval()`, `new Function(string)`, or `vm.runInThisContext()` with user-supplied input.
- When using cookie-based auth, add **CSRF protection** via `csurf` or `doubleCsrf` middleware.

---

## 4. SQL & NoSQL Injection

- **Never** concatenate user input into raw SQL or MongoDB query strings.
- Prefer ORM methods (`Prisma`, `Mongoose` typed queries) over raw queries.
- When raw queries are unavoidable, use **parameterized** forms only (`$queryRaw` tagged template in Prisma — never `$queryRawUnsafe`).
- In multi-tenant architectures, **always** include a `tenantId` filter in every `findMany` / `findFirst` query.
- **Never** pass `JSON.parse()` output directly into a MongoDB query — validate and allowlist operators first.
- Avoid `Model.find({})` with no filters — always scope queries explicitly.
- Sanitize or validate all inputs before they reach a database layer.

---

## 5. Secrets & Credential Leakage

- **Never** hardcode API keys, secrets, passwords, or tokens in source code.
- **Never** use fallback hardcoded secrets: `process.env.SECRET || 'hardcoded'` is forbidden.
- Secrets that must be listed in `.env.example` must use **placeholder values** only (e.g., `JWT_SECRET=CHANGE_ME`).
- Ensure `.env` and `.env.local` are listed in `.gitignore` — never commit them.
- Weak `JWT_SECRET` values such as `dev-`, `test-`, `default-`, `secret`, or `123*` are forbidden in any environment.
- Private keys (PEM format) must never appear in source files.
- MongoDB/PostgreSQL/Redis connection strings with embedded passwords must never appear in source files.
- Do not log secrets, tokens, or passwords — see the Logging section below.

**Patterns that are always forbidden in code:**
```
sk-...          (OpenAI keys)
AKIA...         (AWS Access Key)
ghp_...         (GitHub PAT)
SG....          (SendGrid)
xox...          (Slack)
rk_live_...     (Stripe restricted key)
ya29....        (Google OAuth)
EAA...          (Facebook token)
AC...           (Twilio SID)
-----BEGIN ... PRIVATE KEY-----
```

---

## 6. Cryptography

- **Never** use `MD5` or `SHA1` for any security-sensitive purpose (signatures, integrity checks, password hashing).
- **Never** use `Math.random()` to generate tokens, OTPs, secrets, or nonces — use `crypto.randomBytes()`.
- **Never** hardcode an AES initialization vector (IV) — generate a random IV per encryption operation.
- **Never** use AES in **ECB mode** — use GCM or CBC with a random IV.
- **Never** pass a raw password directly to `createCipheriv()` — derive a key with a KDF (e.g., `scrypt`, `pbkdf2`).
- **Never** use `createHash()` to hash passwords — use `bcrypt`, `scrypt`, or `Argon2`.

---

## 7. Rate Limiting & DDoS Protection

- All APIs must have **rate limiting** via `express-rate-limit` or equivalent.
- Sensitive endpoints (`/register`, `/login`, `/forgot-password`, `/reset-password`) require **stricter limits** than general API endpoints.
- Rate limiters must use a `keyGenerator` based on `userId` (authenticated) or IP (unauthenticated) — not IP alone for authenticated routes.
- Always set `standardHeaders: true` on rate limiters to expose `RateLimit-Remaining` headers.
- Apply at least one rate limiter **globally** in the server entry point.
- Configure `keepAliveTimeout` and `headersTimeout` on the HTTP server to prevent Slowloris attacks.
- If compression middleware is used, enforce a **body size limit** to prevent compression bomb attacks.
- The body parser JSON limit must be **below 5 MB**. Default is fine; only increase with justification.

---

## 8. Route Authorization

- Every route under `/admin` or `/internal` **must** have authentication middleware.
- Use one of the recognized auth middleware names: `authenticate`, `requireAuth`, `isAuthenticated`, `verifyToken`, `authMiddleware`, `checkAuth`, `protect`, `authorize`, `guard`, `requireOrgRole`, `requireModuleRole`, `passport.authenticate`, `ensureLoggedIn`.
- Routes under `/debug`, `/test`, or `/dev` **must not** be exposed in production.
- In multi-tenant apps, enforce a global `tenantContext` or `runInTenantContext` middleware at the router level.
- Use `router.use(authMiddleware)` at the top of a router file to protect all routes in that file — do not rely on per-route decoration only.

---

## 9. Logging & Monitoring

- Use a structured logging library: **winston**, **pino**, **bunyan**, or **morgan**. Never rely on `console.log()` in production controllers or services.
- **Never** log passwords, tokens, API keys, or secrets.
- Implement a `sanitize` / `redact` / `mask` function for any log statement that might contain PII or credentials.
- Propagate a `traceId` / `correlationId` through all workers and async operations.
- Avoid excessive `console.log()` calls — more than 10 per file in controllers/services is a flag.

---

## 10. Infrastructure & Environment (App-Level)

- **Never** expose `--inspect` or `--debug` Node.js flags in production `npm start` scripts.
- Always validate **all required environment variables** at application startup. Fail fast with a clear error message if any are missing.
- Set `NODE_ENV=production` in all production deployments.
- Configure `app.set('trust proxy', 1)` only when behind a known reverse proxy — never use `true` unconditionally.
- **Never** send stack traces to the client in non-development environments. Use a generic error response.
- `.env.example` must never contain real secrets — only placeholder values.

---

## 11. Dependencies

- Run `npm audit` before every release and resolve all **high** and **critical** vulnerabilities.
- Keep the following packages updated, as they have had critical CVEs:
  - `multer` (ReDoS)
  - `jsonwebtoken` (algorithm confusion)
  - `axios` (SSRF, credential leakage)
  - `lodash` / `minimist` (prototype pollution)
  - `express` (path traversal)
  - `semver` (ReDoS)
  - `tough-cookie` (prototype pollution)
- Pin dependency versions in `package.json` and review `package-lock.json` in every PR.

---

## 12. Bot & Abuse Protection

- Endpoints that accept user registration, form submission, or resource-intensive operations must have **CAPTCHA** (reCAPTcHA v3, hCaptcha, Cloudflare Turnstile, or Friendly Captcha).
- Log or filter the `User-Agent` header on sensitive endpoints to detect automation.
- Use a bot-detection library (`isbot`, `@fingerprintjs/botd`) where CAPTCHA is not sufficient.
- Implement login **velocity detection** — detect and alert on repeated failed logins from the same origin.

---

## Quick Reference — Forbidden Code Patterns

| Pattern | Why Forbidden |
|---|---|
| `process.env.SECRET \|\| 'fallback'` | Hardcoded secret fallback |
| `jwt.verify(token, secret)` without `algorithms` | Algorithm confusion / none attack |
| `res.send(req.body.input)` | Reflected XSS |
| `$queryRawUnsafe(...)` | SQL injection |
| `Model.find({})` no filter | Data exposure across tenants |
| `Math.random()` for tokens | Predictable values |
| `createHash('md5')` | Broken hash algorithm |
| `aes-128-ecb` | Deterministic ciphertext leak |
| `origin: '*'` + `credentials: true` | Invalid CORS + auth combo |
| `console.log(password)` | Credential leakage in logs |
| `--inspect` in production | Remote debugger exposure |
| Route `/admin/...` without auth middleware | Privilege escalation |

---

# Part 2 — Infrastructure Rules (Linux Server / IronBase Engine)

> These rules are enforced by IronBase Engine (`engines/ironbase/`). Run via the **Infra Audit** tab in the dashboard or directly with `./engines/ironbase/cmd/ironbase scan`.

## 13. SSH Hardening

- **Never** allow root login via SSH (`PermitRootLogin no`).
- **Never** allow password-based authentication (`PasswordAuthentication no`). Use SSH keys only.
- **Never** allow empty passwords (`PermitEmptyPasswords no`).
- Create a dedicated non-root admin user before disabling root SSH access.
- Always verify key-based access works before applying hardening to avoid lockouts.
- Back up `/etc/ssh/sshd_config` before modifying it.

---

## 14. Firewall (UFW)

- UFW must be **active** on all internet-facing servers.
- Default inbound policy must be **deny** — only explicitly allowed ports should be open.
- Default outbound policy should be **allow** unless restricted access is required.
- **Never** leave conflicting firewall rules (UFW + iptables + Docker) without reconciliation.
- Docker iptables rules must not override UFW policies — configure `DOCKER_OPTS` to respect UFW.
- Regularly audit exposed ports against the actual list of running services.

---

## 15. Filesystem Permissions

- Critical directories (`/`, `/etc`, `/boot`, `/root`, `/var/log`) must have appropriate ownership (root:root) and permissions (750 or stricter for sensitive paths).
- `/usr/bin` and `/usr/sbin` must not be world-writable.
- **Never** leave world-writable directories in the filesystem without explicit justification.
- Audit SUID/SGID binaries regularly — remove or restrict binaries that do not require elevated execution.
- `/root` home directory must not be readable by other users.

---

## 16. User & Privilege Management

- **Never** have two accounts with UID 0 (root duplicates indicate backdoors).
- **Never** have system accounts with empty passwords.
- Regularly audit `/etc/sudoers` and `/etc/sudoers.d/` for overly permissive entries.
- Avoid `NOPASSWD` in sudoers unless strictly necessary and documented.
- Disable or lock accounts that are no longer in use.
- Use the principle of least privilege — no service should run as root if a dedicated user is feasible.

---

## 17. System Configuration

- Keep the OS updated — never run an EOL (End-of-Life) kernel or OS version.
- Configure NTP (`systemd-timesyncd` or `ntpd`) — time synchronization is required for logs and auth tokens.
- Enable and configure `unattended-upgrades` for security patches on Ubuntu/Debian.
- Never run a production server on a kernel that has known critical CVEs without a documented mitigation.

---

## 18. Network Exposure

- Audit all listening ports periodically with `ss -tlnp` or `netstat -tlnp`.
- Services that should only be accessible locally (databases, admin panels) must bind to `127.0.0.1`, not `0.0.0.0`.
- IPv6 must be explicitly configured or disabled — never left in an ambiguous default state.
- Never expose internal services (Redis, PostgreSQL, Elasticsearch) directly to the internet.

---

## 19. Services & Logging

- **auditd** must be installed and running on servers that handle sensitive data.
- **journald** must be configured to persist logs across reboots (`Storage=persistent`).
- Docker daemon must not expose its socket to unauthorized users (`/var/run/docker.sock` permissions).
- Disable or remove services that are not actively used — every running service is an attack surface.

---

## 20. Vulnerability Management

- Run `apt list --upgradable` or equivalent regularly — do not leave known vulnerable packages installed.
- Critical libraries (OpenSSL, sudo, OpenSSH, glibc, polkit) must be kept at their latest stable version.
- Subscribe to Ubuntu Security Notices (USN) or equivalent for the OS in use.
- After patching the kernel, reboot the server — a running kernel is the one being exploited.

---

## Quick Reference — Forbidden Infrastructure Patterns

| Pattern | Why Forbidden |
|---|---|
| `PermitRootLogin yes` in sshd_config | Direct root compromise via SSH |
| `PasswordAuthentication yes` in sshd_config | Brute force via password |
| UFW inactive on internet-facing server | No network perimeter |
| World-writable `/etc` or `/boot` | Full system compromise |
| Duplicate UID 0 accounts | Hidden root backdoor |
| EOL kernel running in production | Known unpatched CVEs |
| Database bound to `0.0.0.0` without firewall | Direct database exposure |
| SUID bit on custom or third-party binaries | Privilege escalation vector |
| auditd not running on sensitive servers | No forensic trail |
| Docker socket world-readable | Container escape to host |

---

*Code rules are enforced by `/auditors/`. Infrastructure rules are enforced by `engines/ironbase/modules/`. Any finding marked as `vulnerability` (not `warning` or `info`) must be resolved before deploying to production.*
