# FinLexPurple 0.3.0 — Deliberately Vulnerable Test Target

> ⚠️ **DELIBERATELY VULNERABLE. LOCAL USE ONLY.**
> This application contains intentional security flaws (SQL injection, SSRF,
> reflected XSS, IDOR, and several misconfigurations). It exists **only** to QA
> and demo the **FinLexPurple 0.3.0** scanner on your own machine.
>
> - It binds to **`127.0.0.1` (localhost) by default** — never `0.0.0.0`.
> - **Do NOT deploy it to a public or shared server**, a VM with a public IP, a
>   container exposed to a network, or any environment reachable by others.
> - It is a **fictional** "FLP Demo Bank" — not a real bank or payment provider.
>   Do not use it to impersonate any real organization.

---

## Purpose

`finlexpurple-targetwebaap-0.3.0` is a small, self-contained, fintech-flavored
web app (a fake bank/payments demo) used as a **versioned, deliberately
vulnerable target** to test the FinLexPurple scanner **before the 0.3.0
release**.

### Why a separate versioned target per release?

Each FinLexPurple release gets its own pinned target repo (this one tracks
**0.3.0**). Keeping a frozen target per version lets us build a **repeatable
test-dataset over time**: the planted vulnerabilities, seed data, and endpoints
don't drift, so a scan of this target should produce the **same findings every
run**. That makes it possible to:

- confirm a release still detects (and *verifies*) the vulnerability classes it
  claims to,
- catch regressions between releases by diffing scan output against the
  expected results below, and
- demo the scanner against a known-good, reproducible target.

---

## Stack

- **Python 3 + Flask** (web app), **requests** (server-side fetch), **SQLite**
  (seeded demo data). Minimal dependencies, one command to run.

---

## Install & run (localhost only)

```bash
# From the repository root:
./run.sh
```

That creates a local virtualenv, installs dependencies, seeds the database, and
serves the app at **http://127.0.0.1:5000/**.

Or run it manually:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py        # serves on http://127.0.0.1:5000/
```

Optional environment overrides (defaults keep it on localhost):

| Variable          | Default     | Notes                                  |
|-------------------|-------------|----------------------------------------|
| `FLP_TARGET_HOST` | `127.0.0.1` | **Keep as localhost.** Never `0.0.0.0`.|
| `FLP_TARGET_PORT` | `5000`      | Change if the port is busy.            |
| `FLP_TARGET_DB`   | `./target.db` | SQLite file path.                    |

### Seeded demo data (deterministic)

| User  | Password   | User id | Owns invoices   |
|-------|------------|---------|-----------------|
| alice | `alice123` | 1       | `1001`, `1002`  |
| bob   | `bob123`   | 2       | `2001`, `2002`  |

Accounts include `DEMO-0001-ALICE`, `DEMO-0002-ALICE`, `DEMO-0003-BOB`.

---

## Vulnerabilities → endpoint map

### Verifiable (scanner should mark `[VERIFIED]`)

| # | Class | Endpoint | How to trigger |
|---|-------|----------|----------------|
| 1 | **SQL injection** | `GET /lookup?account=` and `POST /login` (`username`) | A single quote (`'`) breaks the raw query and returns a visible `sqlite3` error signature (`Database error: ... syntax error`). |
| 2 | **SSRF** | `GET /settings/fetch-logo?url=` | Server fetches any user-supplied URL with no allow-list. A canary URL triggers an out-of-band callback from the server. |
| 3 | **Reflected XSS** | `GET /search?q=` | `q` is reflected into the DOM unescaped, so an injected `<script>`/`<svg onload>` payload executes in a real browser. |
| 4 | **IDOR** | `GET /invoice/<id>` | Any logged-in user can read any invoice by id with no ownership check — e.g. Alice opening `/invoice/2001` (Bob's). Two-session diff with the two seeded users. |

### Reported-only (shows as `[REPORTED]`, not verified)

| Class | Where |
|-------|-------|
| **Debug mode enabled** | Flask runs with `debug=True` (Werkzeug debugger / tracebacks). |
| **Missing security headers** | No `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Strict-Transport-Security`, or `Referrer-Policy`. |
| **Verbose errors** | DB errors and the built query are echoed into responses (`/login`, `/lookup`). |
| **Weak session secret** | Hardcoded `app.secret_key`. |

---

## Quick manual checks

```bash
# SQLi (visible sqlite3 error signature):
curl -s "http://127.0.0.1:5000/lookup?account='" | grep -i "database error"

# Reflected XSS (payload comes back unescaped):
curl -s "http://127.0.0.1:5000/search?q=<script>alert(1)</script>" | grep -i "<script>alert(1)"

# SSRF (server fetches the URL you give it — point it at a canary you control):
curl -s "http://127.0.0.1:5000/settings/fetch-logo?url=http://127.0.0.1:5000/" | head

# IDOR (log in as Alice, then read Bob's invoice 2001):
curl -s -c /tmp/flp.jar -d "username=alice&password=alice123" http://127.0.0.1:5000/login >/dev/null
curl -s -b /tmp/flp.jar "http://127.0.0.1:5000/invoice/2001" | grep -i "Acme Legal"
```

---

## Expected FinLexPurple 0.3.0 scan results

Run the scanner against the running app:

```bash
finlexpurple scan --target http://127.0.0.1:5000/
```

A correct 0.3.0 scan should report **four verifiable findings** and the
reported-only misconfigurations:

| Finding | Endpoint | Expected status |
|---------|----------|-----------------|
| SQL injection | `/lookup?account=`, `/login` | **`[VERIFIED]`** (error-based replay reproduces the SQL error) |
| SSRF | `/settings/fetch-logo?url=` | **`[VERIFIED]`** (out-of-band canary callback observed) |
| Reflected XSS | `/search?q=` | **`[VERIFIED]`** (payload executes in headless browser) |
| IDOR | `/invoice/<id>` | **`[VERIFIED]`** (two-session diff: user A reads user B's object) |
| Debug mode enabled | app-wide | `[REPORTED]` |
| Missing security headers | all responses | `[REPORTED]` |
| Verbose errors | `/login`, `/lookup` | `[REPORTED]` |

Use this table as the regression baseline: a correct run should match it. If a
`[VERIFIED]` finding drops to `[REPORTED]` (or disappears), the verifier for
that class regressed.

> SSRF verification needs the scanner's out-of-band canary/callback host to be
> reachable from this machine. If you run the scanner fully offline, SSRF may
> appear as `[REPORTED]` instead of `[VERIFIED]` — that's an environment
> limitation, not an app change.

---

## License / disclaimer

For local security testing and education only. You are responsible for running
it in an isolated, localhost-only environment. The authors accept no liability
for misuse.
