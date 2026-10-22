# FinLexPurple 0.3.0 — Scan Report

Validation of this deliberately-vulnerable target against the **published**
FinLexPurple release.

| | |
|---|---|
| Scanner | `finlexpurple` **0.3.0** (installed from PyPI: `pip install finlexpurple==0.3.0`) |
| `finlexpurple --version` | `0.3.0` |
| Target | `http://127.0.0.1:5000/` (localhost only — deliberately vulnerable app) |
| Scan date | 2026-10-22 (report `generated_at`: `2026-10-22T10:33:06Z`) |
| Python | 3.12.3 |
| Scan type | Black-box, no credentials supplied |

> ⚠️ This target is **deliberately vulnerable** and is bound to **`127.0.0.1`
> only**. Do not deploy it to a public server. See the repo
> [README](../README.md) for full safety notes.

---

## Summary (real tool output)

```
Recon: discovered 6 endpoints.
Scan complete: 18 findings (4 verified) across 6 detector calls.
```

- **Total findings: 18**
- **Independently verified: 4 (22.2%)**

Status breakdown (`report.json` → `summary.by_status`):

| Status | Count |
|--------|-------|
| verified | 4 |
| reported | 14 |
| human_confirmed | 0 |

Severity breakdown (`summary.by_severity`): critical 0 · high 4 · medium 2 · low 6 · info 6

Class/status counts:

| Class | Status | Count |
|-------|--------|-------|
| sqli | verified | 3 |
| ssrf | verified | 1 |
| xss | reported | 1 |
| idor | reported | 1 |
| generic_misconfig | reported | 12 |

---

## Recon — discovered endpoints

```
GET  http://127.0.0.1:5000/
GET  http://127.0.0.1:5000/login
GET  http://127.0.0.1:5000/lookup                 Parameters: account
GET  http://127.0.0.1:5000/search                 Parameters: q
GET  http://127.0.0.1:5000/settings/fetch-logo    Parameters: url
POST http://127.0.0.1:5000/login                  Parameters: password, username
```

---

## `[VERIFIED]` findings — mapped to app endpoints

These were promoted to `verified` by the scanner's deterministic replay engine
(not by model confidence). `verification_log` values are copied verbatim from
`report.json`.

| Class | Endpoint (app route) | Payload | `verification_log` |
|-------|----------------------|---------|--------------------|
| **sqli** | `GET /lookup` (`account`) → [app.py `lookup()`](../app.py) | `account='` | `re-executed "account='"; SQL error signature reproduced.` |
| **sqli** | `POST /login` (`username`) → [app.py `login()`](../app.py) | `username='` | `re-executed "username='"; SQL error signature reproduced.` |
| **sqli** | `POST /login` (`password`) → [app.py `login()`](../app.py) | `password='` | `re-executed "password='"; SQL error signature reproduced.` |
| **ssrf** | `GET /settings/fetch-logo` (`url`) → [app.py `fetch_logo()`](../app.py) | canary URL | `target fetched the injected canary URL (out-of-band callback observed).` |

- **SQLi** verifies because the raw string-built query echoes a real
  `sqlite3.OperationalError` signature when broken by a single quote; the
  replay re-sends the payload and reproduces that signature.
- **SSRF** verifies because the endpoint fetches the user-supplied URL
  server-side (`requests.get`), so the scanner's local out-of-band canary
  records a callback. (The endpoint is linked from the homepage so a black-box
  crawl discovers it.)

---

## `[REPORTED]` findings — detected but not verified (honest black-box limits)

| Class | Endpoint | Why reported, not verified |
|-------|----------|----------------------------|
| **xss** | `GET /search` (`q`) | The reflected payload is detected, but confirming execution needs a **real/headless browser**; a plain black-box HTTP scan does not drive one, so it stays `reported`. The flaw is genuinely present (`q` is reflected unescaped). |
| **idor** | `/lookup` (and the `/invoice/<id>` object) | IDOR verification needs a **two-session diff** (user A reading user B's object), i.e. two authenticated sessions. A no-credential scan can't log in as the two seeded users, so it can't perform that diff — reported only. |
| **generic_misconfig** × 12 | all routes | Missing security headers (no CSP / `X-Frame-Options` / `X-Content-Type-Options` / HSTS / `Referrer-Policy`), debug mode, and verbose errors. These are misconfigurations, not replayable exploits, so by design they are `reported`. |

None of these are faked or suppressed — `reported` is the correct, honest
status for them in a black-box run. To see XSS/IDOR verified you would wire in a
browser runner / supply the two seeded sessions (`alice`/`bob`).

---

## Offline re-verification — `verify-bundle`

One verified finding's evidence bundle (the `sqli` on `/lookup`,
`finding_id 26a3d6ec…`) re-verified standalone and fully offline:

```
$ finlexpurple verify-bundle <…>/26a3d6ec….bundle.json
  content hash matches (sha256:24f04ad7cc55f5bdfc15c5b76f46e51f83a7d04ff62db01119bf166842d125e1).
  no signature to verify (signing mode: hash-only); integrity rests on the content hash.
OK: bundle verified.

$ finlexpurple verify-bundle <…>/26a3d6ec….bundle.json \
    --expected-hash sha256:24f04ad7cc55f5bdfc15c5b76f46e51f83a7d04ff62db01119bf166842d125e1
  content hash matches (sha256:24f04ad7cc55f5bdfc15c5b76f46e51f83a7d04ff62db01119bf166842d125e1).
  recomputed hash matches the expected hash supplied by the caller.
  no signature to verify (signing mode: hash-only); integrity rests on the content hash.
OK: bundle verified.
```

Both invocations exited `0`. This demonstrates that a third party can confirm a
finding's evidence was not altered, with no scan and no network.

---

## Reproduce this scan

```bash
# 1. Fresh venv with the published package
python3 -m venv .venv-test && source .venv-test/bin/activate
pip install finlexpurple==0.3.0
finlexpurple --version          # -> 0.3.0

# 2. Start the target (in another shell), then scan
./run.sh                        # serves http://127.0.0.1:5000/  (localhost only)
finlexpurple scan --target http://127.0.0.1:5000/   # answer: y

# 3. Offline re-verify a bundle
finlexpurple verify-bundle <report-dir>/evidence/<id>.bundle.json
```

Expected baseline: **18 findings, 4 verified**, with `sqli` and `ssrf` among the
verified. If either drops to `reported`, the verifier (or this target's planted
signal) regressed.
