"""
FinLexPurple 0.3.0 — Deliberately Vulnerable Test Target
========================================================

A small, self-contained, fintech-flavored demo web app used ONLY to QA and demo
the FinLexPurple 0.3.0 scanner on localhost. It is INTENTIONALLY INSECURE.

SAFETY:
  * Binds to 127.0.0.1 (localhost) by default. Do NOT bind to 0.0.0.0.
  * Do NOT deploy this to a public server. Run it locally only.

The vulnerabilities below are planted on purpose so the scanner can find and
verify them. See README.md for the endpoint -> vulnerability map and the
expected scan results.
"""

import os
import sqlite3

import requests
from flask import (
    Flask,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

# --- Configuration ---------------------------------------------------------
# Localhost only by default. Overridable via env for advanced local testing,
# but the default MUST remain 127.0.0.1 (see README safety notes).
HOST = os.environ.get("FLP_TARGET_HOST", "127.0.0.1")
PORT = int(os.environ.get("FLP_TARGET_PORT", "5000"))
DB_PATH = os.environ.get("FLP_TARGET_DB", os.path.join(os.path.dirname(__file__), "target.db"))

app = Flask(__name__)
# Weak, hardcoded secret (REPORTED-only finding: insecure session config).
app.secret_key = "flp-0.3.0-demo-secret"


# --- Database helpers ------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Create schema and seed deterministic demo data (idempotent)."""
    db = sqlite3.connect(DB_PATH)
    db.executescript(
        """
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS accounts;
        DROP TABLE IF EXISTS invoices;

        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            full_name TEXT NOT NULL,
            email TEXT NOT NULL
        );

        CREATE TABLE accounts (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            number TEXT NOT NULL,
            kind TEXT NOT NULL,
            balance_cents INTEGER NOT NULL
        );

        CREATE TABLE invoices (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            counterparty TEXT NOT NULL,
            memo TEXT NOT NULL,
            amount_cents INTEGER NOT NULL,
            status TEXT NOT NULL
        );
        """
    )
    # Deterministic seed data so scans are repeatable.
    db.executemany(
        "INSERT INTO users (id, username, password, full_name, email) VALUES (?,?,?,?,?)",
        [
            (1, "alice", "alice123", "Alice Ashford", "alice@demo.invalid"),
            (2, "bob", "bob123", "Bob Baxter", "bob@demo.invalid"),
        ],
    )
    db.executemany(
        "INSERT INTO accounts (id, user_id, number, kind, balance_cents) VALUES (?,?,?,?,?)",
        [
            (1, 1, "DEMO-0001-ALICE", "checking", 532100),
            (2, 1, "DEMO-0002-ALICE", "savings", 1200000),
            (3, 2, "DEMO-0003-BOB", "checking", 87500),
        ],
    )
    db.executemany(
        "INSERT INTO invoices (id, user_id, counterparty, memo, amount_cents, status) VALUES (?,?,?,?,?,?)",
        [
            # Alice's invoices
            (1001, 1, "Northwind Supplies", "Office furniture", 149900, "paid"),
            (1002, 1, "Globex Cloud", "Hosting — Q3", 48000, "due"),
            # Bob's invoices (IDOR target: readable by Alice via /invoice/<id>)
            (2001, 2, "Acme Legal", "Retainer", 300000, "due"),
            (2002, 2, "Initech Payroll", "Contractor payout", 92500, "paid"),
        ],
    )
    db.commit()
    db.close()


# --- Security misconfig (REPORTED-only) ------------------------------------
@app.after_request
def no_security_headers(resp):
    """
    Intentionally does NOT set common security headers
    (Content-Security-Policy, X-Frame-Options, X-Content-Type-Options,
    Strict-Transport-Security, Referrer-Policy). Leave them absent so the
    scanner reports the missing-headers misconfiguration.
    """
    resp.headers["Server"] = "FinLexPurple-Target/0.3.0"
    return resp


def current_user():
    uid = session.get("uid")
    if not uid:
        return None
    return get_db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()


# --- Routes ----------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html", user=current_user())


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        # VULN #1 (SQL injection): raw string-built query. A single quote (')
        # yields a visible sqlite3 error signature in the response.
        query = (
            "SELECT * FROM users WHERE username = '%s' AND password = '%s'"
            % (username, password)
        )
        try:
            row = get_db().execute(query).fetchone()
        except sqlite3.Error as exc:
            # Verbose DB error echoed back (SQLi signature + REPORTED verbose errors).
            return render_template("login.html", error="Database error: %s" % exc, query=query), 500
        if row:
            session["uid"] = row["id"]
            return redirect(url_for("dashboard"))
        error = "Invalid credentials."
    return render_template("login.html", error=error, query=None)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/dashboard")
def dashboard():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    accounts = get_db().execute(
        "SELECT * FROM accounts WHERE user_id = ?", (user["id"],)
    ).fetchall()
    return render_template("dashboard.html", user=user, accounts=accounts)


@app.route("/invoices")
def invoices():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    rows = get_db().execute(
        "SELECT * FROM invoices WHERE user_id = ?", (user["id"],)
    ).fetchall()
    return render_template("invoices.html", user=user, invoices=rows)


@app.route("/invoice/<int:invoice_id>")
def invoice(invoice_id):
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    # VULN #4 (IDOR): fetches by id with NO ownership check, so Alice can read
    # Bob's invoices (e.g. /invoice/2001). Two seeded users make this a clean
    # two-session diff for the verifier.
    row = get_db().execute(
        "SELECT * FROM invoices WHERE id = ?", (invoice_id,)
    ).fetchone()
    if not row:
        return render_template("invoice.html", user=user, invoice=None), 404
    return render_template("invoice.html", user=user, invoice=row)


@app.route("/search")
def search():
    # VULN #3 (Reflected XSS): 'q' is reflected into the page unescaped, so a
    # payload executes in a real DOM (headless-browser-verifiable).
    q = request.args.get("q", "")
    return render_template("search.html", user=current_user(), q=q)


@app.route("/lookup")
def lookup():
    # VULN #1b (SQL injection, GET): account lookup builds raw SQL. A single
    # quote (') yields a visible sqlite3 error signature — scanner-friendly
    # GET parameter for the verifier's replay.
    account = request.args.get("account", "")
    results = []
    error = None
    sql = None
    if account:
        sql = "SELECT number, kind FROM accounts WHERE number = '%s'" % account
        try:
            results = get_db().execute(sql).fetchall()
        except sqlite3.Error as exc:
            error = "Database error: %s" % exc
    return render_template(
        "lookup.html", user=current_user(), account=account, results=results, error=error, sql=sql
    )


@app.route("/settings/fetch-logo")
def fetch_logo():
    # VULN #2 (SSRF): fetches a user-supplied URL server-side with no allow-list
    # or host validation, so an injected canary URL causes an out-of-band
    # callback from this server.
    url = request.args.get("url", "")
    fetched = None
    error = None
    if url:
        try:
            r = requests.get(url, timeout=5)
            fetched = {
                "status": r.status_code,
                "content_type": r.headers.get("Content-Type", ""),
                "length": len(r.content),
                "preview": r.text[:500],
            }
        except requests.RequestException as exc:
            error = "Fetch error: %s" % exc
    return render_template(
        "settings.html", user=current_user(), url=url, fetched=fetched, error=error
    )


@app.route("/profile")
def profile():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    return render_template("profile.html", user=user)


if __name__ == "__main__":
    init_db()
    # VULN (REPORTED-only): debug=True exposes the Werkzeug debugger and verbose
    # tracebacks. Host defaults to 127.0.0.1 — localhost only. Never 0.0.0.0.
    print(" * FinLexPurple 0.3.0 TARGET — deliberately vulnerable, localhost only")
    print(" * Serving on http://%s:%s/  (do NOT expose publicly)" % (HOST, PORT))
    app.run(host=HOST, port=PORT, debug=True)
