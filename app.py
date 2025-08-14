# app.py
import os
import csv
import re
import ssl
import time
import socket
import smtplib
import dns.resolver
import logging
import threading
import uuid
from collections import defaultdict
from contextlib import contextmanager
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from flask import Flask, request, jsonify, send_file, render_template
from werkzeug.utils import secure_filename

# -----------------------------
# App & paths
# -----------------------------
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB

BASE_DIR = "/opt/email-validator"
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
RESULTS_DIR = os.path.join(BASE_DIR, "results")
PROGRESS_DIR = os.path.join(BASE_DIR, "progress")
for d in (UPLOAD_DIR, RESULTS_DIR, PROGRESS_DIR):
    os.makedirs(d, exist_ok=True)

# -----------------------------
# Logging
# -----------------------------
logging.basicConfig(
    filename=os.path.join(BASE_DIR, "validation.log"),
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)

# -----------------------------
# Identity / SMTP tuning
# -----------------------------
HELO_NAME = "validator.bancadobrasil.com"   # must match A & PTR
MAIL_FROM = "verify@bancadobrasil.com"      # aligned with SPF
SMTP_TIMEOUT = 8                             # seconds per SMTP call
DNS_TIMEOUT = 3                              # per UDP try
DNS_LIFETIME = 5                             # total resolve time
TRY_STARTTLS = True                          # attempt STARTTLS if offered
SMTP_RETRY_ON_TRANSIENT = 1                  # retry once on transient
TRANSIENT_SMTP_CODES = {421, 450, 451, 452, 454, 471}
MX_BACKOFF_SECONDS = 60                      # cool down per MX on net errors
PER_DOMAIN_CONCURRENCY = 1                   # serialize hits per MX/domain
THREADS_PER_BATCH = 5                        # overall concurrency

# -----------------------------
# Data & Regex
# -----------------------------
def _load_lines(path):
    p = os.path.join(BASE_DIR, path)
    if not os.path.exists(p):
        return set()
    with open(p, "r", encoding="utf-8") as f:
        return {ln.strip() for ln in f if ln.strip()}

DISPOSABLE_DOMAINS = _load_lines("disposable_domains.txt")
SPAM_TRAP_DOMAINS = _load_lines("bad_domains.txt")
ROLE_ADDRESSES = {"admin", "info", "support", "sales", "contact", "help", "postmaster"}

# No double dots in local/domain, simple but safe TLD check
EMAIL_REGEX = re.compile(r"^(?!.*\.\.)[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")

# dns.resolver tuned instance
_resolver = dns.resolver.Resolver()
_resolver.timeout = DNS_TIMEOUT
_resolver.lifetime = DNS_LIFETIME

# -----------------------------
# MX cache & backoff
# -----------------------------
@dataclass
class MXCacheEntry:
    host: str
    expires_at: float

_mx_cache: dict[str, MXCacheEntry] = {}
_mx_cache_ttl = 3600  # 1 hour
_last_mx_backoff: dict[str, float] = {}  # mx_host -> until_epoch
_mx_cache_lock = threading.Lock()

def resolve_mx_cached(domain: str) -> str:
    now = time.time()
    with _mx_cache_lock:
        entry = _mx_cache.get(domain)
        if entry and entry.expires_at > now:
            return entry.host
    # Resolve fresh
    answers = _resolver.resolve(domain, "MX")
    mx_host = str(sorted(answers, key=lambda r: r.preference)[0].exchange).rstrip(".")
    with _mx_cache_lock:
        _mx_cache[domain] = MXCacheEntry(mx_host, now + _mx_cache_ttl)
    return mx_host

# -----------------------------
# Per-domain limiter
# -----------------------------
_domain_locks: dict[str, threading.Semaphore] = defaultdict(
    lambda: threading.Semaphore(PER_DOMAIN_CONCURRENCY)
)
_domain_locks_guard = threading.Lock()

@contextmanager
def domain_gate(mx_host: str):
    # One gate per MX host (serialize to avoid bursts)
    with _domain_locks_guard:
        sem = _domain_locks[mx_host]
    sem.acquire()
    try:
        yield
    finally:
        sem.release()

# -----------------------------
# SMTP connection pool (per MX)
# -----------------------------
class SMTPPool:
    def __init__(self):
        self._pool: dict[str, smtplib.SMTP] = {}
        self._locks: dict[str, threading.Lock] = defaultdict(threading.Lock)
        self._last_used: dict[str, float] = {}
        self._idle_ttl = 120  # close idle > 2 min
        self._guard = threading.Lock()

    def _get_lock(self, mx_host: str) -> threading.Lock:
        with self._guard:
            return self._locks[mx_host]

    def _is_alive(self, cli: smtplib.SMTP) -> bool:
        try:
            cli.noop()
            return True
        except Exception:
            return False

    def _connect(self, mx_host: str) -> smtplib.SMTP:
        cli = smtplib.SMTP(mx_host, 25, local_hostname=HELO_NAME, timeout=SMTP_TIMEOUT)
        cli.ehlo_or_helo_if_needed()
        if TRY_STARTTLS and cli.has_extn("starttls"):
            try:
                ctx = ssl.create_default_context()
                cli.starttls(context=ctx)
                cli.ehlo()
            except Exception as e:
                logging.info(f"{mx_host}: STARTTLS not used ({e})")
        return cli

    def _get_client(self, mx_host: str) -> smtplib.SMTP:
        cli = self._pool.get(mx_host)
        if not cli or not self._is_alive(cli):
            # create/replace
            if cli:
                self._safe_quit(cli)
            cli = self._connect(mx_host)
            self._pool[mx_host] = cli
        self._last_used[mx_host] = time.time()
        return cli

    def _safe_quit(self, cli: smtplib.SMTP):
        try:
            cli.quit()
        except Exception:
            pass

    def gc_idle(self):
        now = time.time()
        for mx_host, cli in list(self._pool.items()):
            last = self._last_used.get(mx_host, 0)
            if now - last > self._idle_ttl:
                self._safe_quit(cli)
                del self._pool[mx_host]
                self._last_used.pop(mx_host, None)

    def rcpt_probe(self, mx_host: str, recipient: str) -> tuple[int, bytes]:
        """
        Reuse one connection per MX. For each address:
        MAIL FROM -> RCPT TO -> RSET (to clean txn)
        """
        lock = self._get_lock(mx_host)
        with lock:
            cli = self._get_client(mx_host)
            try:
                cli.mail(MAIL_FROM)
                code, resp = cli.rcpt(recipient)
                try:
                    cli.rset()
                except Exception:
                    # not fatal; next txn will EHLO if needed
                    pass
                self._last_used[mx_host] = time.time()
                return code, resp
            except Exception as e:
                # drop this client; force reconnect next time
                self._safe_quit(cli)
                self._pool.pop(mx_host, None)
                raise e

_smtp_pool = SMTPPool()

# Background idle GC
def _smtp_gc_loop():
    while True:
        try:
            _smtp_pool.gc_idle()
        except Exception:
            pass
        time.sleep(30)

threading.Thread(target=_smtp_gc_loop, daemon=True).start()

# -----------------------------
# Routes
# -----------------------------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/upload", methods=["POST"])
def upload_file():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    file = request.files["file"]
    uid = str(uuid.uuid4())
    path = os.path.join(UPLOAD_DIR, f"{uid}.csv")
    file.save(path)

    thread = threading.Thread(target=validate_emails, args=(path, uid), daemon=True)
    thread.start()
    return jsonify({"job_id": uid})

@app.route("/progress/<job_id>")
def check_progress(job_id):
    path = os.path.join(PROGRESS_DIR, f"{job_id}.txt")
    if not os.path.exists(path):
        return jsonify({"status": "pending", "percent": 0})
    with open(path, "r", encoding="utf-8") as f:
        txt = f.read().strip()
    if txt == "done":
        return jsonify({"status": "done"})
    try:
        pct = int(txt)
    except:
        pct = 0
    return jsonify({"status": "processing", "percent": pct})

@app.route("/result/<job_id>")
def result(job_id):
    all_p = os.path.join(RESULTS_DIR, f"{job_id}_validated.csv")
    if not os.path.exists(all_p):
        return "Result not found", 404
    summary_path = os.path.join(RESULTS_DIR, f"{job_id}_summary.txt")
    summary_txt = ""
    if os.path.exists(summary_path):
        with open(summary_path, "r", encoding="utf-8") as f:
            summary_txt = f.read()

    return jsonify({
        "downloads": {
            "all":     f"/download/{job_id}_validated.csv",
            "valid":   f"/download/{job_id}_valid.csv",
            "risky":   f"/download/{job_id}_risky.csv",
            "invalid": f"/download/{job_id}_invalid.csv",
        },
        "summary": summary_txt,
    })

@app.route("/download/<filename>")
def download_file(filename):
    return send_file(os.path.join(RESULTS_DIR, filename), as_attachment=True)

# -----------------------------
# Core validation pipeline
# -----------------------------
def validate_emails(path, job_id):
    progress_path = os.path.join(PROGRESS_DIR, f"{job_id}.txt")
    result_all     = os.path.join(RESULTS_DIR, f"{job_id}_validated.csv")
    result_valid   = os.path.join(RESULTS_DIR, f"{job_id}_valid.csv")
    result_risky   = os.path.join(RESULTS_DIR, f"{job_id}_risky.csv")
    result_invalid = os.path.join(RESULTS_DIR, f"{job_id}_invalid.csv")
    summary_path   = os.path.join(RESULTS_DIR, f"{job_id}_summary.txt")

    # Read CSV (BOM safe). If no "email" header, use first column.
    with open(path, "r", encoding="utf-8-sig", newline="") as csvfile:
        reader = csv.DictReader(csvfile)
        if not reader.fieldnames:
            logging.error("CSV has no header/columns")
            _write_progress(progress_path, "done")
            return
        lower_map = {h.lower().strip(): h for h in reader.fieldnames}
        email_key = lower_map.get("email", reader.fieldnames[0])
        rows = [r for r in reader if any((v or "").strip() for v in r.values())]

    total = len(rows)
    if total == 0:
        _write_progress(progress_path, "done")
        return

    batch_size = 5000
    batches = [rows[i:i + batch_size] for i in range(0, total, batch_size)]

    all_rows, valid_rows, risky_rows, invalid_rows = [], [], [], []
    summary = defaultdict(int)
    completed = 0

    for batch in batches:
        with ThreadPoolExecutor(max_workers=THREADS_PER_BATCH) as executor:
            fut_map = {executor.submit(_validate_row_safe, r, email_key): r for r in batch}
            while fut_map:
                done, _ = wait(fut_map, timeout=10, return_when=FIRST_COMPLETED)
                if not done:
                    continue
                for fut in done:
                    try:
                        row, status = fut.result(timeout=1)
                    except Exception as e:
                        row = fut_map[fut]
                        status = "error"
                        row["status"] = "error"
                        row["reason"] = f"worker: {e}"
                        logging.warning(f"Worker failure: {e}")

                    all_rows.append(row)
                    summary[status] += 1
                    if status.startswith("valid"):
                        valid_rows.append(row)
                    elif status.startswith("risky"):
                        risky_rows.append(row)
                    else:
                        invalid_rows.append(row)

                    completed += 1
                    pct = min(99, int((completed / total) * 100))
                    _write_progress(progress_path, str(pct))
                    del fut_map[fut]

    # write outputs
    fieldnames = list(all_rows[0].keys())
    _write_csv(result_all, fieldnames, all_rows)
    _write_csv(result_valid, fieldnames, valid_rows)
    _write_csv(result_risky, fieldnames, risky_rows)
    _write_csv(result_invalid, fieldnames, invalid_rows)

    # summary
    with open(summary_path, "w", encoding="utf-8") as f:
        for k, v in sorted(summary.items()):
            f.write(f"{k}: {v}\n")

    _write_progress(progress_path, "done")
    logging.info(f"Job {job_id} finished: {dict(summary)}")

def _write_csv(path, fieldnames, rows):
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)

def _write_progress(path, txt):
    with open(path, "w", encoding="utf-8") as f:
        f.write(txt)

def _validate_row_safe(row, key):
    email = (row.get(key) or "").strip()
    if not email:
        row["status"] = "invalid:empty"
        row["reason"] = "No email in row"
        return row, "invalid:empty"
    try:
        status, reason = validate_email(email)
    except Exception as e:
        status, reason = "error", f"exception: {e}"
    row["status"], row["reason"] = status, reason
    return row, status

# -----------------------------
# Email checks (syntax, lists, DNS, SMTP with reuse)
# -----------------------------
def validate_email(email: str):
    # 1) Syntax
    if not EMAIL_REGEX.match(email):
        return "invalid:syntax", "Invalid format"

    local, domain = email.rsplit("@", 1)
    local_l = local.lower()
    domain_l = domain.lower()

    # 2) Cheap filters
    if is_heuristically_risky(email):
        return "risky:heuristic", "Heuristic match"
    if domain_l in SPAM_TRAP_DOMAINS:
        return "risky:spam-trap", "Spam-trap domain"
    if domain_l in DISPOSABLE_DOMAINS:
        return "risky:disposable", "Disposable domain"
    if local_l in ROLE_ADDRESSES:
        return "risky:role-based", "Role-based address"

    # 3) MX resolve with cache
    try:
        mx_host = resolve_mx_cached(domain_l)
    except Exception as e:
        return "invalid:mx", f"MX lookup failed: {e}"

    # Backoff window after transient failures on this MX
    now = time.time()
    if now < _last_mx_backoff.get(mx_host, 0):
        return "risky:smtp-error", "Backoff on MX after recent network error"

    # 4) SMTP probe with connection reuse and per-domain gate
    attempts = 0
    last_err = None
    with domain_gate(mx_host):
        while attempts <= SMTP_RETRY_ON_TRANSIENT:
            attempts += 1
            try:
                code, resp = _smtp_pool.rcpt_probe(mx_host, email)
                if code in (250, 251):
                    return "valid", "SMTP accepted"
                if code in TRANSIENT_SMTP_CODES:
                    last_err = f"Transient SMTP {code}"
                    continue
                return "invalid:smtp", f"SMTP {code}"
            except (socket.timeout, smtplib.SMTPConnectError,
                    smtplib.SMTPServerDisconnected, ConnectionRefusedError, OSError) as e:
                last_err = str(e)
                # retry once on transient net errors
                continue
            except Exception as e:
                return "risky:smtp-error", f"SMTP failed: {e}"

    # mark backoff for this MX
    _last_mx_backoff[mx_host] = time.time() + MX_BACKOFF_SECONDS
    return "risky:smtp-error", (last_err or "SMTP transient/timeout")

# -----------------------------
# Heuristics
# -----------------------------
def is_heuristically_risky(email: str) -> bool:
    username, domain = email.lower().split("@", 1)

    risky_tlds = (".xyz", ".top", ".click", ".buzz", ".club", ".site",
                  ".online", ".space", ".fun", ".work", ".shop")
    known_fake_terms = (
        # PT/BR + EN
        "teste", "testando", "senha", "usuario", "user", "admin", "example", "demo",
        "password", "foobar", "fulano", "ciclano", "beltrano", "zap", "12345", "abcdef", "test1",
        "contato", "suporte", "atendimento", "cadastro", "tmp", "temp"
    )
    risky_domains = (
        "zipmail.com.br", "bol.com.br", "uol.com.br", "superig.com.br", "r7.com",
        "mail.ru", "yopmail.com", "guerrillamail.com"
    )

    if username.isnumeric() or len(username) <= 2:
        return True
    if not re.search(r"[aeiou]", username):
        return True
    if any(term in username for term in known_fake_terms):
        return True
    if domain in risky_domains or any(domain.endswith(tld) for tld in risky_tlds):
        return True
    if re.search(r"(.)\1{2,}", username):
        return True
    if "cpf" in username or "rg" in username:
        return True
    return False

# -----------------------------
# Main
# -----------------------------
if __name__ == "__main__":
    app.run(debug=True)
