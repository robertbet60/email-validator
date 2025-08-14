# app.py
import os
import csv
import re
import smtplib
import ssl
import time
import socket
import dns.resolver
import logging
import threading
import uuid
from flask import Flask, request, jsonify, send_file, render_template
from werkzeug.utils import secure_filename
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from collections import defaultdict

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
HELO_NAME = "validator.bancadobrasil.com"   # matches A & PTR
MAIL_FROM = "verify@bancadobrasil.com"      # allowed by SPF

# timeouts & concurrency
SMTP_TIMEOUT = 8          # seconds per SMTP phase
DNS_TIMEOUT = 3           # per UDP try
DNS_LIFETIME = 5          # total resolve time
TRY_STARTTLS = True       # attempt STARTTLS if offered

# retries & backoff
SMTP_RETRY_ON_TRANSIENT = 1
TRANSIENT_SMTP_CODES = {421, 450, 451, 452, 454, 471}
MX_BACKOFF_SECONDS = 60
_last_mx_backoff = {}     # {mx_host: until_epoch}

# watchdog / batching
MAX_WORKERS = 6
PER_TASK_HARD_TIMEOUT = 15  # seconds (absolute cap per email)
BATCH_SIZE = 5000

# -----------------------------
# Data & Regex
# -----------------------------
def _load_lines(path):
    p = os.path.join(BASE_DIR, path)
    if not os.path.exists(p):
        return set()
    with open(p, "r", encoding="utf-8") as f:
        return {ln.strip().lower() for ln in f if ln.strip() and not ln.startswith("#")}

DISPOSABLE_DOMAINS = _load_lines("disposable_domains.txt")
SPAM_TRAP_DOMAINS = _load_lines("bad_domains.txt")
ROLE_ADDRESSES = {"admin", "info", "support", "sales", "contact", "help", "postmaster"}

# Tight syntax: no double dots, TLD >=2, no spaces, length guard
EMAIL_REGEX = re.compile(
    r"^(?=.{6,254}$)(?!.*\.\.)[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$"
)

# dns.resolver tuned instance
_resolver = dns.resolver.Resolver()
_resolver.timeout = DNS_TIMEOUT
_resolver.lifetime = DNS_LIFETIME

# job-scoped MX cache (domain -> mx_host)
# Filled per-job in validate_emails(); passed to validate_email()
def _resolve_mx_cached(domain_l: str, mx_cache: dict):
    if domain_l in mx_cache:
        return mx_cache[domain_l]
    mx_answers = _resolver.resolve(domain_l, "MX")
    mx_host = str(sorted(mx_answers, key=lambda r: r.preference)[0].exchange).rstrip(".")
    mx_cache[domain_l] = mx_host
    return mx_host

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
    # keep UI under 100 until files are completely written
    pct = max(0, min(99, pct))
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
            "all":    f"/download/{job_id}_validated.csv",
            "valid":  f"/download/{job_id}_valid.csv",
            "risky":  f"/download/{job_id}_risky.csv",
            "invalid":f"/download/{job_id}_invalid.csv",
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
    result_all   = os.path.join(RESULTS_DIR, f"{job_id}_validated.csv")
    result_valid = os.path.join(RESULTS_DIR, f"{job_id}_valid.csv")
    result_risky = os.path.join(RESULTS_DIR, f"{job_id}_risky.csv")
    result_invalid = os.path.join(RESULTS_DIR, f"{job_id}_invalid.csv")
    summary_path = os.path.join(RESULTS_DIR, f"{job_id}_summary.txt")

    # Read CSV (robust to BOM and missing header)
    with open(path, "r", encoding="utf-8-sig", newline="") as csvfile:
        # Auto sniff dialect if possible
        sample = csvfile.read(4096)
        csvfile.seek(0)
        try:
            dialect = csv.Sniffer().sniff(sample) if sample else csv.excel
        except Exception:
            dialect = csv.excel
        reader = csv.DictReader(csvfile, dialect=dialect)
        if not reader.fieldnames:
            logging.error("CSV has no header/columns")
            _write_progress(progress_path, "done")
            return
        # Try to find 'email' column by name (case-insensitive); fallback to first column
        lower_map = {h.lower().strip(): h for h in reader.fieldnames}
        email_key = lower_map.get("email", reader.fieldnames[0])
        rows = [r for r in reader if any((v or "").strip() for v in r.values())]

    # De-duplicate emails (keep first occurrence)
    seen = set()
    uniq_rows = []
    for r in rows:
        e = (r.get(email_key) or "").strip().lower()
        if not e:
            continue
        if e not in seen:
            seen.add(e)
            uniq_rows.append(r)
    rows = uniq_rows

    total = len(rows)
    if total == 0:
        logging.info(f"Job {job_id}: empty CSV after filtering/dedupe")
        _write_progress(progress_path, "done")
        return

    batches = [rows[i:i + BATCH_SIZE] for i in range(0, total, BATCH_SIZE)]

    all_rows, valid_rows, risky_rows, invalid_rows = [], [], [], []
    summary = defaultdict(int)
    completed = 0

    # job-scoped MX cache
    mx_cache = {}

    for batch_index, batch in enumerate(batches, start=1):
        logging.info("Job %s: batch %d/%d size=%d", job_id, batch_index, len(batches), len(batch))

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_info = {}
            for r in batch:
                fut = executor.submit(_validate_row_guarded, r, email_key, mx_cache)
                future_to_info[fut] = {"start": time.time(), "row": r}

            while future_to_info:
                done, _ = wait(list(future_to_info.keys()), timeout=2, return_when=FIRST_COMPLETED)

                # handle finished
                for fut in done:
                    info = future_to_info.pop(fut, None)
                    if info is None:
                        continue
                    try:
                        row, status = fut.result(timeout=0)
                    except Exception as e:
                        logging.warning("Future failed: %s", e)
                        row = info["row"]
                        status = "risky:worker-error"
                        row["status"] = status
                        row["reason"] = f"Worker error: {e}"

                    _collect(row, status, all_rows, valid_rows, risky_rows, invalid_rows, summary)
                    completed += 1
                    _write_progress(progress_path, str(min(99, int(completed / total * 100))))

                # watchdog for stragglers
                now = time.time()
                to_force = []
                for fut, info in list(future_to_info.items()):
                    age = now - info["start"]
                    if age > PER_TASK_HARD_TIMEOUT:
                        row = info["row"]
                        row["status"] = "risky:timeout"
                        row["reason"] = f"Exceeded {PER_TASK_HARD_TIMEOUT}s"
                        to_force.append(fut)
                        _collect(row, "risky:timeout",
                                 all_rows, valid_rows, risky_rows, invalid_rows, summary)
                        completed += 1
                        _write_progress(progress_path, str(min(99, int(completed / total * 100))))
                for fut in to_force:
                    future_to_info.pop(fut, None)

                time.sleep(0.05)

    # write outputs
    fieldnames = sorted({k for r in all_rows for k in r.keys()})
    if "status" not in fieldnames: fieldnames.append("status")
    if "reason" not in fieldnames: fieldnames.append("reason")

    _write_csv(result_all, fieldnames, all_rows)
    _write_csv(result_valid, fieldnames, valid_rows)
    _write_csv(result_risky, fieldnames, risky_rows)
    _write_csv(result_invalid, fieldnames, invalid_rows)

    # summary
    with open(summary_path, "w", encoding="utf-8") as f:
        for k in sorted(summary):
            f.write(f"{k}: {summary[k]}\n")

    _write_progress(progress_path, "done")
    logging.info(f"Job {job_id} finished: {dict(summary)}")

def _collect(row, status, all_rows, valid_rows, risky_rows, invalid_rows, summary):
    all_rows.append(row)
    summary[status] += 1
    if status.startswith("valid"):
        valid_rows.append(row)
    elif status.startswith("risky"):
        risky_rows.append(row)
    else:
        invalid_rows.append(row)

def _write_csv(path, fieldnames, rows):
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)

def _write_progress(path, txt):
    with open(path, "w", encoding="utf-8") as f:
        f.write(txt)

def _validate_row_guarded(row, key, mx_cache):
    email = (row.get(key) or "").strip()
    if not email:
        row["status"] = "invalid:empty"
        row["reason"] = "No email in row"
        return row, "invalid:empty"
    try:
        status, reason = validate_email(email, mx_cache)
    except Exception as e:
        status, reason = "risky:exception", f"{type(e).__name__}: {e}"
    row["status"], row["reason"] = status, reason
    return row, status

# -----------------------------
# Email checks (syntax, lists, DNS, SMTP)
# -----------------------------
def validate_email(email: str, mx_cache: dict):
    # 1) syntax
    if not EMAIL_REGEX.match(email):
        return "invalid:syntax", "Invalid format"

    local, domain = email.rsplit("@", 1)
    local_l = local.lower()
    domain_l = domain.lower()

    # 2) heuristics and lists first (cheap)
    if is_heuristically_risky(email):
        return "risky:heuristic", "Heuristic match"
    if domain_l in SPAM_TRAP_DOMAINS:
        return "risky:spam-trap", "Spam-trap domain"
    if domain_l in DISPOSABLE_DOMAINS:
        return "risky:disposable", "Disposable domain"
    if local_l in ROLE_ADDRESSES:
        return "risky:role-based", "Role-based address"

    # 3) DNS (MX) with per-job cache
    try:
        mx_host = _resolve_mx_cached(domain_l, mx_cache)
    except Exception as e:
        return "invalid:mx", f"MX lookup failed: {e}"

    # MX backoff if recent net errors
    now = time.time()
    until = _last_mx_backoff.get(mx_host, 0)
    if now < until:
        return "risky:smtp-error", "Backoff on MX after recent network error"

    # 4) SMTP RCPT probe (EHLO, optional STARTTLS, one retry)
    attempt = 0
    last_err = None
    while attempt <= SMTP_RETRY_ON_TRANSIENT:
        attempt += 1
        server = None
        try:
            server = smtplib.SMTP(mx_host, 25, local_hostname=HELO_NAME, timeout=SMTP_TIMEOUT)
            code, _ = server.ehlo_or_helo_if_needed()

            # STARTTLS if offered
            if TRY_STARTTLS and code == 250:
                try:
                    if server.has_extn("starttls"):
                        ctx = ssl.create_default_context()
                        server.starttls(context=ctx)
                        server.ehlo()
                except Exception as tls_e:
                    logging.info("%s: STARTTLS skipped: %s", mx_host, tls_e)

            server.mail(MAIL_FROM)
            code, resp = server.rcpt(email)
            try:
                server.quit()
            except Exception:
                pass

            if code in (250, 251):
                return "valid", "SMTP accepted"
            if code in TRANSIENT_SMTP_CODES:
                last_err = f"Transient SMTP {code}"
                continue
            return "invalid:smtp", f"SMTP {code}"

        except (socket.timeout, smtplib.SMTPServerDisconnected, smtplib.SMTPConnectError,
                smtplib.SMTPHeloError, smtplib.SMTPDataError, smtplib.SMTPRecipientsRefused,
                ConnectionRefusedError, OSError) as e:
            last_err = str(e)
            # retry if allowed
            continue
        except Exception as e:
            if server:
                try:
                    server.quit()
                except Exception:
                    pass
            return "risky:smtp-error", f"SMTP failed: {e}"

    # If we reach here, both attempts failed transiently — set MX backoff
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
