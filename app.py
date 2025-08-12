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
SMTP_TIMEOUT = 8                             # seconds per SMTP phase
DNS_TIMEOUT = 3                              # per UDP try
DNS_LIFETIME = 5                             # total resolve time
TRY_STARTTLS = True                          # attempt STARTTLS if offered
SMTP_RETRY_ON_TRANSIENT = 1                  # retry once on transient net errors
TRANSIENT_SMTP_CODES = {421, 450, 451, 452, 454, 471}  # treat as transient
# Backoff cache to avoid hammering the same MX after net failures (in-memory)
MX_BACKOFF_SECONDS = 60
_last_mx_backoff = {}  # {mx_host: until_epoch}

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

# Tight syntax: no double dots, TLD >=2, no spaces
EMAIL_REGEX = re.compile(r"^(?!.*\.\.)[a-zA-Z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")

# dns.resolver tuned instance
_resolver = dns.resolver.Resolver()
_resolver.timeout = DNS_TIMEOUT
_resolver.lifetime = DNS_LIFETIME

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
        reader = csv.DictReader(csvfile)
        if not reader.fieldnames:
            logging.error("CSV has no header/columns")
            _write_progress(progress_path, "done")
            return
        # Try to find 'email' column by name (case-insensitive); fallback to first column
        lower_map = {h.lower().strip(): h for h in reader.fieldnames}
        email_key = lower_map.get("email", reader.fieldnames[0])
        rows = [r for r in reader if any(v.strip() for v in r.values() if isinstance(v, str))]

    total = len(rows)
    if total == 0:
        logging.info(f"Job {job_id}: empty CSV after filtering")
        _write_progress(progress_path, "done")
        return

    batch_size = 5000
    batches = [rows[i:i + batch_size] for i in range(0, total, batch_size)]

    all_rows, valid_rows, risky_rows, invalid_rows = [], [], [], []
    summary = defaultdict(int)
    completed = 0

    for batch in batches:
        # modest concurrency to avoid saturating the box / MXs
        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_row = {executor.submit(_validate_row_safe, r, email_key): r for r in batch}

            while future_to_row:
                done, _ = wait(future_to_row, timeout=10, return_when=FIRST_COMPLETED)
                if not done:
                    # Nothing finished in 10s – keep looping; progress will move when tasks complete
                    continue
                for fut in done:
                    try:
                        row, status = fut.result(timeout=1)
                    except Exception as e:
                        row = future_to_row[fut]
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
                    # cap UI at 99% until we finish writing files
                    pct = min(99, int((completed / total) * 100))
                    _write_progress(progress_path, str(pct))
                    del future_to_row[fut]

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
# Email checks (syntax, lists, DNS, SMTP)
# -----------------------------
def validate_email(email: str):
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

    # 3) DNS (MX)
    try:
        mx_answers = _resolver.resolve(domain_l, "MX")
        mx_host = str(sorted(mx_answers, key=lambda r: r.preference)[0].exchange).rstrip(".")
    except Exception as e:
        return "invalid:mx", f"MX lookup failed: {e}"

    # Optional: in-memory backoff if the MX recently errored at socket level
    now = time.time()
    until = _last_mx_backoff.get(mx_host, 0)
    if now < until:
        return "risky:smtp-error", "Backoff on MX after recent network error"

    # 4) SMTP RCPT probe (with EHLO, optional STARTTLS, one retry)
    attempt = 0
    last_err = None
    while attempt <= SMTP_RETRY_ON_TRANSIENT:
        attempt += 1
        try:
            server = smtplib.SMTP(mx_host, 25, local_hostname=HELO_NAME, timeout=SMTP_TIMEOUT)
            server.ehlo_or_helo_if_needed()

            # STARTTLS if offered (some providers insist on TLS before RCPT)
            if TRY_STARTTLS:
                try:
                    if server.has_extn("starttls"):
                        ctx = ssl.create_default_context()
                        server.starttls(context=ctx)
                        server.ehlo()  # re-EHLO after TLS
                except Exception as tls_e:
                    # Not fatal for validation; continue without TLS
                    logging.info(f"{mx_host}: STARTTLS skipped: {tls_e}")

            # MAIL FROM & RCPT TO
            server.mail(MAIL_FROM)
            code, resp = server.rcpt(email)
            server.quit()

            if code in (250, 251):
                return "valid", "SMTP accepted"
            elif code in TRANSIENT_SMTP_CODES:
                last_err = f"Transient SMTP {code}"
                continue  # retry once
            else:
                return "invalid:smtp", f"SMTP {code}"

        except (socket.timeout, smtplib.SMTPServerDisconnected, smtplib.SMTPConnectError,
                smtplib.SMTPHeloError, smtplib.SMTPDataError, smtplib.SMTPRecipientsRefused,
                ConnectionRefusedError, OSError) as e:
            last_err = str(e)
            # transient network problem → retry once
            continue
        except Exception as e:
            # Unknown/unexpected
            server_quit_silent()
            return "risky:smtp-error", f"SMTP failed: {e}"

    # If we got here, both attempts failed transiently — set backoff
    _last_mx_backoff[mx_host] = time.time() + MX_BACKOFF_SECONDS
    return "risky:smtp-error", (last_err or "SMTP transient/timeout")

def server_quit_silent(server=None):
    try:
        if server:
            server.quit()
    except Exception:
        pass

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
