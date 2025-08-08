import os
import csv
import re
import smtplib
import dns.resolver
import logging
import threading
import uuid
import time
from flask import Flask, request, jsonify, send_file, render_template
from werkzeug.utils import secure_filename
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB max upload

# Configuration
BASE_DIR = "/opt/email-validator"
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
RESULTS_DIR = os.path.join(BASE_DIR, "results")
PROGRESS_DIR = os.path.join(BASE_DIR, "progress")
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(RESULTS_DIR, exist_ok=True)
os.makedirs(PROGRESS_DIR, exist_ok=True)

# Logging
logging.basicConfig(filename=os.path.join(BASE_DIR, 'validation.log'), level=logging.INFO)

# Load lists
DISPOSABLE_DOMAINS = set(line.strip() for line in open(os.path.join(BASE_DIR, "disposable_domains.txt")))
SPAM_TRAP_DOMAINS = set(line.strip() for line in open(os.path.join(BASE_DIR, "bad_domains.txt")))
ROLE_ADDRESSES = {"admin", "info", "support", "sales", "contact", "help", "postmaster"}
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$")

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/upload", methods=["POST"])
def upload_file():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    file = request.files["file"]
    uid = str(uuid.uuid4())
    filepath = os.path.join(UPLOAD_DIR, f"{uid}.csv")
    file.save(filepath)

    thread = threading.Thread(target=validate_emails_in_batches, args=(filepath, uid))
    thread.start()

    return jsonify({"job_id": uid})

@app.route("/progress/<job_id>")
def progress(job_id):
    path = os.path.join(PROGRESS_DIR, f"{job_id}.txt")
    if not os.path.exists(path):
        return jsonify({"status": "pending", "percent": 0})
    with open(path) as f:
        val = f.read().strip()
    if val == "done":
        return jsonify({"status": "done"})
    return jsonify({"status": "processing", "percent": int(val)})

@app.route("/result/<job_id>")
def result(job_id):
    base = f"{job_id}_validated"
    return jsonify({
        "downloads": {
            "all": f"/download/{base}.csv",
            "valid": f"/download/{job_id}_valid.csv",
            "risky": f"/download/{job_id}_risky.csv",
            "invalid": f"/download/{job_id}_invalid.csv"
        },
        "summary": open(os.path.join(RESULTS_DIR, f"{job_id}_summary.txt")).read()
    })

@app.route("/download/<filename>")
def download_file(filename):
    return send_file(os.path.join(RESULTS_DIR, filename), as_attachment=True)

# Batch validation handler
def validate_emails_in_batches(csv_path, job_id, batch_size=5000):
    with open(csv_path, newline='') as f:
        reader = csv.DictReader(f)
        header = reader.fieldnames
        email_key = next((h for h in header if h.lower() == "email"), header[0])
        rows = list(reader)

    total = len(rows)
    summary = defaultdict(int)
    all_rows, valid_rows, risky_rows, invalid_rows = [], [], [], []

    for i in range(0, total, batch_size):
        batch = rows[i:i+batch_size]
        batch_results, batch_summary = validate_batch(batch, email_key, total, job_id, i)

        for row in batch_results:
            all_rows.append(row)
            if row["status"].startswith("valid"):
                valid_rows.append(row)
            elif row["status"].startswith("risky"):
                risky_rows.append(row)
            else:
                invalid_rows.append(row)

        for k, v in batch_summary.items():
            summary[k] += v

    save_results(job_id, all_rows, valid_rows, risky_rows, invalid_rows, summary)

def validate_batch(batch, email_key, total, job_id, offset):
    results = []
    summary = defaultdict(int)
    futures = []
    executor = ThreadPoolExecutor(max_workers=5)

    def safe_validate(row):
        email = row.get(email_key, "").strip()
        try:
            if not EMAIL_REGEX.match(email):
                return row | {"status": "invalid:syntax", "reason": "Invalid format"}, "invalid:syntax"
            status, reason = validate_email(email)
        except Exception as e:
            status, reason = "error", str(e)
        return row | {"status": status, "reason": reason}, status

    futures = [executor.submit(safe_validate, row) for row in batch]
    for i, future in enumerate(as_completed(futures)):
        try:
            row, status = future.result(timeout=8)
            results.append(row)
            summary[status] += 1
        except Exception as e:
            row = {"email": "unknown", "status": "error", "reason": f"Timeout or fail: {e}"}
            results.append(row)
            summary["error"] += 1
        write_progress(job_id, offset + i + 1, total)

    executor.shutdown(wait=True)
    return results, summary

def write_progress(job_id, count, total):
    path = os.path.join(PROGRESS_DIR, f"{job_id}.txt")
    percent = int(count / total * 100)
    with open(path, "w") as f:
        f.write(str(percent))

def save_results(job_id, all_rows, valid, risky, invalid, summary):
    def write_csv(path, rows):
        if rows:
            with open(path, "w", newline='') as f:
                writer = csv.DictWriter(f, fieldnames=rows[0].keys())
                writer.writeheader()
                writer.writerows(rows)

    write_csv(os.path.join(RESULTS_DIR, f"{job_id}_validated.csv"), all_rows)
    write_csv(os.path.join(RESULTS_DIR, f"{job_id}_valid.csv"), valid)
    write_csv(os.path.join(RESULTS_DIR, f"{job_id}_risky.csv"), risky)
    write_csv(os.path.join(RESULTS_DIR, f"{job_id}_invalid.csv"), invalid)

    with open(os.path.join(RESULTS_DIR, f"{job_id}_summary.txt"), "w") as f:
        for k, v in summary.items():
            f.write(f"{k}: {v}\n")

    with open(os.path.join(PROGRESS_DIR, f"{job_id}.txt"), "w") as f:
        f.write("done")

    logging.info(f"Completed {job_id} with summary: {dict(summary)}")

def validate_email(email):
    domain = email.split("@")[-1].lower()
    local = email.split("@")[0].lower()

    if is_heuristically_risky(email):
        return "risky:heuristic", "Heuristically risky"
    if domain in SPAM_TRAP_DOMAINS:
        return "risky:spam-trap", "Spam trap"
    if domain in DISPOSABLE_DOMAINS:
        return "risky:disposable", "Disposable"
    if local in ROLE_ADDRESSES:
        return "risky:role-based", "Role address"

    try:
        mx = dns.resolver.resolve(domain, 'MX', lifetime=5)
        mx_host = str(sorted(mx, key=lambda r: r.preference)[0].exchange).rstrip('.')
    except Exception as e:
        return "invalid:mx", f"MX failed: {e}"

    try:
        server = smtplib.SMTP(mx_host, 25, timeout=8)
        server.helo("example.com")
        server.mail("test@example.com")
        code, _ = server.rcpt(email)
        server.quit()
        return ("valid", "SMTP accepted") if code in [250, 251] else ("invalid:smtp", f"Code {code}")
    except Exception as e:
        return "risky:smtp-error", f"SMTP failed: {e}"

def is_heuristically_risky(email):
    username, domain = email.lower().split("@")
    bad_terms = {"teste", "admin", "senha", "usuario", "foobar", "example", "12345", "abcdef"}
    risky_tlds = [".xyz", ".top", ".click", ".buzz", ".club", ".site"]
    risky_domains = {"mail.ru", "zipmail.com.br", "yopmail.com", "guerrillamail.com"}

    return (
        username.isnumeric()
        or len(username) <= 2
        or not re.search(r"[aeiou]", username)
        or any(t in username for t in bad_terms)
        or domain in risky_domains
        or any(domain.endswith(tld) for tld in risky_tlds)
        or re.search(r"(.)\1{2,}", username)
        or "cpf" in username or "rg" in username
    )

if __name__ == "__main__":
    app.run(debug=True)
