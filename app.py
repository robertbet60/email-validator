import os
import csv
import re
import smtplib
import dns.resolver
import logging
import threading
import uuid
from flask import Flask, request, jsonify, send_file, render_template
from werkzeug.utils import secure_filename
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from collections import defaultdict
from functools import partial

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB max upload

BASE_DIR = "/opt/email-validator"
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
RESULTS_DIR = os.path.join(BASE_DIR, "results")
PROGRESS_DIR = os.path.join(BASE_DIR, "progress")
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(RESULTS_DIR, exist_ok=True)
os.makedirs(PROGRESS_DIR, exist_ok=True)

logging.basicConfig(filename=os.path.join(BASE_DIR, 'validation.log'), level=logging.INFO)

DISPOSABLE_DOMAINS = set(line.strip() for line in open(os.path.join(BASE_DIR, "disposable_domains.txt")) if line.strip())
SPAM_TRAP_DOMAINS = set(line.strip() for line in open(os.path.join(BASE_DIR, "bad_domains.txt")) if line.strip())
ROLE_ADDRESSES = {"admin", "info", "support", "sales", "contact", "help", "postmaster"}
EMAIL_REGEX = re.compile(r"^(?!.*\.\.)[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")


@app.route("/")
def index():
    return render_template("index.html")

@app.route("/upload", methods=["POST"])
def upload_file():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    file = request.files["file"]
    filename = secure_filename(file.filename)
    uid = str(uuid.uuid4())
    filepath = os.path.join(UPLOAD_DIR, f"{uid}.csv")
    file.save(filepath)

    thread = threading.Thread(target=validate_emails, args=(filepath, uid))
    thread.start()

    return jsonify({"job_id": uid})

@app.route("/progress/<job_id>")
def check_progress(job_id):
    path = os.path.join(PROGRESS_DIR, f"{job_id}.txt")
    if not os.path.exists(path):
        return jsonify({"status": "pending", "percent": 0})
    with open(path) as f:
        line = f.read().strip()
    if line == "done":
        return jsonify({"status": "done"})
    try:
        return jsonify({"status": "processing", "percent": int(line)})
    except:
        return jsonify({"status": "processing", "percent": 0})

@app.route("/result/<job_id>")
def result(job_id):
    result_path = os.path.join(RESULTS_DIR, f"{job_id}_validated.csv")
    if not os.path.exists(result_path):
        return "Result not found", 404

    valid = os.path.join(RESULTS_DIR, f"{job_id}_valid.csv")
    risky = os.path.join(RESULTS_DIR, f"{job_id}_risky.csv")
    invalid = os.path.join(RESULTS_DIR, f"{job_id}_invalid.csv")
    summary_path = os.path.join(RESULTS_DIR, f"{job_id}_summary.txt")

    return jsonify({
        "downloads": {
            "all": f"/download/{os.path.basename(result_path)}",
            "valid": f"/download/{os.path.basename(valid)}",
            "risky": f"/download/{os.path.basename(risky)}",
            "invalid": f"/download/{os.path.basename(invalid)}"
        },
        "summary": open(summary_path).read() if os.path.exists(summary_path) else ""
    })

@app.route("/download/<filename>")
def download_file(filename):
    return send_file(os.path.join(RESULTS_DIR, filename), as_attachment=True)

def validate_emails(csv_path, job_id):
    result_path = os.path.join(RESULTS_DIR, f"{job_id}_validated.csv")
    valid_path = os.path.join(RESULTS_DIR, f"{job_id}_valid.csv")
    risky_path = os.path.join(RESULTS_DIR, f"{job_id}_risky.csv")
    invalid_path = os.path.join(RESULTS_DIR, f"{job_id}_invalid.csv")
    summary_path = os.path.join(RESULTS_DIR, f"{job_id}_summary.txt")
    progress_path = os.path.join(PROGRESS_DIR, f"{job_id}.txt")

    summary = defaultdict(int)
    rows = []

    with open(csv_path, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        header = reader.fieldnames
        email_key = next((h for h in header if h.lower().strip() == "email"), header[0])
        rows = list(reader)

    total = len(rows)
    results = []
    valid_rows, risky_rows, invalid_rows = [], [], []

    def wrapped_validate(row):
        email = row.get(email_key, "").strip()
        try:
            status, reason = validate_email(email)
        except Exception as e:
            status, reason = "error", str(e)
        row["status"] = status
        row["reason"] = reason
        return row, status

    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_row = {executor.submit(wrapped_validate, row): row for row in rows}
        completed = 0

        while future_to_row:
            done, _ = wait(future_to_row, timeout=10, return_when=FIRST_COMPLETED)
            for future in done:
                try:
                    row, status = future.result(timeout=8)
                    summary[status] += 1
                    results.append(row)
                    if status.startswith("valid"):
                        valid_rows.append(row)
                    elif status.startswith("risky"):
                        risky_rows.append(row)
                    else:
                        invalid_rows.append(row)
                except Exception as e:
                    logging.warning(f"Validation thread failed: {e}")
                    continue
                finally:
                    completed += 1
                    with open(progress_path, "w") as f:
                        f.write(str(int((completed / total) * 100)))
                    del future_to_row[future]

    if not results:
        logging.error("No results produced!")
        return

    fieldnames = results[0].keys()
    def write_csv(path, rows):
        with open(path, "w", newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)

    write_csv(result_path, results)
    write_csv(valid_path, valid_rows)
    write_csv(risky_path, risky_rows)
    write_csv(invalid_path, invalid_rows)

    with open(summary_path, "w") as f:
        for k, v in summary.items():
            f.write(f"{k}: {v}\n")

    with open(progress_path, "w") as f:
        f.write("done")

    logging.info(f"Job {job_id} finished. Summary: {dict(summary)}")

def validate_email(email):
    match = EMAIL_REGEX.match(email)
    if not match:
        return "invalid:syntax", "Invalid syntax"
    domain = match.group(1).lower()
    local_part = email.split("@")[0].lower()

    if is_heuristically_risky(email):
        return "risky:heuristic", "Heuristically risky"
    if domain in SPAM_TRAP_DOMAINS:
        return "risky:spam-trap", "Spam trap"
    if domain in DISPOSABLE_DOMAINS:
        return "risky:disposable", "Disposable domain"
    if local_part in ROLE_ADDRESSES:
        return "risky:role-based", "Role-based address"

    try:
        mx_records = dns.resolver.resolve(domain, 'MX', lifetime=5)
        mx_host = str(sorted(mx_records, key=lambda r: r.preference)[0].exchange).rstrip('.')
    except Exception as e:
        return "invalid:mx", f"MX lookup failed: {e}"

    try:
        server = smtplib.SMTP(mx_host, 25, timeout=8)
        server.helo("example.com")
        server.mail("test@example.com")
        code, _ = server.rcpt(email)
        server.quit()
        if code in [250, 251]:
            return "valid", "SMTP accepted"
        else:
            return "invalid:smtp", f"SMTP code {code}"
    except Exception as e:
        return "risky:smtp-error", f"SMTP failed: {e}"

def is_heuristically_risky(email):
    username, domain = email.lower().split("@")
    risky_tlds = [".xyz", ".top", ".click", ".buzz", ".club", ".site", ".online", ".space", ".fun", ".work", ".shop"]
    known_fake_terms = [
        "teste", "testando", "senha", "usuario", "user", "admin", "example", "demo",
        "password", "foobar", "fulano", "ciclano", "beltrano", "zap", "12345", "abcdef", "test1"
    ]
    risky_domains = [
        "zipmail.com.br", "bol.com.br", "uol.com.br", "superig.com.br", "r7.com",
        "hotmail.co.uk", "mail.ru", "yopmail.com", "guerrillamail.com"
    ]

    if username.isnumeric():
        return True
    if len(username) <= 2:
        return True
    if not re.search(r"[aeiou]", username):
        return True
    if any(term in username for term in known_fake_terms):
        return True
    if domain in risky_domains:
        return True
    if any(domain.endswith(tld) for tld in risky_tlds):
        return True
    if re.search(r"(.)\1{2,}", username):
        return True
    if "cpf" in username or "rg" in username:
        return True
    return False

if __name__ == "__main__":
    app.run(debug=True)
