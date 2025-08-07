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
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2MB max upload

UPLOAD_DIR = "uploads"
RESULTS_DIR = "results"
PROGRESS_DIR = "progress"
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(RESULTS_DIR, exist_ok=True)
os.makedirs(PROGRESS_DIR, exist_ok=True)

# Logging setup
logging.basicConfig(filename='validation.log', level=logging.INFO)

# Load domain lists
DISPOSABLE_DOMAINS = set(line.strip() for line in open("disposable_domains.txt") if line.strip())
SPAM_TRAP_DOMAINS = set(line.strip() for line in open("bad_domains.txt") if line.strip())
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
    filename = secure_filename(file.filename)
    uid = str(uuid.uuid4())
    filepath = os.path.join(UPLOAD_DIR, f"{uid}.csv")
    file.save(filepath)

    # Start background thread
    thread = threading.Thread(target=validate_emails, args=(filepath, uid))
    thread.start()

    return jsonify({"job_id": uid})

@app.route("/progress/<job_id>")
def check_progress(job_id):
    progress_path = os.path.join(PROGRESS_DIR, f"{job_id}.txt")
    if not os.path.exists(progress_path):
        return jsonify({"status": "pending", "percent": 0})
    with open(progress_path) as f:
        line = f.read().strip()
    if line == "done":
        return jsonify({"status": "done"})
    return jsonify({"status": "processing", "percent": int(line)})

@app.route("/result/<job_id>")
def download_result(job_id):
    file_path = os.path.join(RESULTS_DIR, f"{job_id}_validated.csv")
    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    return "Result not found", 404

def validate_emails(csv_path, job_id):
    result_path = os.path.join(RESULTS_DIR, f"{job_id}_validated.csv")
    progress_path = os.path.join(PROGRESS_DIR, f"{job_id}.txt")
    summary = defaultdict(int)

    with open(csv_path, newline='') as csvfile:
        reader = list(csv.DictReader(csvfile))
        total = len(reader)
        with open(result_path, 'w', newline='') as outfile:
            fieldnames = reader[0].keys() | {"status", "reason"}
            writer = csv.DictWriter(outfile, fieldnames=fieldnames)
            writer.writeheader()

            def worker(row):
                email = row["email"].strip()
                try:
                    status, reason = validate_email(email)
                except Exception as e:
                    status, reason = "error", str(e)
                row["status"] = status
                row["reason"] = reason
                return row, status

            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = [executor.submit(worker, row) for row in reader]
                for i, future in enumerate(as_completed(futures)):
                    row, status = future.result()
                    summary[status] += 1
                    writer.writerow(row)
                    with open(progress_path, "w") as f:
                        f.write(str(int((i + 1) / total * 100)))

    with open(progress_path, "w") as f:
        f.write("done")
    logging.info(f"Summary: {dict(summary)}")

def validate_email(email):
    match = EMAIL_REGEX.match(email)
    if not match:
        return "invalid:syntax", "Invalid email format"
    domain = match.group(1).lower()
    local_part = email.split("@")[0].lower()

    if is_heuristically_risky(email):
        return "risky:heuristic", "Heuristically risky"
    if domain in SPAM_TRAP_DOMAINS:
        return "risky:spam-trap", "Spam trap domain"
    if domain in DISPOSABLE_DOMAINS:
        return "risky:disposable", "Disposable domain"
    if local_part in ROLE_ADDRESSES:
        return "risky:role-based", "Role-based address"

    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        mx_host = str(sorted(mx_records, key=lambda r: r.preference)[0].exchange).rstrip('.')
    except Exception as e:
        return "invalid:mx", f"MX lookup failed: {e}"

    try:
        server = smtplib.SMTP(mx_host, 25, timeout=10)
        server.helo("example.com")
        server.mail("test@example.com")
        code, _ = server.rcpt(email)
        server.quit()
        if code in [250, 251]:
            return "valid", "Accepted by SMTP"
        else:
            return "invalid:smtp", f"SMTP rejected with code {code}"
    except Exception as e:
        return "risky:smtp-error", f"SMTP check failed: {e}"

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
