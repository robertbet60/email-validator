import os
import csv
import re
import smtplib
import dns.resolver
import logging
from flask import Flask, request, jsonify, send_file, render_template
from werkzeug.utils import secure_filename
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2MB max upload
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Logging setup
logging.basicConfig(filename='validation.log', level=logging.INFO)

# Load domain lists
DISPOSABLE_DOMAINS = set(line.strip() for line in open("disposable_domains.txt") if line.strip())
SPAM_TRAP_DOMAINS = set(line.strip() for line in open("bad_domains.txt") if line.strip())
ROLE_ADDRESSES = {"admin", "info", "support", "sales", "contact", "help", "postmaster"}

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$")

@app.route("/", methods=["GET"])
def home():
    return render_template("index.html")

@app.route("/validate", methods=["POST"])
def validate_route():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    file = request.files["file"]
    filename = secure_filename(file.filename)
    filepath = os.path.join(UPLOAD_DIR, filename)
    file.save(filepath)

    output_file, summary, download_name = validate_emails(filepath)
    return jsonify({
        "summary": summary,
        "download": f"/download/{download_name}"
    })

@app.route("/download/<path:filename>")
def download_file(filename):
    return send_file(os.path.join(UPLOAD_DIR, filename), as_attachment=True)

def validate_emails(csv_path):
    base = os.path.basename(csv_path).replace(".csv", "")
    result_path = os.path.join(UPLOAD_DIR, f"{base}_validated.csv")
    summary = defaultdict(int)

    with open(csv_path, newline='') as csvfile, open(result_path, 'w', newline='') as outfile:
        reader = csv.DictReader(csvfile)
        fieldnames = reader.fieldnames + ["status", "reason"]
        writer = csv.DictWriter(outfile, fieldnames=fieldnames)
        writer.writeheader()

        emails = [(row, row["email"].strip()) for row in reader]

        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_row = {executor.submit(validate_email_with_retry, email): row for row, email in emails}
            for future in as_completed(future_to_row):
                row = future_to_row[future]
                try:
                    status, reason = future.result()
                except Exception as e:
                    status, reason = "error", str(e)
                row["status"] = status
                row["reason"] = reason
                writer.writerow(row)
                summary[status] += 1

    logging.info(f"Validation summary: {dict(summary)}")
    return result_path, dict(summary), os.path.basename(result_path)

def validate_email_with_retry(email, retries=1):
    for attempt in range(retries + 1):
        status, reason = validate_email(email)
        if not status.startswith("risky") or attempt == retries:
            return status, reason
    return status, reason

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
