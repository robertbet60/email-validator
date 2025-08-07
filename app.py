import os
import csv
import re
import smtplib
import dns.resolver
import logging
import time
from flask import Flask, request, jsonify, send_file, render_template
from werkzeug.utils import secure_filename
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2MB max upload
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Logging
logging.basicConfig(filename='validation.log', level=logging.INFO)

# Domain filters
DISPOSABLE_DOMAINS = set(line.strip() for line in open("disposable_domains.txt") if line.strip())
SPAM_TRAP_DOMAINS = set(line.strip() for line in open("bad_domains.txt") if line.strip())
ROLE_ADDRESSES = {"admin", "info", "support", "sales", "contact", "help", "postmaster"}

# Email regex
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

    files, summary = validate_emails(filepath)
    return jsonify({
        "summary": summary,
        "downloads": files
    })

@app.route("/download/<path:filename>")
def download_file(filename):
    return send_file(os.path.join(UPLOAD_DIR, filename), as_attachment=True)

def validate_emails(csv_path):
    base = os.path.basename(csv_path).replace(".csv", "")
    all_path = os.path.join(UPLOAD_DIR, f"{base}_all.csv")
    valid_path = os.path.join(UPLOAD_DIR, f"{base}_valid.csv")
    risky_path = os.path.join(UPLOAD_DIR, f"{base}_risky.csv")

    summary = defaultdict(int)

    with open(csv_path, newline='') as csvfile, \
         open(all_path, 'w', newline='') as all_out, \
         open(valid_path, 'w', newline='') as valid_out, \
         open(risky_path, 'w', newline='') as risky_out:

        reader = csv.DictReader(csvfile)
        fieldnames = reader.fieldnames + ["status", "reason", "score"]
        all_writer = csv.DictWriter(all_out, fieldnames=fieldnames)
        valid_writer = csv.DictWriter(valid_out, fieldnames=fieldnames)
        risky_writer = csv.DictWriter(risky_out, fieldnames=fieldnames)

        for w in (all_writer, valid_writer, risky_writer):
            w.writeheader()

        emails = [(row, row["email"].strip()) for row in reader]

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(validate_email_with_retry, email): row for row, email in emails}
            for future in as_completed(futures):
                row = futures[future]
                try:
                    status, reason, score = future.result()
                except Exception as e:
                    status, reason, score = "error", str(e), 0
                row.update({"status": status, "reason": reason, "score": score})
                all_writer.writerow(row)
                if status.startswith("valid"):
                    valid_writer.writerow(row)
                elif status.startswith("risky"):
                    risky_writer.writerow(row)
                summary[status] += 1

    logging.info(f"Validation summary: {dict(summary)}")
    return {
        "all": f"/download/{os.path.basename(all_path)}",
        "valid": f"/download/{os.path.basename(valid_path)}",
        "risky": f"/download/{os.path.basename(risky_path)}"
    }, dict(summary)

def validate_email_with_retry(email, retries=2):
    for attempt in range(retries + 1):
        try:
            return validate_email(email)
        except Exception as e:
            if attempt < retries:
                time.sleep(2 ** attempt)  # Exponential backoff
            else:
                return "risky:smtp-error", f"SMTP retry failed: {e}", 60

def validate_email(email):
    match = EMAIL_REGEX.match(email)
    if not match:
        return "invalid:syntax", "Invalid format", 0

    domain = match.group(1).lower()
    local = email.split("@")[0].lower()

    if is_heuristically_risky(email):
        return "risky:heuristic", "Heuristically risky", 40
    if domain in SPAM_TRAP_DOMAINS:
        return "risky:spam-trap", "Spam trap domain", 30
    if domain in DISPOSABLE_DOMAINS:
        return "risky:disposable", "Disposable domain", 35
    if local in ROLE_ADDRESSES:
        return "risky:role-based", "Role-based address", 50

    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        mx_host = str(sorted(mx_records, key=lambda r: r.preference)[0].exchange).rstrip('.')
    except Exception as e:
        return "invalid:mx", f"MX lookup failed: {e}", 0

    try:
        server = smtplib.SMTP(mx_host, 25, timeout=10)
        server.set_debuglevel(0)
        server.ehlo("yourdomain.com")
        server.mail("validator@yourdomain.com")
        code, _ = server.rcpt(email)
        server.quit()

        if 200 <= code < 300:
            return "valid", "Accepted by SMTP", 100
        elif 400 <= code < 500:
            return "risky:smtp-soft", f"Temporary SMTP error ({code})", 70
        else:
            return "invalid:smtp", f"SMTP rejected ({code})", 0
    except Exception as e:
        return "risky:smtp-error", f"SMTP exception: {e}", 60

def is_heuristically_risky(email):
    user, domain = email.lower().split("@")
    risky_tlds = [".xyz", ".top", ".click", ".buzz", ".club", ".site", ".online", ".space", ".fun", ".work", ".shop"]
    known_terms = [
        "teste", "testando", "senha", "usuario", "user", "admin", "example", "demo",
        "password", "foobar", "fulano", "ciclano", "beltrano", "zap", "12345", "abcdef", "test1"
    ]
    risky_domains = [
        "zipmail.com.br", "bol.com.br", "uol.com.br", "superig.com.br", "r7.com",
        "hotmail.co.uk", "mail.ru", "yopmail.com", "guerrillamail.com"
    ]

    if user.isnumeric() or len(user) <= 2 or not re.search(r"[aeiou]", user):
        return True
    if any(term in user for term in known_terms):
        return True
    if domain in risky_domains or any(domain.endswith(tld) for tld in risky_tlds):
        return True
    if re.search(r"(.)\\1{2,}", user) or "cpf" in user or "rg" in user:
        return True

    return False
