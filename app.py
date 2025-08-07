import os
import csv
import re
import smtplib
import dns.resolver
import logging
from flask import Flask, request, send_file, render_template_string
from werkzeug.utils import secure_filename
from concurrent.futures import ThreadPoolExecutor, as_completed

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # Limit upload size to 2MB

# Logging
logging.basicConfig(filename='validation.log', level=logging.INFO)

# Disposable and role-based lists
DISPOSABLE_DOMAINS = set(line.strip() for line in open("disposable_domains.txt") if line.strip())
ROLE_ADDRESSES = {"admin", "info", "support", "sales", "contact", "help", "postmaster"}

# Email regex
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$")

UPLOAD_FORM = '''
<!doctype html>
<title>Email Validator</title>
<h1>Upload CSV with emails (header must be "email")</h1>
<form method=post enctype=multipart/form-data>
  <input type=file name=file>
  <input type=submit value=Upload>
</form>
'''

@app.route("/", methods=["GET", "POST"])
def upload_file():
    if request.method == "POST":
        file = request.files["file"]
        if not file:
            return "No file uploaded", 400
        filename = secure_filename(file.filename)
        filepath = os.path.join("uploads", filename)
        os.makedirs("uploads", exist_ok=True)
        file.save(filepath)
        output = validate_emails(filepath)
        return send_file(output, as_attachment=True)
    return render_template_string(UPLOAD_FORM)

def validate_emails(csv_path):
    result_path = csv_path.replace(".csv", "_validated.csv")
    valid_count = 0
    risky_count = 0
    invalid_count = 0

    with open(csv_path, newline='') as csvfile, open(result_path, 'w', newline='') as outfile:
        reader = csv.DictReader(csvfile)
        fieldnames = reader.fieldnames + ["status", "reason"]
        writer = csv.DictWriter(outfile, fieldnames=fieldnames)
        writer.writeheader()

        emails = [(row, row["email"].strip()) for row in reader]

        with ThreadPoolExecutor(max_workers=min(10, len(emails))) as executor:
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

                # Track results
                if status == "valid":
                    valid_count += 1
                elif status == "risky":
                    risky_count += 1
                else:
                    invalid_count += 1

    logging.info(f"Validation complete: {valid_count} valid, {risky_count} risky, {invalid_count} invalid")
    return result_path

def validate_email_with_retry(email, retries=1):
    for attempt in range(retries + 1):
        status, reason = validate_email(email)
        if status != "risky" or attempt == retries:
            return status, reason
    return status, reason

def validate_email(email):
    match = EMAIL_REGEX.match(email)
    if not match:
        return "invalid", "Invalid syntax"
    domain = match.group(1)
    local_part = email.split("@")[0].lower()

    if domain.lower() in DISPOSABLE_DOMAINS:
        return "risky", "Disposable domain"
    if local_part in ROLE_ADDRESSES:
        return "risky", "Role-based address"

    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        mx_host = str(sorted(mx_records, key=lambda r: r.preference)[0].exchange).rstrip('.')
    except Exception as e:
        return "invalid", f"MX lookup failed: {e}"

    try:
        server = smtplib.SMTP(mx_host, 25, timeout=10)
        server.set_debuglevel(0)
        server.helo("example.com")
        server.mail("test@example.com")
        code, _ = server.rcpt(email)
        server.quit()

        if code in [250, 251]:
            return "valid", "Accepted by SMTP"
        else:
            return "invalid", f"SMTP rejected with code {code}"
    except Exception as e:
        logging.info(f"SMTP error for {email}: {e}")
        return "risky", f"SMTP check failed: {e}"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
