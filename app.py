import os
import csv
import re
import smtplib
import dns.resolver
from flask import Flask, request, send_file, render_template_string

app = Flask(__name__)

# Disposable and role-based lists
DISPOSABLE_DOMAINS = set(line.strip() for line in open("disposable_domains.txt") if line.strip())
ROLE_ADDRESSES = {"admin", "info", "support", "sales", "contact", "help", "postmaster"}

# Email regex
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$")

# Template for upload form
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
        filepath = os.path.join("uploads", file.filename)
        os.makedirs("uploads", exist_ok=True)
        file.save(filepath)
        output = validate_emails(filepath)
        return send_file(output, as_attachment=True)
    return render_template_string(UPLOAD_FORM)

def validate_emails(csv_path):
    result_path = csv_path.replace(".csv", "_validated.csv")
    with open(csv_path, newline='') as csvfile, open(result_path, 'w', newline='') as outfile:
        reader = csv.DictReader(csvfile)
        fieldnames = reader.fieldnames + ["status", "reason"]
        writer = csv.DictWriter(outfile, fieldnames=fieldnames)
        writer.writeheader()
        for row in reader:
            email = row["email"].strip()
            status, reason = validate_email(email)
            row["status"] = status
            row["reason"] = reason
            writer.writerow(row)
    return result_path

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
        # SMTP check with timeout
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
        return "risky", f"SMTP check failed: {e}"



if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)

