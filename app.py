# -- snip -- same imports --
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

# -- config & setup --
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB

BASE_DIR = "/opt/email-validator"
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
RESULTS_DIR = os.path.join(BASE_DIR, "results")
PROGRESS_DIR = os.path.join(BASE_DIR, "progress")
for d in [UPLOAD_DIR, RESULTS_DIR, PROGRESS_DIR]:
    os.makedirs(d, exist_ok=True)

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
    uid = str(uuid.uuid4())
    filename = f"{uid}.csv"
    path = os.path.join(UPLOAD_DIR, filename)
    file.save(path)

    thread = threading.Thread(target=validate_emails, args=(path, uid))
    thread.start()
    return jsonify({"job_id": uid})


@app.route("/progress/<job_id>")
def check_progress(job_id):
    path = os.path.join(PROGRESS_DIR, f"{job_id}.txt")
    if not os.path.exists(path):
        return jsonify({"status": "pending", "percent": 0})
    with open(path) as f:
        txt = f.read().strip()
    return jsonify({"status": "done" if txt == "done" else "processing", "percent": int(txt) if txt.isdigit() else 0})


@app.route("/result/<job_id>")
def result(job_id):
    result_path = os.path.join(RESULTS_DIR, f"{job_id}_validated.csv")
    if not os.path.exists(result_path):
        return "Result not found", 404

    return jsonify({
        "downloads": {
            "all": f"/download/{job_id}_validated.csv",
            "valid": f"/download/{job_id}_valid.csv",
            "risky": f"/download/{job_id}_risky.csv",
            "invalid": f"/download/{job_id}_invalid.csv"
        },
        "summary": open(os.path.join(RESULTS_DIR, f"{job_id}_summary.txt")).read()
    })


@app.route("/download/<filename>")
def download_file(filename):
    return send_file(os.path.join(RESULTS_DIR, filename), as_attachment=True)


def validate_emails(path, job_id):
    progress_path = os.path.join(PROGRESS_DIR, f"{job_id}.txt")
    result_all = os.path.join(RESULTS_DIR, f"{job_id}_validated.csv")
    result_valid = os.path.join(RESULTS_DIR, f"{job_id}_valid.csv")
    result_risky = os.path.join(RESULTS_DIR, f"{job_id}_risky.csv")
    result_invalid = os.path.join(RESULTS_DIR, f"{job_id}_invalid.csv")
    summary_path = os.path.join(RESULTS_DIR, f"{job_id}_summary.txt")

    with open(path) as csvfile:
        reader = csv.DictReader(csvfile)
        header = reader.fieldnames
        email_key = next((h for h in header if h.lower().strip() == "email"), header[0])
        all_rows = list(reader)

    total = len(all_rows)
    batch_size = 5000
    batches = [all_rows[i:i+batch_size] for i in range(0, total, batch_size)]

    full_results, valid_rows, risky_rows, invalid_rows = [], [], [], []
    summary = defaultdict(int)
    completed = 0

    for batch in batches:
        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_row = {executor.submit(validate_row, r, email_key): r for r in batch}
            while future_to_row:
                done, _ = wait(future_to_row, timeout=10, return_when=FIRST_COMPLETED)
                for fut in done:
                    try:
                        row, status = fut.result(timeout=8)
                        full_results.append(row)
                        summary[status] += 1
                        if status.startswith("valid"):
                            valid_rows.append(row)
                        elif status.startswith("risky"):
                            risky_rows.append(row)
                        else:
                            invalid_rows.append(row)
                    except Exception as e:
                        logging.warning(f"Thread error: {e}")
                    finally:
                        completed += 1
                        with open(progress_path, "w") as f:
                            f.write(str(int(completed / total * 100)))
                        del future_to_row[fut]

    def write_csv(filepath, data):
        with open(filepath, "w", newline='') as f:
            writer = csv.DictWriter(f, fieldnames=full_results[0].keys())
            writer.writeheader()
            writer.writerows(data)

    write_csv(result_all, full_results)
    write_csv(result_valid, valid_rows)
    write_csv(result_risky, risky_rows)
    write_csv(result_invalid, invalid_rows)

    with open(summary_path, "w") as f:
        for k, v in summary.items():
            f.write(f"{k}: {v}\n")

    with open(progress_path, "w") as f:
        f.write("done")
    logging.info(f"Validation complete for {job_id}")


def validate_row(row, key):
    email = row.get(key, "").strip()
    try:
        status, reason = validate_email(email)
    except Exception as e:
        status, reason = "error", str(e)
    row["status"], row["reason"] = status, reason
    return row, status


def validate_email(email):
    if not EMAIL_REGEX.match(email):
        return "invalid:syntax", "Invalid format"
    domain = email.split("@")[1].lower()
    local = email.split("@")[0].lower()

    if is_heuristically_risky(email):
        return "risky:heuristic", "Heuristic match"
    if domain in SPAM_TRAP_DOMAINS:
        return "risky:spam-trap", "Spam trap"
    if domain in DISPOSABLE_DOMAINS:
        return "risky:disposable", "Disposable"
    if local in ROLE_ADDRESSES:
        return "risky:role-based", "Role address"

    try:
        mx = dns.resolver.resolve(domain, 'MX', lifetime=5)
        mx_host = str(sorted(mx, key=lambda r: r.preference)[0].exchange).rstrip(".")
    except Exception as e:
        return "invalid:mx", f"MX lookup failed: {e}"

    try:
        server = smtplib.SMTP(mx_host, 25, timeout=8)
        server.helo("example.com")
        server.mail("test@example.com")
        code, _ = server.rcpt(email)
        server.quit()
        return ("valid", "SMTP accepted") if code in [250, 251] else ("invalid:smtp", f"SMTP code {code}")
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
    if username.isnumeric() or len(username) <= 2 or not re.search(r"[aeiou]", username):
        return True
    if any(t in username for t in known_fake_terms):
        return True
    if any(domain.endswith(tld) for tld in risky_tlds) or domain in risky_domains:
        return True
    if re.search(r"(.)\1{2,}", username) or "cpf" in username or "rg" in username:
        return True
    return False


if __name__ == "__main__":
    app.run(debug=True)
