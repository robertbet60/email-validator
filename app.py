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

    # SMTP check temporarily disabled to prevent server timeout
    # try:
    #     server = smtplib.SMTP(timeout=10)
    #     server.connect(mx_host)
    #     server.helo("example.com")
    #     server.mail("test@example.com")
    #     code, _ = server.rcpt(email)
    #     server.quit()
    #     if code in [250, 251]:
    #         return "valid", "Accepted by SMTP"
    #     else:
    #         return "invalid", f"SMTP rejected with code {code}"
    # except Exception as e:
    #     return "risky", f"SMTP check failed: {e}"

    # Fallback response since SMTP check is skipped
    return "valid", "MX record found, SMTP check skipped"
