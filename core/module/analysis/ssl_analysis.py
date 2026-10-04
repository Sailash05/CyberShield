from module.collector.ssl_collector import SslCollector

def analyze_ssl(ssl_data):

    findings = []

    # --------------------------------
    # Certificate Expiry
    # --------------------------------

    days_remaining = ssl_data.get("Days Remaining")

    if days_remaining is None:

        findings.append({
            "check": "Certificate Expiry",
            "status": "Unknown",
            "severity": "Informational",
            "description": "Certificate expiry information is unavailable.",
            "recommendation": "Verify the SSL certificate manually."
        })

    elif days_remaining < 0:

        findings.append({
            "check": "Certificate Expiry",
            "status": "Failed",
            "severity": "Critical",
            "description": "The SSL certificate has expired.",
            "recommendation": "Renew the SSL certificate immediately."
        })

    elif days_remaining <= 7:

        findings.append({
            "check": "Certificate Expiry",
            "status": "Warning",
            "severity": "High",
            "description": f"The certificate expires in {days_remaining} days.",
            "recommendation": "Renew the certificate immediately."
        })

    elif days_remaining <= 30:

        findings.append({
            "check": "Certificate Expiry",
            "status": "Warning",
            "severity": "Medium",
            "description": f"The certificate expires in {days_remaining} days.",
            "recommendation": "Plan certificate renewal soon."
        })

    else:

        findings.append({
            "check": "Certificate Expiry",
            "status": "Secure",
            "severity": "Informational",
            "description": f"The certificate has {days_remaining} days remaining.",
            "recommendation": None
        })


    # --------------------------------
    # TLS Version
    # --------------------------------

    tls_version = ssl_data.get("TLS Version")

    if tls_version == "TLSv1.3":

        findings.append({
            "check": "TLS Version",
            "status": "Secure",
            "severity": "Informational",
            "description": "The server supports TLS 1.3.",
            "recommendation": None
        })

    elif tls_version == "TLSv1.2":

        findings.append({
            "check": "TLS Version",
            "status": "Secure",
            "severity": "Informational",
            "description": "The server uses TLS 1.2.",
            "recommendation": "Consider supporting TLS 1.3 where possible."
        })

    elif tls_version in ["TLSv1", "TLSv1.1"]:

        findings.append({
            "check": "TLS Version",
            "status": "Vulnerable",
            "severity": "High",
            "description": f"The server uses an outdated TLS version: {tls_version}.",
            "recommendation": "Disable TLS 1.0 and TLS 1.1 and use TLS 1.2 or TLS 1.3."
        })

    else:

        findings.append({
            "check": "TLS Version",
            "status": "Unknown",
            "severity": "Medium",
            "description": f"Unrecognized TLS version: {tls_version}.",
            "recommendation": "Verify the supported TLS versions."
        })


    # --------------------------------
    # Cipher
    # --------------------------------

    cipher = ssl_data.get("Cipher")

    weak_cipher_keywords = [
        "RC4",
        "3DES",
        "DES",
        "MD5",
        "NULL",
        "EXPORT"
    ]

    if cipher:

        cipher_upper = cipher.upper()

        if any(keyword in cipher_upper for keyword in weak_cipher_keywords):

            findings.append({
                "check": "Cipher",
                "status": "Vulnerable",
                "severity": "High",
                "description": f"Weak cipher detected: {cipher}.",
                "recommendation": "Use modern authenticated encryption ciphers such as AES-GCM or ChaCha20-Poly1305."
            })

        else:

            findings.append({
                "check": "Cipher",
                "status": "Secure",
                "severity": "Informational",
                "description": f"Modern cipher detected: {cipher}.",
                "recommendation": None
            })


    # --------------------------------
    # Final Result
    # --------------------------------

    return {
        "domain": ssl_data.get("Domain"),
        "findings": findings
    }


def get_ssl_data(domain: str):

    sslCollector = SslCollector(domain)

    ssl_data = sslCollector.check_ssl()

    result = analyze_ssl(ssl_data)

    return result