from datetime import datetime, timezone
from module.collector.whois_collector import WHOISCollector


def analyze_whois(whois_data):
    findings = []

    if "error" in whois_data:
        findings.append({
            "title": "WHOIS Lookup Failed",
            "severity": "Medium",
            "status": "Error",
            "description": whois_data["error"]
        })

        return {
            "domain": whois_data.get("domain"),
            "findings": findings
        }

    # Domain age
    domain_age = whois_data.get("domain_age_days")

    if domain_age is not None:

        if domain_age < 30:
            severity = "High"
            status = "Warning"
            description = (
                f"The domain was registered {domain_age} days ago. "
                "Very recently registered domains can be a useful signal "
                "in legitimacy analysis."
            )

        elif domain_age < 180:
            severity = "Medium"
            status = "Warning"
            description = (
                f"The domain is approximately {domain_age} days old."
            )

        elif domain_age < 365:
            severity = "Low"
            status = "Informational"
            description = (
                f"The domain is approximately {domain_age} days old."
            )

        else:
            severity = "Informational"
            status = "Normal"
            description = (
                f"The domain has been registered for approximately "
                f"{domain_age} days."
            )

        findings.append({
            "title": "Domain Age",
            "severity": severity,
            "status": status,
            "description": description
        })

    # Expiration
    expiration_date = whois_data.get("expiration_date")

    if expiration_date:
        try:
            expiry = datetime.fromisoformat(
                expiration_date.replace("Z", "+00:00")
            )

            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)

            days_until_expiry = (
                expiry - datetime.now(timezone.utc)
            ).days

            if days_until_expiry < 0:
                severity = "High"
                status = "Expired"

            elif days_until_expiry <= 30:
                severity = "High"
                status = "Expiring Soon"

            elif days_until_expiry <= 90:
                severity = "Medium"
                status = "Expiring Soon"

            else:
                severity = "Informational"
                status = "Valid"

            findings.append({
                "title": "Domain Expiration",
                "severity": severity,
                "status": status,
                "description": (
                    f"Domain expiration date: {expiration_date}. "
                    f"Approximately {max(days_until_expiry, 0)} days remaining."
                )
            })

        except (ValueError, TypeError):
            findings.append({
                "title": "Domain Expiration",
                "severity": "Informational",
                "status": "Unknown",
                "description": "Expiration date could not be parsed."
            })

    else:
        findings.append({
            "title": "Domain Expiration",
            "severity": "Low",
            "status": "Unavailable",
            "description": "Domain expiration information is not available."
        })

    # DNSSEC
    dnssec = whois_data.get("dnssec")

    if dnssec:
        findings.append({
            "title": "DNSSEC",
            "severity": "Informational",
            "status": "Enabled",
            "description": f"DNSSEC status: {dnssec}."
        })
    else:
        findings.append({
            "title": "DNSSEC",
            "severity": "Low",
            "status": "Not Detected",
            "description": (
                "DNSSEC information is not available or DNSSEC is not enabled."
            )
        })

    # Registrar
    registrar = whois_data.get("registrar")

    if registrar:
        findings.append({
            "title": "Registrar Information",
            "severity": "Informational",
            "status": "Available",
            "description": f"Registrar: {registrar}."
        })
    else:
        findings.append({
            "title": "Registrar Information",
            "severity": "Informational",
            "status": "Unavailable",
            "description": "Registrar information is not available."
        })

    # Name servers
    name_servers = whois_data.get("name_servers")

    if name_servers:
        findings.append({
            "title": "Name Servers",
            "severity": "Informational",
            "status": "Available",
            "description": (
                f"{len(name_servers)} name server(s) were identified."
            )
        })
    else:
        findings.append({
            "title": "Name Servers",
            "severity": "Medium",
            "status": "Unavailable",
            "description": "No name server information was found."
        })

    # Domain status
    status = whois_data.get("status")

    if status:
        findings.append({
            "title": "Domain Status",
            "severity": "Informational",
            "status": "Available",
            "description": f"WHOIS domain status: {status}."
        })

    return {
        "domain": whois_data.get("domain"),
        "domain_name": whois_data.get("domain_name"),
        "creation_date": whois_data.get("creation_date"),
        "updated_date": whois_data.get("updated_date"),
        "expiration_date": whois_data.get("expiration_date"),
        "domain_age_days": whois_data.get("domain_age_days"),
        "dnssec": dnssec,
        "findings": findings
    }

def get_whois_data(domain: str):

    collector = WHOISCollector(domain)

    data = collector.collect()

    result = analyze_whois(data)

    return result