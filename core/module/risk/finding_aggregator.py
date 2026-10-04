SEVERITY_ORDER = {
    "Critical": 4,
    "High": 3,
    "Medium": 2,
    "Low": 1,
    "Informational": 0
}


def aggregate_findings(*analysis_results):
    """
    Combine findings from multiple analysis modules
    into one normalized list.
    """

    all_findings = []

    for result in analysis_results:

        if not isinstance(result, dict):
            continue

        source = get_source(result)

        findings = result.get("findings", [])

        if not isinstance(findings, list):
            continue

        for finding in findings:

            if not isinstance(finding, dict):
                continue

            normalized = {
                "source": source,
                "title": finding.get(
                    "title",
                    finding.get("check", "Unknown Finding")
                ),
                "severity": finding.get(
                    "severity",
                    "Informational"
                ),
                "status": finding.get("status"),
                "description": finding.get("description"),
                "recommendation": finding.get("recommendation")
            }

            all_findings.append(normalized)

    # Sort from highest severity to lowest
    all_findings.sort(
        key=lambda x: SEVERITY_ORDER.get(
            x["severity"], 0
        ),
        reverse=True
    )

    return all_findings


def get_source(result):
    """
    Identify which analysis module produced the findings.
    """

    if "domain" in result:
        return "DNS / WHOIS"

    if "technologies" in result:
        return "Technology"

    if "normalized_url" in result:
        return "URL"

    # Header analyzer
    if any(
        finding.get("header")
        for finding in result.get("findings", [])
        if isinstance(finding, dict)
    ):
        return "HTTP Headers"

    # SSL analyzer
    if any(
        finding.get("check") in [
            "Certificate Expiry",
            "TLS Version",
            "Cipher"
        ]
        for finding in result.get("findings", [])
        if isinstance(finding, dict)
    ):
        return "SSL/TLS"

    # HTTP method analyzer
    if any(
        "Method" in finding.get("check", "")
        or finding.get("check") == "Allow Header"
        or finding.get("check") == "Supported Methods"
        for finding in result.get("findings", [])
        if isinstance(finding, dict)
    ):
        return "HTTP Methods"

    # HTTP information analyzer
    if any(
        finding.get("check") in [
            "HTTPS",
            "HTTP Redirect",
            "HTTP Status",
            "HTTP Version",
            "Redirect Count",
            "Response Time",
            "Cookies"
        ]
        for finding in result.get("findings", [])
        if isinstance(finding, dict)
    ):
        return "HTTP Information"

    return "Unknown"


def summarize_findings(findings):
    """
    Generate severity counts from aggregated findings.
    """

    summary = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Informational": 0
    }

    for finding in findings:
        severity = finding.get("severity", "Informational")

        if severity in summary:
            summary[severity] += 1

    summary["Total"] = len(findings)

    return summary