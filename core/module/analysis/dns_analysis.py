from module.collector.dns_collection import DNSCollector


def analyze_dns(dns_data):

    findings = []

    domain = dns_data.get("domain")
    dns_records = dns_data.get("dns_records", {})

    # --------------------------------
    # A Record
    # --------------------------------

    a_records = dns_records.get("A", [])

    if a_records:
        findings.append({
            "check": "A Record",
            "status": "Present",
            "severity": "Informational",
            "description": f"The domain resolves to {len(a_records)} IPv4 address(es).",
            "recommendation": None
        })
    else:
        findings.append({
            "check": "A Record",
            "status": "Missing",
            "severity": "Medium",
            "description": "No IPv4 A record was found for the domain.",
            "recommendation": "Verify that the domain has a valid A record if IPv4 connectivity is required."
        })

    # --------------------------------
    # AAAA Record
    # --------------------------------

    aaaa_records = dns_records.get("AAAA", [])

    if aaaa_records:
        findings.append({
            "check": "AAAA Record",
            "status": "Present",
            "severity": "Informational",
            "description": f"The domain has {len(aaaa_records)} IPv6 address(es).",
            "recommendation": None
        })
    else:
        findings.append({
            "check": "AAAA Record",
            "status": "Not Configured",
            "severity": "Informational",
            "description": "No IPv6 AAAA record was found.",
            "recommendation": "Configure an AAAA record if IPv6 connectivity is required."
        })

    # --------------------------------
    # MX Record
    # --------------------------------

    mx_records = dns_records.get("MX", [])

    if mx_records:
        findings.append({
            "check": "MX Record",
            "status": "Present",
            "severity": "Informational",
            "description": f"The domain has {len(mx_records)} mail exchange record(s).",
            "recommendation": None
        })
    else:
        findings.append({
            "check": "MX Record",
            "status": "Missing",
            "severity": "Low",
            "description": "No MX record was found for the domain.",
            "recommendation": "Configure an MX record if the domain is intended to receive email."
        })

    # --------------------------------
    # SPF
    # --------------------------------

    txt_records = dns_records.get("TXT", [])

    spf_records = [
        record for record in txt_records
        if "v=spf1" in record.lower()
    ]

    if spf_records:

        findings.append({
            "check": "SPF",
            "status": "Present",
            "severity": "Informational",
            "description": "An SPF policy is configured in the domain's TXT records.",
            "recommendation": None
        })

        # Check for overly permissive SPF
        for spf in spf_records:

            spf_lower = spf.lower()

            if "+all" in spf_lower:
                findings.append({
                    "check": "SPF Policy",
                    "status": "Weak",
                    "severity": "High",
                    "description": "The SPF policy uses +all, allowing any mail server to send email for the domain.",
                    "recommendation": "Avoid +all and configure SPF with a restrictive ending such as -all or ~all."
                })

            elif "?all" in spf_lower:
                findings.append({
                    "check": "SPF Policy",
                    "status": "Neutral",
                    "severity": "Medium",
                    "description": "The SPF policy uses ?all, which provides no definitive authorization decision.",
                    "recommendation": "Use a more restrictive SPF policy where appropriate."
                })

            elif "~all" in spf_lower:
                findings.append({
                    "check": "SPF Policy",
                    "status": "Soft Fail",
                    "severity": "Low",
                    "description": "The SPF policy uses ~all, causing unauthorized senders to receive a soft-fail result.",
                    "recommendation": "Consider using -all when all legitimate sending sources are known."
                })

            elif "-all" in spf_lower:
                findings.append({
                    "check": "SPF Policy",
                    "status": "Strict",
                    "severity": "Informational",
                    "description": "The SPF policy uses -all to reject unauthorized sending sources.",
                    "recommendation": None
                })

    else:

        findings.append({
            "check": "SPF",
            "status": "Missing",
            "severity": "Medium",
            "description": "No SPF record was found in the domain's TXT records.",
            "recommendation": "Configure an SPF record to help prevent unauthorized email sending."
        })

    # --------------------------------
    # CAA Record
    # --------------------------------

    caa_records = dns_records.get("CAA", [])

    if caa_records:
        findings.append({
            "check": "CAA Record",
            "status": "Present",
            "severity": "Informational",
            "description": "The domain has a Certificate Authority Authorization (CAA) record.",
            "recommendation": None
        })
    else:
        findings.append({
            "check": "CAA Record",
            "status": "Missing",
            "severity": "Low",
            "description": "No CAA record was found for the domain.",
            "recommendation": "Consider configuring a CAA record to specify which certificate authorities may issue certificates for the domain."
        })

    # --------------------------------
    # NS Record
    # --------------------------------

    ns_records = dns_records.get("NS", [])

    if ns_records:

        findings.append({
            "check": "NS Record",
            "status": "Present",
            "severity": "Informational",
            "description": f"The domain has {len(ns_records)} authoritative name server(s).",
            "recommendation": None
        })

    else:

        findings.append({
            "check": "NS Record",
            "status": "Missing",
            "severity": "High",
            "description": "No authoritative name server records were found.",
            "recommendation": "Verify the domain's DNS delegation and authoritative name servers."
        })

    # --------------------------------
    # CNAME Record
    # --------------------------------

    cname_records = dns_records.get("CNAME", [])

    if cname_records:

        findings.append({
            "check": "CNAME Record",
            "status": "Present",
            "severity": "Informational",
            "description": "A CNAME record is configured for the domain.",
            "recommendation": None
        })

    else:

        findings.append({
            "check": "CNAME Record",
            "status": "Not Configured",
            "severity": "Informational",
            "description": "No CNAME record was found for the domain.",
            "recommendation": None
        })

    # --------------------------------
    # SOA Record
    # --------------------------------

    soa_records = dns_records.get("SOA", [])

    if soa_records:

        findings.append({
            "check": "SOA Record",
            "status": "Present",
            "severity": "Informational",
            "description": "The domain has a Start of Authority (SOA) record.",
            "recommendation": None
        })

    else:

        findings.append({
            "check": "SOA Record",
            "status": "Missing",
            "severity": "Medium",
            "description": "No SOA record was found for the domain.",
            "recommendation": "Verify the domain's authoritative DNS configuration."
        })

    # --------------------------------
    # PTR Record
    # --------------------------------

    ptr_records = dns_records.get("PTR", [])

    if ptr_records:

        findings.append({
            "check": "PTR Record",
            "status": "Present",
            "severity": "Informational",
            "description": "A PTR record was found.",
            "recommendation": None
        })

    else:

        findings.append({
            "check": "PTR Record",
            "status": "Not Found",
            "severity": "Informational",
            "description": "No PTR record was found for the queried domain.",
            "recommendation": "Configure reverse DNS (PTR) where reverse DNS is required, particularly for mail servers."
        })

    # --------------------------------
    # Final Result
    # --------------------------------

    return {
        "domain": domain,
        "findings": findings
    }


def get_dns_data(domain: str):

    collector = DNSCollector(domain)

    dns_data = collector.collect()

    result = analyze_dns(dns_data)

    return result
