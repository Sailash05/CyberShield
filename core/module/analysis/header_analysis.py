from module.collector.header_collection import HeaderCollector

def analyze_headers(header_data):

    security_headers = header_data.get("security_headers", {})

    findings = []

    checks = {
        "Content-Security-Policy": {
            "severity": "High",
            "title": "Missing Content Security Policy",
            "description": (
                "The website does not define a Content-Security-Policy "
                "header."
            ),
            "recommendation": (
                "Implement a Content-Security-Policy to reduce the risk "
                "of XSS and other content injection attacks."
            )
        },

        "Strict-Transport-Security": {
            "severity": "High",
            "title": "Missing HTTP Strict Transport Security",
            "description": (
                "The website does not define the Strict-Transport-Security "
                "header."
            ),
            "recommendation": (
                "Enable HSTS to force browsers to use HTTPS."
            )
        },

        "X-Frame-Options": {
            "severity": "Medium",
            "title": "Missing X-Frame-Options",
            "description": (
                "The website does not define X-Frame-Options."
            ),
            "recommendation": (
                "Set X-Frame-Options to DENY or SAMEORIGIN, "
                "or use CSP frame-ancestors."
            )
        },

        "X-Content-Type-Options": {
            "severity": "Medium",
            "title": "Missing X-Content-Type-Options",
            "description": (
                "The website does not define X-Content-Type-Options."
            ),
            "recommendation": (
                "Set X-Content-Type-Options to nosniff."
            )
        },

        "Referrer-Policy": {
            "severity": "Low",
            "title": "Missing Referrer Policy",
            "description": (
                "The website does not define a Referrer-Policy."
            ),
            "recommendation": (
                "Configure a restrictive Referrer-Policy such as "
                "strict-origin-when-cross-origin."
            )
        },

        "Permissions-Policy": {
            "severity": "Low",
            "title": "Missing Permissions Policy",
            "description": (
                "The website does not define a Permissions-Policy."
            ),
            "recommendation": (
                "Define a Permissions-Policy to restrict unnecessary "
                "browser capabilities."
            )
        },

        "Cross-Origin-Opener-Policy": {
            "severity": "Low",
            "title": "Missing Cross-Origin-Opener-Policy",
            "description": (
                "The website does not define a Cross-Origin-Opener-Policy."
            ),
            "recommendation": (
                "Consider configuring COOP where cross-origin isolation "
                "is required."
            )
        },

        "Cross-Origin-Resource-Policy": {
            "severity": "Low",
            "title": "Missing Cross-Origin-Resource-Policy",
            "description": (
                "The website does not define a Cross-Origin-Resource-Policy."
            ),
            "recommendation": (
                "Consider configuring CORP to control cross-origin "
                "resource loading."
            )
        },

        "Cross-Origin-Embedder-Policy": {
            "severity": "Low",
            "title": "Missing Cross-Origin-Embedder-Policy",
            "description": (
                "The website does not define a Cross-Origin-Embedder-Policy."
            ),
            "recommendation": (
                "Consider configuring COEP when cross-origin isolation "
                "is required."
            )
        }
    }

    for header, check in checks.items():

        value = security_headers.get(header)

        if value is None:

            findings.append({
                "header": header,
                "status": "Missing",
                "severity": check["severity"],
                "title": check["title"],
                "description": check["description"],
                "recommendation": check["recommendation"]
            })

        else:

            findings.append({
                "header": header,
                "status": "Present",
                "severity": "Informational",
                "title": f"{header} is configured",
                "description": f"{header} is present.",
                "recommendation": None
            })

    return {
        "url": header_data.get("url"),
        "findings": findings
    }


def get_header_data(url: str):

    headers = HeaderCollector.collect(url)

    result = analyze_headers(headers)

    return result