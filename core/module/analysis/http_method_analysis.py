from module.collector.http_method_collector import HTTPMethodsCollector


def analyze_http_methods(method_data):

    findings = []

    url = method_data.get("url")
    allow_header = method_data.get("allow_header", [])
    supported_methods = method_data.get("supported_methods", [])
    tested_methods = method_data.get("tested_methods", [])
    errors = method_data.get("errors", [])

    # --------------------------------
    # Allow Header
    # --------------------------------

    if allow_header:

        findings.append({
            "check": "Allow Header",
            "status": "Present",
            "severity": "Informational",
            "description": (
                f"The server advertises the following HTTP methods: "
                f"{', '.join(allow_header)}."
            ),
            "recommendation": None
        })

    else:

        findings.append({
            "check": "Allow Header",
            "status": "Not Present",
            "severity": "Informational",
            "description": "The server did not provide an Allow header.",
            "recommendation": None
        })

    # --------------------------------
    # GET
    # --------------------------------

    get_result = next(
        (
            item for item in tested_methods
            if item.get("method") == "GET"
        ),
        None
    )

    if get_result:

        status_code = get_result.get("status_code")

        if 200 <= status_code < 300:

            findings.append({
                "check": "GET Method",
                "status": "Allowed",
                "severity": "Informational",
                "description": f"GET requests returned HTTP {status_code}.",
                "recommendation": None
            })

        elif status_code == 405:

            findings.append({
                "check": "GET Method",
                "status": "Blocked",
                "severity": "Medium",
                "description": "The server rejected the GET method.",
                "recommendation": "Verify that GET is intentionally disabled."
            })

        else:

            findings.append({
                "check": "GET Method",
                "status": "Restricted",
                "severity": "Low",
                "description": f"GET requests returned HTTP {status_code}.",
                "recommendation": "Verify the server's GET method configuration."
            })

    # --------------------------------
    # HEAD
    # --------------------------------

    head_result = next(
        (
            item for item in tested_methods
            if item.get("method") == "HEAD"
        ),
        None
    )

    if head_result:

        status_code = head_result.get("status_code")

        if 200 <= status_code < 300:

            findings.append({
                "check": "HEAD Method",
                "status": "Allowed",
                "severity": "Informational",
                "description": f"HEAD requests returned HTTP {status_code}.",
                "recommendation": None
            })

        elif status_code == 405:

            findings.append({
                "check": "HEAD Method",
                "status": "Blocked",
                "severity": "Low",
                "description": "The server rejected the HEAD method.",
                "recommendation": "Verify whether disabling HEAD is intentional."
            })

        else:

            findings.append({
                "check": "HEAD Method",
                "status": "Restricted",
                "severity": "Low",
                "description": f"HEAD requests returned HTTP {status_code}.",
                "recommendation": None
            })

    # --------------------------------
    # Dangerous / Unnecessary Methods
    # --------------------------------

    potentially_risky_methods = {
        "PUT": "PUT can allow clients to upload or replace resources.",
        "DELETE": "DELETE can allow clients to remove resources.",
        "TRACE": "TRACE can expose request information and is generally unnecessary.",
        "CONNECT": "CONNECT can be used to establish a tunnel through an HTTP proxy."
    }

    for method, risk_description in potentially_risky_methods.items():

        result = next(
            (
                item for item in tested_methods
                if item.get("method") == method
            ),
            None
        )

        if not result:
            continue

        status_code = result.get("status_code")

        # Successful response
        if 200 <= status_code < 300:

            findings.append({
                "check": f"{method} Method",
                "status": "Allowed",
                "severity": "Medium",
                "description": (
                    f"The {method} method returned HTTP {status_code}. "
                    f"{risk_description}"
                ),
                "recommendation": (
                    f"Disable {method} if it is not required by the application."
                )
            })

        # Authorization required
        elif status_code in [401, 403]:

            findings.append({
                "check": f"{method} Method",
                "status": "Restricted",
                "severity": "Low",
                "description": (
                    f"The {method} method returned HTTP {status_code}, "
                    "indicating that access may be restricted."
                ),
                "recommendation": (
                    f"Verify that {method} is intentionally enabled "
                    "and properly protected."
                )
            })

        # Method explicitly rejected
        elif status_code == 405:

            findings.append({
                "check": f"{method} Method",
                "status": "Blocked",
                "severity": "Informational",
                "description": (
                    f"The server explicitly rejected the {method} method "
                    "with HTTP 405."
                ),
                "recommendation": None
            })

        # Other response
        else:

            findings.append({
                "check": f"{method} Method",
                "status": "Rejected",
                "severity": "Informational",
                "description": (
                    f"The {method} method returned HTTP {status_code}. "
                    "This does not confirm that the method is supported."
                ),
                "recommendation": None
            })

    # --------------------------------
    # OPTIONS
    # --------------------------------

    options_result = next(
        (
            item for item in tested_methods
            if item.get("method") == "OPTIONS"
        ),
        None
    )

    if options_result:

        status_code = options_result.get("status_code")

        if 200 <= status_code < 300:

            findings.append({
                "check": "OPTIONS Method",
                "status": "Allowed",
                "severity": "Informational",
                "description": (
                    f"The OPTIONS method returned HTTP {status_code}."
                ),
                "recommendation": None
            })

        elif status_code == 405:

            findings.append({
                "check": "OPTIONS Method",
                "status": "Blocked",
                "severity": "Informational",
                "description": (
                    "The server rejected the OPTIONS method."
                ),
                "recommendation": None
            })

        else:

            findings.append({
                "check": "OPTIONS Method",
                "status": "Restricted",
                "severity": "Informational",
                "description": (
                    f"The OPTIONS method returned HTTP {status_code}."
                ),
                "recommendation": None
            })

    # --------------------------------
    # Supported Methods Summary
    # --------------------------------

    if supported_methods:

        findings.append({
            "check": "Supported Methods",
            "status": "Detected",
            "severity": "Informational",
            "description": (
                f"The collector detected the following potentially "
                f"supported methods: {', '.join(supported_methods)}."
            ),
            "recommendation": (
                "Review enabled HTTP methods and disable unnecessary "
                "methods."
            )
        })

    # --------------------------------
    # Collection Errors
    # --------------------------------

    if errors:

        findings.append({
            "check": "Collection Errors",
            "status": "Error",
            "severity": "Informational",
            "description": (
                f"{len(errors)} error(s) occurred while collecting "
                "HTTP method information."
            ),
            "recommendation": "Review the collector errors and repeat the scan if necessary."
        })

    # --------------------------------
    # Final Result
    # --------------------------------

    return {
        "url": url,
        "findings": findings
    }

def get_http_method_data(url: str):

    collector = HTTPMethodsCollector("https://example.com")

    method_data = collector.collect()

    result = analyze_http_methods(method_data)

    return result