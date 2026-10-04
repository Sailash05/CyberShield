from module.collector.http_info_collection import HTTPInfoCollector


def analyze_http_info(http_data):

    findings = []

    url = http_data.get("url")
    scheme = http_data.get("scheme")
    status_code = http_data.get("status_code")
    http_version = http_data.get("http_version")
    redirect_count = http_data.get("redirect_count", 0)
    redirect_history = http_data.get("redirect_history", [])
    redirected = http_data.get("redirected", False)
    response_time = http_data.get("response_time_ms")
    cookies = http_data.get("cookies", [])

    # --------------------------------
    # HTTPS
    # --------------------------------

    if scheme == "https":

        findings.append({
            "check": "HTTPS",
            "status": "Secure",
            "severity": "Informational",
            "description": "The website is accessed over HTTPS.",
            "recommendation": None
        })

    else:

        findings.append({
            "check": "HTTPS",
            "status": "Insecure",
            "severity": "High",
            "description": "The website is accessed over HTTP instead of HTTPS.",
            "recommendation": "Configure HTTPS and redirect HTTP requests to HTTPS."
        })

    # --------------------------------
    # HTTP to HTTPS Redirect
    # --------------------------------

    if redirected:

        https_redirect = any(
            history.get("status_code") in [301, 302, 307, 308]
            and history.get("url", "").startswith("http://")
            for history in redirect_history
        )

        if https_redirect:

            findings.append({
                "check": "HTTP to HTTPS Redirect",
                "status": "Configured",
                "severity": "Informational",
                "description": "HTTP requests are redirected to HTTPS.",
                "recommendation": None
            })

        else:

            findings.append({
                "check": "HTTP Redirect",
                "status": "Configured",
                "severity": "Informational",
                "description": "The website uses HTTP redirection.",
                "recommendation": None
            })

    else:

        if scheme == "https":

            findings.append({
                "check": "HTTP to HTTPS Redirect",
                "status": "Not Detected",
                "severity": "Low",
                "description": "No HTTP-to-HTTPS redirect was observed during the request.",
                "recommendation": "Verify that HTTP requests are redirected to HTTPS."
            })

    # --------------------------------
    # HTTP Status Code
    # --------------------------------

    if status_code is None:

        findings.append({
            "check": "HTTP Status",
            "status": "Unknown",
            "severity": "Medium",
            "description": "The HTTP response status code could not be determined.",
            "recommendation": "Verify that the website is reachable and returning a valid HTTP response."
        })

    elif 200 <= status_code < 300:

        findings.append({
            "check": "HTTP Status",
            "status": "Success",
            "severity": "Informational",
            "description": f"The server returned HTTP status code {status_code}.",
            "recommendation": None
        })

    elif 300 <= status_code < 400:

        findings.append({
            "check": "HTTP Status",
            "status": "Redirect",
            "severity": "Informational",
            "description": f"The server returned HTTP redirect status code {status_code}.",
            "recommendation": None
        })

    elif 400 <= status_code < 500:

        findings.append({
            "check": "HTTP Status",
            "status": "Client Error",
            "severity": "Medium",
            "description": f"The server returned HTTP client error status code {status_code}.",
            "recommendation": "Verify that the requested resource and access controls are correctly configured."
        })

    elif 500 <= status_code < 600:

        findings.append({
            "check": "HTTP Status",
            "status": "Server Error",
            "severity": "High",
            "description": f"The server returned HTTP server error status code {status_code}.",
            "recommendation": "Investigate the server-side error and verify application availability."
        })

    # --------------------------------
    # HTTP Version
    # --------------------------------

    if http_version == 10:

        findings.append({
            "check": "HTTP Version",
            "status": "Outdated",
            "severity": "Low",
            "description": "The server responded using HTTP/1.0.",
            "recommendation": "Consider supporting HTTP/1.1 or newer HTTP versions."
        })

    elif http_version == 11:

        findings.append({
            "check": "HTTP Version",
            "status": "Supported",
            "severity": "Informational",
            "description": "The server responded using HTTP/1.1.",
            "recommendation": None
        })

    elif http_version == 2:

        findings.append({
            "check": "HTTP Version",
            "status": "Modern",
            "severity": "Informational",
            "description": "The server responded using HTTP/2.",
            "recommendation": None
        })

    elif http_version == 3:

        findings.append({
            "check": "HTTP Version",
            "status": "Modern",
            "severity": "Informational",
            "description": "The server responded using HTTP/3.",
            "recommendation": None
        })

    else:

        findings.append({
            "check": "HTTP Version",
            "status": "Unknown",
            "severity": "Low",
            "description": f"The detected HTTP version is {http_version}.",
            "recommendation": "Verify the supported HTTP protocol versions."
        })

    # --------------------------------
    # Redirect Count
    # --------------------------------

    if redirect_count == 0:

        findings.append({
            "check": "Redirect Count",
            "status": "None",
            "severity": "Informational",
            "description": "No redirects were observed.",
            "recommendation": None
        })

    elif redirect_count <= 2:

        findings.append({
            "check": "Redirect Count",
            "status": "Normal",
            "severity": "Informational",
            "description": f"The request used {redirect_count} redirect(s).",
            "recommendation": None
        })

    elif redirect_count <= 5:

        findings.append({
            "check": "Redirect Count",
            "status": "Multiple",
            "severity": "Low",
            "description": f"The request used {redirect_count} redirects.",
            "recommendation": "Review the redirect chain and remove unnecessary redirects."
        })

    else:

        findings.append({
            "check": "Redirect Count",
            "status": "Excessive",
            "severity": "Medium",
            "description": f"The request used {redirect_count} redirects.",
            "recommendation": "Reduce unnecessary redirects and verify that the redirect chain does not create loops."
        })

    # --------------------------------
    # Response Time
    # --------------------------------

    if response_time is not None:

        if response_time <= 1000:

            findings.append({
                "check": "Response Time",
                "status": "Normal",
                "severity": "Informational",
                "description": f"The server responded in {response_time:.2f} ms.",
                "recommendation": None
            })

        elif response_time <= 3000:

            findings.append({
                "check": "Response Time",
                "status": "Slow",
                "severity": "Low",
                "description": f"The server responded in {response_time:.2f} ms.",
                "recommendation": "Review server and network performance if slow responses are persistent."
            })

        else:

            findings.append({
                "check": "Response Time",
                "status": "Very Slow",
                "severity": "Medium",
                "description": f"The server responded in {response_time:.2f} ms.",
                "recommendation": "Investigate server, application, database, and network performance."
            })

    # --------------------------------
    # Cookies
    # --------------------------------

    if cookies:

        findings.append({
            "check": "Cookies",
            "status": "Present",
            "severity": "Informational",
            "description": f"The server returned {len(cookies)} cookie(s).",
            "recommendation": "Cookie security attributes should be validated separately, including Secure, HttpOnly, and SameSite."
        })

    else:

        findings.append({
            "check": "Cookies",
            "status": "None Detected",
            "severity": "Informational",
            "description": "No cookies were returned in the response.",
            "recommendation": None
        })

    # --------------------------------
    # Final Result
    # --------------------------------

    return {
        "url": url,
        "findings": findings
    }


def get_http_info_data(url: str):

    collector = HTTPInfoCollector(url)

    http_data = collector.collect()

    result = analyze_http_info(http_data)

    return result