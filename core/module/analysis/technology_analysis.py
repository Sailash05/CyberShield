from module.collector.tech_collector import TechnologyCollector


def analyze_technology(technology_data):
    findings = []

    if "error" in technology_data:
        findings.append({
            "title": "Technology Detection Failed",
            "severity": "Medium",
            "status": "Error",
            "description": technology_data["error"]
        })
        return {
            "url": technology_data.get("url"),
            "findings": findings
        }

    # Server disclosure
    server = technology_data.get("server")

    if server:
        findings.append({
            "title": "Server Information Disclosure",
            "severity": "Low",
            "status": "Detected",
            "description": f"Server information is exposed through the HTTP response: {server}."
        })
    else:
        findings.append({
            "title": "Server Information Disclosure",
            "severity": "Informational",
            "status": "Not Detected",
            "description": "No Server header was detected."
        })

    # X-Powered-By disclosure
    powered_by = technology_data.get("powered_by")

    if powered_by:
        findings.append({
            "title": "Technology Information Disclosure",
            "severity": "Low",
            "status": "Detected",
            "description": f"X-Powered-By header exposes technology information: {powered_by}."
        })
    else:
        findings.append({
            "title": "X-Powered-By Disclosure",
            "severity": "Informational",
            "status": "Not Detected",
            "description": "No X-Powered-By header was detected."
        })

    # Generator disclosure
    generator = technology_data.get("generator")

    if generator:
        findings.append({
            "title": "Generator Information Disclosure",
            "severity": "Low",
            "status": "Detected",
            "description": f"HTML generator information is exposed: {generator}."
        })
    else:
        findings.append({
            "title": "Generator Disclosure",
            "severity": "Informational",
            "status": "Not Detected",
            "description": "No generator meta tag was detected."
        })

    # Framework
    framework = technology_data.get("framework")

    if framework:
        findings.append({
            "title": "Framework Detected",
            "severity": "Informational",
            "status": "Detected",
            "description": f"The website appears to use the {framework} framework."
        })
    else:
        findings.append({
            "title": "Framework Detection",
            "severity": "Informational",
            "status": "Not Detected",
            "description": "No supported web framework was identified."
        })

    # Programming language
    language = technology_data.get("language")

    if language:
        findings.append({
            "title": "Programming Language Detected",
            "severity": "Informational",
            "status": "Detected",
            "description": f"The website appears to use {language}."
        })

    # CDN
    cdn = technology_data.get("cdn")

    if cdn:
        findings.append({
            "title": "CDN Detected",
            "severity": "Informational",
            "status": "Detected",
            "description": f"The website appears to use {cdn} as a CDN."
        })

    return {
        "url": technology_data.get("url"),
        "technologies": technology_data.get("technologies", {}),
        "findings": findings
    }


def get_tech_data(url: str):

    collector = TechnologyCollector(url)
    data = collector.collect()

    result = analyze_technology(data)

    return result