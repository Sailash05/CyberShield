from module.analysis import dns_analysis, header_analysis, http_info_analysis, http_method_analysis, ssl_analysis, technology_analysis, url_analysis, whois_analysis

from module.risk.finding_aggregator import (
    aggregate_findings,
    summarize_findings
)

from module.risk.risk_engine import (
    generate_risk_report
)

if __name__ == '__main__':

    from pprint import pprint

    dns = dns_analysis.get_dns_data("example.com")
    header = header_analysis.get_header_data("https://example.com")
    http_info = http_info_analysis.get_http_info_data("https://www.angelcab.in/")
    http_method = http_method_analysis.get_http_method_data("https://example.com")
    ssl = ssl_analysis.get_ssl_data("example.com")
    tech = technology_analysis.get_tech_data("https://example.com")
    url = url_analysis.get_url_data("https://example.com/login?id=10")
    whois = whois_analysis.get_whois_data("example.com")

    findings = aggregate_findings(
        dns,
        header,
        http_info,
        http_method,
        ssl,
        tech,
        url,
        whois
    )

    summary = summarize_findings(findings)

    risk = generate_risk_report(findings)  # out of 100

    pprint(findings)
    pprint(summary)
    pprint(risk)