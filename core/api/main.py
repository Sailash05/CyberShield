from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, HttpUrl
from fastapi.middleware.cors import CORSMiddleware
import requests

import json
import re

from pathlib import Path
from collections import Counter

import requests

from bs4 import BeautifulSoup
from fastapi import HTTPException

from module.analysis.phishing_text_analysis import (
    analyze_webpage_html
)

from module.analysis import (
    dns_analysis,
    header_analysis,
    http_info_analysis,
    http_method_analysis,
    ssl_analysis,
    technology_analysis,
    url_analysis,
    whois_analysis
)

from module.risk.finding_aggregator import (
    aggregate_findings,
    summarize_findings
)

from module.risk.risk_engine import (
    generate_risk_report
)


app = FastAPI(
    title="Cyber Shield API",
    description="Intelligent Web Security Assessment Platform",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    url: HttpUrl


@app.get("/")
def root():
    return {
        "name": "Cyber Shield",
        "status": "running",
        "version": "1.0.0"
    }


@app.get("/health")
def health():
    return {
        "status": "healthy"
    }


@app.post("/api/scan")
def scan_website(request: ScanRequest):

    url = str(request.url)

    try:

        # -----------------------------
        # URL
        # -----------------------------

        url_result = url_analysis.get_url_data(url)

        # Extract hostname for domain-based collectors
        hostname = url_result.get("hostname")

        if not hostname:
            raise HTTPException(
                status_code=400,
                detail="Unable to determine hostname from URL."
            )

        # -----------------------------
        # Existing Analysis Modules
        # -----------------------------

        dns = dns_analysis.get_dns_data(hostname)

        header = header_analysis.get_header_data(url)

        http_info = http_info_analysis.get_http_info_data(url)

        http_method = http_method_analysis.get_http_method_data(url)

        ssl = ssl_analysis.get_ssl_data(hostname)

        tech = technology_analysis.get_tech_data(url)

        whois = whois_analysis.get_whois_data(hostname)

        # -----------------------------
        # STEP 3
        # Finding Aggregation
        # -----------------------------

        findings = aggregate_findings(
            dns,
            header,
            http_info,
            http_method,
            ssl,
            tech,
            url_result,
            whois
        )

        summary = summarize_findings(findings)

        # -----------------------------
        # STEP 4
        # Risk Scoring
        # -----------------------------

        risk = generate_risk_report(findings)

        # -----------------------------
        # Final API Response
        # -----------------------------

        return {
            "target": url,

            "risk": risk,

            "summary": summary,

            "findings": findings,

            "analysis": {
                "dns": dns,
                "headers": header,
                "http_info": http_info,
                "http_methods": http_method,
                "ssl": ssl,
                "technology": tech,
                "url": url_result,
                "whois": whois
            }
        }

    except HTTPException:
        raise

    except Exception as e:

        raise HTTPException(
            status_code=500,
            detail=str(e)
        )


KEYWORDS_FILE = (
    Path(__file__).resolve().parent.parent
    / "data"
    / "phishing_keywords.json"
)


def load_phishing_keywords():
    """Load the word dictionary from the JSON file."""

    try:
        with open(KEYWORDS_FILE, "r", encoding="utf-8") as file:
            keywords = json.load(file)

        if not isinstance(keywords, dict):
            raise ValueError(
                "The phishing keyword file must contain a JSON object."
            )

        for word, label in keywords.items():
            if not isinstance(word, str) or label not in (0, 1):
                raise ValueError(
                    "Each keyword must map to either 0 or 1."
                )

        return keywords

    except FileNotFoundError:
        raise HTTPException(
            status_code=500,
            detail="Phishing keyword dictionary was not found."
        )

    except json.JSONDecodeError:
        raise HTTPException(
            status_code=500,
            detail="Phishing keyword dictionary contains invalid JSON."
        )


def extract_visible_text(html):
    """Extract visible text from webpage HTML."""

    soup = BeautifulSoup(html, "html.parser")

    # Remove content that should not be analyzed as visible text
    for element in soup([
        "script",
        "style",
        "noscript",
        "template",
        "svg"
    ]):
        element.decompose()

    return soup.get_text(separator=" ", strip=True)


def analyze_webpage_keywords(html):
    """Classify webpage text using predefined keyword rules."""

    keywords = load_phishing_keywords()

    # Step 1: Extract visible webpage text
    text = extract_visible_text(html)

    # Step 2: Tokenize the text
    words = re.findall(r"\b[a-z0-9]+\b", text.lower())

    # Step 3: Count word occurrences
    word_counts = Counter(words)

    # Step 4: Match words against the JSON dictionary
    phishing_matches = {}
    legitimate_matches = {}

    for word, count in word_counts.items():
        if word not in keywords:
            continue

        if keywords[word] == 1:
            phishing_matches[word] = count
        else:
            legitimate_matches[word] = count

    # Step 5: Calculate matching word counts
    phishing_count = sum(phishing_matches.values())
    legitimate_count = sum(legitimate_matches.values())

    total_matches = phishing_count + legitimate_count

    # Step 6: Calculate the heuristic risk score
    if total_matches > 0:
        risk_score = round(
            phishing_count / total_matches * 100,
            2
        )
    else:
        risk_score = 0.0

    # Step 7: Binary classification
    if phishing_count > legitimate_count:
        classification = "Phishing"
    else:
        classification = "Legitimate"

    # Step 8: Return the result
    return {
        "classification": classification,
        "risk_score": risk_score,
        "phishing_matches": phishing_matches,
        "legitimate_matches": legitimate_matches,
        "phishing_word_count": phishing_count,
        "legitimate_word_count": legitimate_count,
        "matched_word_count": total_matches,
        "text_length": len(text),
        "message": "Classification based on predefined keyword matching."
    }

@app.post("/api/legitimacy-analysis")
def legitimacy_analysis(request: ScanRequest):

    url = str(request.url)

    try:
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=False,
            headers={"User-Agent": "CyberShield/1.0"},
            stream=True
        )

        try:
            # Step 1: Reject redirects
            if 300 <= response.status_code < 400:
                raise HTTPException(
                    status_code=400,
                    detail=(
                        "The website returned a redirect. "
                        "Submit the final destination URL."
                    )
                )

            # Step 2: Check HTTP response
            response.raise_for_status()

            # Step 3: Validate content type
            content_type = response.headers.get(
                "Content-Type", ""
            ).lower()

            if (
                "text/html" not in content_type
                and "application/xhtml+xml" not in content_type
            ):
                raise HTTPException(
                    status_code=415,
                    detail="The target URL does not return HTML content."
                )

            # Step 4: Read HTML with a 1 MB limit
            max_html_size = 1_000_000
            html_chunks = []
            total_size = 0

            for chunk in response.iter_content(chunk_size=8192):

                if not chunk:
                    continue

                total_size += len(chunk)

                if total_size > max_html_size:
                    raise HTTPException(
                        status_code=413,
                        detail="The webpage HTML exceeds the 1 MB limit."
                    )

                html_chunks.append(chunk)

            html = b"".join(html_chunks).decode(
                response.encoding or "utf-8",
                errors="replace"
            )

        finally:
            response.close()

        # Step 5: Run dictionary-based analysis
        result = analyze_webpage_keywords(html)

        # Step 6: Return analysis results
        return {
            "target": url,
            "analysis_type": "legitimacy_analysis",
            "method": "Dictionary-Based Keyword Analysis",
            "result": result
        }

    except HTTPException:
        raise

    except requests.Timeout:
        raise HTTPException(
            status_code=504,
            detail="The target website took too long to respond."
        )

    except requests.RequestException:
        raise HTTPException(
            status_code=502,
            detail="Unable to retrieve the target webpage."
        )

    except ValueError as e:
        raise HTTPException(
            status_code=422,
            detail=str(e)
        )

    except Exception:
        raise HTTPException(
            status_code=500,
            detail=(
                "An internal error occurred during legitimacy analysis."
            )
        )




# @app.post("/api/legitimacy-analysis")
# def legitimacy_analysis(request: ScanRequest):
#     url = str(request.url)

#     try:
#         response = requests.get(
#             url,
#             timeout=10,
#             allow_redirects=False,
#             headers={"User-Agent": "CyberShield/1.0"},
#             stream=True
#         )

#         try:
#             # Step 1: Reject redirects
#             if 300 <= response.status_code < 400:
#                 raise HTTPException(
#                     status_code=400,
#                     detail=(
#                         "The website returned a redirect. "
#                         "Submit the final destination URL."
#                     )
#                 )

#             # Step 2: Check HTTP response
#             response.raise_for_status()

#             # Step 3: Validate content type
#             content_type = response.headers.get(
#                 "Content-Type", ""
#             ).lower()

#             if (
#                 "text/html" not in content_type
#                 and "application/xhtml+xml" not in content_type
#             ):
#                 raise HTTPException(
#                     status_code=415,
#                     detail="The target URL does not return HTML content."
#                 )

#             # Step 4: Read HTML with a 1 MB limit
#             max_html_size = 1_000_000
#             html_chunks = []
#             total_size = 0

#             for chunk in response.iter_content(chunk_size=8192):
#                 if not chunk:
#                     continue

#                 total_size += len(chunk)

#                 if total_size > max_html_size:
#                     raise HTTPException(
#                         status_code=413,
#                         detail="The webpage HTML exceeds the 1 MB limit."
#                     )

#                 html_chunks.append(chunk)

#             html = b"".join(html_chunks).decode(
#                 response.encoding or "utf-8",
#                 errors="replace"
#             )

#         finally:
#             response.close()

#         # Step 5: Run the ML text analysis
#         result = analyze_webpage_html(html)

#         # Step 6: Apply the 90% threshold
#         phishing_score = result["phishing_probability"]

#         if phishing_score > 90:
#             classification = "Phishing"
#         else:
#             classification = "Legitimate"

#         # Step 7: Keep the final prediction consistent with the threshold.
#         # Preserve the model's original prediction separately for transparency.
#         model_prediction = result["prediction"]

#         result["model_prediction"] = model_prediction
#         result["prediction"] = classification
#         result["classification"] = classification
#         result["threshold"] = 90.0

#         # Step 8: Return the response
#         return {
#             "target": url,
#             "analysis_type": "legitimacy_analysis",
#             "result": result
#         }

#     except HTTPException:
#         raise

#     except requests.Timeout:
#         raise HTTPException(
#             status_code=504,
#             detail="The target website took too long to respond."
#         )

#     except requests.RequestException:
#         raise HTTPException(
#             status_code=502,
#             detail="Unable to retrieve the target webpage."
#         )

#     except ValueError as e:
#         raise HTTPException(
#             status_code=422,
#             detail=str(e)
#         )

#     except Exception:
#         raise HTTPException(
#             status_code=500,
#             detail="An internal error occurred during legitimacy analysis."
#         )



    