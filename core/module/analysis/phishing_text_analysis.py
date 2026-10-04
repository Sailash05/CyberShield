from pathlib import Path

import joblib
from bs4 import BeautifulSoup, Comment


# --------------------------------------------------
# Model configuration
# --------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[3]

MODEL_PATH = (
    PROJECT_ROOT
    / "training"
    / "models"
    / "phishing_text_model.joblib"
)

MAX_CONTENT_LENGTH = 1_000_000


# --------------------------------------------------
# Load the trained model once
# --------------------------------------------------

if not MODEL_PATH.is_file():
    raise FileNotFoundError(
        f"Trained phishing model not found: {MODEL_PATH}"
    )

model = joblib.load(MODEL_PATH)


# --------------------------------------------------
# Extract visible text from HTML
# --------------------------------------------------

def extract_visible_text(html: str) -> str:
    """
    Extract readable text from webpage HTML.

    Removes scripts, styles, comments, and elements
    that are generally unsuitable for visible-text analysis.
    """

    if not isinstance(html, str):
        raise ValueError("HTML content must be a string.")

    if len(html) > MAX_CONTENT_LENGTH:
        raise ValueError("HTML content exceeds the size limit.")

    soup = BeautifulSoup(html, "lxml")

    excluded_tags = [
        "script",
        "style",
        "noscript",
        "template",
        "svg",
        "canvas",
        "iframe",
    ]

    for tag in soup.find_all(excluded_tags):
        tag.decompose()

    for comment in soup.find_all(
        string=lambda text: isinstance(text, Comment)
    ):
        comment.extract()

    text = soup.get_text(separator=" ", strip=True)

    return " ".join(text.split())


# --------------------------------------------------
# Analyze webpage text
# --------------------------------------------------

def analyze_webpage_text(text: str) -> dict:
    """
    Classify extracted webpage text using the trained model.

    Label mapping:
        0 = NotPhish
        1 = Phish
    """

    if not isinstance(text, str):
        raise ValueError("Webpage text must be a string.")

    text = " ".join(text.split())

    if not text:
        raise ValueError("No readable webpage text was provided.")

    if len(text) > MAX_CONTENT_LENGTH:
        raise ValueError("Webpage text exceeds the size limit.")

    prediction = int(model.predict([text])[0])

    probabilities = model.predict_proba([text])[0]
    classes = list(model.named_steps["classifier"].classes_)

    phishing_index = classes.index(1)

    phishing_probability = float(
        probabilities[phishing_index]
    )

    return {
        "prediction": (
            "Phish" if prediction == 1 else "NotPhish"
        ),
        "phishing_probability": round(
            phishing_probability * 100, 2
        ),
        "model": "TF-IDF + Logistic Regression",
        "model_version": "1.0.0",
        "disclaimer": (
            "This prediction is based on webpage text and "
            "does not prove that a website is safe or malicious."
        ),
    }


# --------------------------------------------------
# Analyze HTML directly
# --------------------------------------------------

def analyze_webpage_html(html: str) -> dict:
    """
    Extract visible text from HTML and classify it.
    """

    text = extract_visible_text(html)

    if not text:
        raise ValueError(
            "No readable text could be extracted from the HTML."
        )

    result = analyze_webpage_text(text)

    result["text_length"] = len(text)

    return result
