const API_URL = "http://127.0.0.1:8000/api/legitimacy-analysis";

const params = new URLSearchParams(window.location.search);
const targetUrl = params.get("url");

const heading = document.getElementById("heading");
const message = document.getElementById("message");
const target = document.getElementById("target");
const status = document.getElementById("status");
const actions = document.getElementById("actions");
const backButton = document.getElementById("backButton");
const continueButton = document.getElementById("continueButton");
const retryButton = document.getElementById("retryButton");
const scoreBox = document.getElementById("scoreBox");
const score = document.getElementById("score");

target.textContent = targetUrl || "No URL provided";

// Validate HTTP and HTTPS URLs.
function isWebUrl(url) {
  try {
    const parsed = new URL(url);

    return (
      parsed.protocol === "http:" ||
      parsed.protocol === "https:"
    );
  } catch {
    return false;
  }
}

// Display a warning with a Continue Anyway button.
function showWarning(title, text, statusText) {
  heading.textContent = title;
  message.textContent = text;
  status.textContent = statusText;

  actions.hidden = false;
  retryButton.hidden = true;

  continueButton.hidden = false;
  continueButton.disabled = false;
  backButton.disabled = false;
}

// Display an error with Retry and Go Back options.
function showError(text) {
  heading.textContent = "Unable to verify this website";
  message.textContent = text;

  status.textContent =
    "The website was not automatically opened. You can retry or go back.";

  actions.hidden = false;
  retryButton.hidden = false;
  scoreBox.hidden = true;

  continueButton.hidden = true;
  continueButton.disabled = false;
  backButton.disabled = false;
}

// Open the destination through the background service worker.
async function openTarget() {
  if (!targetUrl || !isWebUrl(targetUrl)) {
    showError("The destination URL is missing or invalid.");
    return;
  }

  continueButton.disabled = true;
  backButton.disabled = true;

  try {
    const response = await chrome.runtime.sendMessage({
      type: "CYBER_SHIELD_ALLOW_AND_OPEN",
      url: targetUrl,
    });

    if (!response?.ok) {
      throw new Error(
        response?.error || "Could not open the destination URL."
      );
    }
  } catch (error) {
    status.textContent = `Could not continue: ${error.message}`;

    continueButton.disabled = false;
    backButton.disabled = false;
  }
}

// Close the checker tab when Go Back is clicked.
backButton.addEventListener("click", async () => {
  try {
    const tab = await chrome.tabs.getCurrent();

    if (tab?.id !== undefined) {
      await chrome.tabs.remove(tab.id);
      return;
    }
  } catch (error) {
    console.error("Could not close checker tab:", error);
  }

  if (history.length > 1) {
    history.back();
  } else {
    window.close();
  }
});

continueButton.addEventListener("click", openTarget);
retryButton.addEventListener("click", runCheck);

// Call the Cyber Shield API and process its response.
async function runCheck() {
  actions.hidden = true;
  retryButton.hidden = true;
  scoreBox.hidden = true;

  continueButton.hidden = false;
  continueButton.disabled = false;
  backButton.disabled = false;

  heading.textContent = "Checking this website…";

  message.textContent =
    "Cyber Shield is analyzing the webpage using predefined keyword rules.";

  status.textContent = "Contacting Cyber Shield API…";

  if (!targetUrl || !isWebUrl(targetUrl)) {
    showError("The destination URL is missing or invalid.");
    return;
  }

  try {
    // Request the updated dictionary-based analysis.
    const response = await fetch(API_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        url: targetUrl,
      }),
    });

    let data;

    try {
      data = await response.json();
      console.log("Cyber Shield API response:", data);
    } catch {
      throw new Error("The API returned an unreadable response.");
    }

    if (!response.ok) {
      throw new Error(
        typeof data.detail === "string"
          ? data.detail
          : `The API returned HTTP ${response.status}.`
      );
    }

    // Extract the result returned by FastAPI.
    const result = data.result || {};

    const classification = result.classification;
    const riskScore = Number(result.risk_score);
    const phishingCount = Number(result.phishing_word_count);
    const legitimateCount = Number(result.legitimate_word_count);
    const matchedCount = Number(result.matched_word_count);

    const phishingMatches =
      result.phishing_matches &&
      typeof result.phishing_matches === "object"
        ? result.phishing_matches
        : {};

    const legitimateMatches =
      result.legitimate_matches &&
      typeof result.legitimate_matches === "object"
        ? result.legitimate_matches
        : {};

    // Validate the fields required by the extension.
    if (
      !["Phishing", "Legitimate"].includes(classification) ||
      !Number.isFinite(riskScore) ||
      !Number.isFinite(phishingCount) ||
      !Number.isFinite(legitimateCount) ||
      !Number.isFinite(matchedCount)
    ) {
      throw new Error(
        "The API response is missing valid classification data."
      );
    }

    // Display the dictionary-based heuristic score.
    scoreBox.hidden = false;
    score.textContent = `${riskScore.toFixed(2)}%`;

    // Prepare matched keyword summaries.
    const phishingWords = Object.keys(phishingMatches);
    const legitimateWords = Object.keys(legitimateMatches);

    const phishingSummary =
      phishingWords.length > 0
        ? `Phishing indicators: ${phishingWords.join(", ")}.`
        : "No predefined phishing keywords were matched.";

    const legitimateSummary =
      legitimateWords.length > 0
        ? `Other matched keywords: ${legitimateWords.join(", ")}.`
        : "No predefined non-phishing keywords were matched.";

    // =====================================================
    // CASE 1: API CLASSIFICATION IS PHISHING
    // =====================================================
    if (classification === "Phishing") {
      showWarning(
        "⚠ Potentially malicious website",
        `Cyber Shield classified this destination as potential phishing. ${phishingSummary} ${legitimateSummary}`,
        `Keyword risk score: ${riskScore.toFixed(2)}%. Review the destination carefully before deciding.`
      );

      return;
    }

    // =====================================================
    // CASE 2: API CLASSIFICATION IS LEGITIMATE
    // =====================================================
    // Follow the API classification exactly, even when
    // matched_word_count is zero.
    if (classification === "Legitimate") {
      heading.textContent = "Legitimate Website";

      message.textContent =
        "Cyber Shield classified this website as Legitimate based on its predefined keyword rules.";

      status.textContent =
        `Keyword risk score: ${riskScore.toFixed(2)}%. ` +
        `Phishing matches: ${phishingCount}; ` +
        `other matches: ${legitimateCount}; ` +
        `total matched keywords: ${matchedCount}.`;

      actions.hidden = true;
      retryButton.hidden = true;

      // Automatically open the website after displaying the result.
      setTimeout(() => {
        openTarget();
      }, 650);

      return;
    }
  } catch (error) {
    console.error("Cyber Shield analysis error:", error);

    showError(
      `${error.message} Check that the Cyber Shield FastAPI backend is running and accessible.`
    );
  }
}

// Start the analysis when checker.html loads.
runCheck();