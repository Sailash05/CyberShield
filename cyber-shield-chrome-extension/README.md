# Cyber Shield Chrome Extension (Manifest V3)

## What it does
- Watches top-level HTTP/HTTPS navigations.
- Sends the destination URL to `POST http://127.0.0.1:8000/api/legitimacy-analysis`.
- Opens a local extension checking page.
- Automatically opens destinations below the configured threshold.
- Shows a warning with **Go Back** and **Continue Anyway** for URLs flagged as phishing.
- If the API is unavailable, it does not automatically open the destination and asks the user to retry or explicitly continue.

## Install for local development
1. Start your Cyber Shield FastAPI backend on `127.0.0.1:8000`.
2. Open `chrome://extensions` in Chrome.
3. Enable **Developer mode**.
4. Click **Load unpacked**.
5. Select this extension folder.
6. Test with a URL in a new tab.

## Important limitations
This is a development prototype. Chrome's `webNavigation.onBeforeNavigate` event is not a synchronous blocking API. The extension redirects the tab to its local checker page when navigation is observed, but it cannot guarantee that the original request never starts. Do not present this prototype as a hard security boundary.

The configured backend threshold flags a URL only when the phishing probability is greater than 90%. A lower score is not proof that a website is safe. A production version should use a calibrated model, additional reputation/signature checks, robust SSRF protections on the backend, and security testing.

## Backend/API
The extension expects a JSON response shaped like:
{
  "target": "https://example.com/",
  "analysis_type": "legitimacy_analysis",
  "result": {
    "prediction": "Legitimate",
    "model_prediction": "Phish",
    "phishing_probability": 55.29,
    "classification": "Legitimate",
    "threshold": 90.0
  }
}

If your backend is on another host/port, update `API_URL` in `background.js` and `checker.js`, then adjust `host_permissions` in `manifest.json`.
