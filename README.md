# BrandShield AI

**A simulated digital risk protection platform demo for social and mobile-app threats.**

BrandShield AI demonstrates how an analyst could triage suspected fake profiles, impersonation, scam accounts, and suspicious mobile apps. It includes a local detection queue, Google Play and Apple App Store listing support, sample detections, explainable rules, relationship mapping, and auditable reports.

> **Prototype boundary:** The dashboard uses fictional sample records and does not connect to social-network or app-store feeds, run continuous monitoring, or use a trained AI model. Triage is performed by transparent local heuristics; scores are not proof of fraud or verified detections. Optional Google Safe Browsing reputation checks run only after an analyst explicitly clicks the check button; the submitted URL is sent to Google. A Website case is fetched only after clicking **Check website now**. App-store listings are not queried.

## Run locally

Requires Python 3.10+ and Flask 3.x.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

Open [http://127.0.0.1:5000](http://127.0.0.1:5000). The app initializes its SQLite database and sample cases on first run. Keep the Flask terminal open while using the app.

## Optional Google Safe Browsing lookup

To enable the real-world URL reputation lookup, create a Google Cloud API key, enable the **Safe Browsing API** for its project, and keep the key server-side. In the same PowerShell window used to start Flask, set the key and then run the app:

```powershell
$env:GOOGLE_SAFE_BROWSING_API_KEY = "YOUR_GOOGLE_API_KEY"
python app.py
```

Restart Flask after changing the key. Without it, the case-details page shows that reputation lookup is not configured and disables the check button. Never put this key in frontend JavaScript, HTML, a committed file, or a public repository.

Open a case and explicitly click **Check with Google Safe Browsing** to query the URL against Google’s malware and social-engineering threat lists. That action sends the full case URL to Google. A match means Google returned a known threat-list category; no match means only that neither queried list returned a match at that time—it is not proof the URL is safe. The lookup does not alter the demo score, save results to SQLite, or run automatically. API availability and quota depend on the Google Cloud project and key. See [Google’s Lookup API documentation](https://developers.google.com/safe-browsing/v4/lookup-api).

## Demo sign-in

The local prototype has one shared demo account:

- **Username:** `analyst`
- **Password:** `shield-demo`

For a presentation, set `BRANDSHIELD_DEMO_USERNAME` and `BRANDSHIELD_DEMO_PASSWORD` before starting the server to use different shared demo credentials. Set `BRANDSHIELD_SECRET_KEY` to a long, random value if sessions should remain valid across server restarts. The app generates a temporary signing key automatically when it is not set.

This is a hackathon demo gate, not production authentication: it has no individual accounts, password recovery, or real user isolation. Do not expose it to the public internet or enter sensitive information.

## Judge walkthrough

Use **Guided demo** on the dashboard for a built-in four-step tour, or follow this path:

1. **Dashboard:** Review seeded sample detections across social profiles and mobile-app listings. Select a detection to see its evidence and contributing rules. The open/high-risk/related metric cards filter the corresponding cases; the reports card opens report history.
2. **Threat detections:** Search and filter records, add a social profile or a Google Play / Apple App Store listing, inspect a record, and update its analyst review status.
3. **Threat Graph:** Inspect links created only by exact, explicitly entered shared indicators; similar domains alone are not linked.
4. **Reports:** Generate and download a case summary, then revisit it from the saved report history.
5. **Settings:** Export a JSON backup or restore the fictional sample workspace for another demo.

For a one-time availability check, add or open a case whose platform is **Website**, open its details, and click **Check website now**. The app reports the HTTP response, check time, and (when available) page title. It does not crawl the site, store its page content, change the risk score, or decide whether the site is legitimate. Checks reject non-public hosts and non-standard ports.

## What it demonstrates

- Threat intake and status management for social profiles, websites, Google Play listings, and Apple App Store listings, backed by local SQLite storage.
- Dashboard metrics, risk/platform charts, and exact-indicator relationship links served by the authenticated Flask analytics endpoint from SQLite-backed case data.
- Explainable local heuristic scoring for brand/domain mismatch, suspicious language, impersonation or unofficial-app cues, shared indicators, and HTTP links, with visible reasons and human-review guidance.
- Fictional sample detections for scam/impersonation profiles and suspicious Android/iOS app listings.
- Conservative relationship mapping based on exact shared indicators.
- Locally generated reports with a persistent history.
- JSON import/export, responsive layouts, keyboard-accessible controls, and clear prototype limitations.

### Demo scoring rules

| Signal | Points |
| --- | ---: |
| Known shortened or redirect-style host | +25 |
| Brand name absent from the asset domain, profile handle, or app listing identifier | +20 |
| Scam, phishing, urgency, prize, credential, or payment wording in notes | +20 |
| Fake, cloned, counterfeit, unofficial, or impersonating wording | +20 for profiles; +25 for app listings |
| Explicit indicator shared with another case | +10 |
| Unencrypted HTTP URL | +10 |

Scores are capped at 100; 0 to 39 is low, 40 to 69 medium, and 70 to 100 high. A baseline score is used when no listed signals are detected. These intentionally simple heuristics are not machine-learning or AI-model output. They demonstrate explainable triage, not real-time monitoring, enforcement, or safety decisions.

## Implementation

- **Frontend:** semantic HTML, CSS, and vanilla JavaScript.
- **Backend:** Flask JSON API.
- **Persistence:** SQLite database at `brandshield.sqlite3` in the project directory.
- **Dependencies:** Flask only; see `requirements.txt`.

Submitted records and reports remain in the local database. The two external checks—the one-time Website availability request and optional Google Safe Browsing lookup—are analyst-triggered only. Reputation results are kept in browser memory for the current page session and are not included in saved reports. No automatic polling or social-platform monitoring is performed.

## Coverage against the project brief

| Brief item | Demo status |
| --- | --- |
| Fake profiles, impersonation, and scam accounts | Represented with fictional sample records and local keyword/domain heuristics. |
| Suspicious mobile apps | Google Play and Apple App Store listing URLs can be recorded and triaged with app-specific heuristic cues. |
| Social and app monitoring | Seeded sample cases only; no platform feeds, crawling, or scheduled monitoring are connected. |
| AI-powered detection | Not implemented as a trained or hosted AI model. The current scoring is deterministic and explainable. |

To move beyond the demo and implement live monitoring or model-based classification, the project needs authorized platform/app-store data providers and a selected AI inference service, along with their API documentation, credentials, privacy requirements, and operating budget. This prototype intentionally does not fabricate those integrations.
