# Privacy Policy for Nexus

**Effective Date:** March 17, 2026

## Introduction
Nexus ("we", "our", or "the extension") is a browser extension developed by IntelSecLab. We are committed to protecting your privacy. This Privacy Policy explains how our extension handles your data.

## Data Collection
**Nexus does NOT collect, store, or transmit any personal data.**

- **No Remote Servers:** The extension runs entirely within your browser environment. No data is sent to external servers or third parties.
- **Local Processing:** All scanning, analysis, and finding generation happens locally on your device using JavaScript.
- **Temporary Storage:** Findings are stored temporarily in your browser's local storage (`chrome.storage.session`) solely for the purpose of displaying results to you. This data is cleared when you close the tab or browser, or when you explicitly clear it.

## Permissions Usage
Nexus requires specific browser permissions to function. Here is how they are used:

- **activeTab & scripting:** Used to inject a passive scanner into the current page to detect client-side vulnerabilities (e.g., exposed API keys in DOM). This only happens on pages you visit.
- **webRequest:** Used to analyze HTTP response headers for security misconfigurations (e.g., missing security headers).
- **storage:** Used to save your settings and temporary findings locally.
- **Host Permissions (`<all_urls>`):** Required to allow the extension to run on any website you choose to audit.

## Third-Party Services
The extension does not integrate with any third-party analytics, tracking, or advertising services.

## Changes to This Policy
We may update our Privacy Policy from time to time. We will notify you of any changes by posting the new Privacy Policy on this page.

## Contact Us
If you have any questions about this Privacy Policy, please contact us at:
- GitHub: [https://github.com/intelseclab/nexus](https://github.com/intelseclab/nexus)
