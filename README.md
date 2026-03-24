# Nexus Scanner

**Nexus** is a Chrome Manifest V3 extension designed for **passive web security reconnaissance**. Built for pentesters and bug bounty hunters, it automatically detects exposed API keys, sensitive tokens, configuration files, technology stacks, and security misconfigurations as you browse.

![Nexus Demo](demo.png)

## Features

- **Passive Scanning**: Detects 70+ sensitive patterns (AWS, Google, Stripe, Slack, etc.) without sending malicious payloads.
- **Technology Fingerprinting**: Identifies frameworks (React, Next.js, Vue), CMSs, and analytics tools.
- **Path Probing**: Checks for sensitive paths like `.env`, `.git/config`, `sitemap.xml`, and admin panels.
- **Secure Architecture**: Runs entirely in the browser. No data is sent to external servers.
- **Professional Reporting**: Exports findings to JSON or a standalone HTML report suitable for pentest deliverables.

## Installation

### From Source
1. Clone this repository:
   ```bash
   git clone https://github.com/intelseclab/nexus.git
   ```
2. Open Chrome and navigate to `chrome://extensions/`.
3. Enable **Developer mode** (top right).
4. Click **Load unpacked** and select the extension directory.

## Usage
1. Browse target websites normally.
2. The Nexus icon badge will show the count of findings.
3. Click the extension icon to view detailed findings, site technology profile, and export options.

## Development

This project uses vanilla JavaScript (no build step required).

- `manifest.json`: Configuration and permissions.
- `background.js`: Service worker for header analysis and state management.
- `content.js`: DOM scanner and page analysis.
- `scanner/`: Core detection logic and patterns.
- `popup/`: UI implementation.


## LEGAL NOTICE:
Nexus performs active reconnaissance including HTTP requests to sensitive paths on target websites. On first use, a legal disclaimer requires you to acknowledge that you will only scan targets you are authorized to test. Unauthorized scanning may violate applicable laws (CFAA, Computer Misuse Act, etc.) and terms of service. You are solely responsible for your use of this tool.

## Privacy Policy

Nexus does **NOT** collect or transmit any user data. All scanning is performed locally within your browser.
For more details, see our [Privacy Policy](PRIVACY.md).

## License

MIT
