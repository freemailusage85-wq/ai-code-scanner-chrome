# AI Code Security Scanner — Chrome Extension

> Scan any GitHub repository for security vulnerabilities directly from your browser.

## Features

- **One-click scanning** — Click the scan button on any GitHub repo page
- **Secret detection** — Finds hardcoded API keys, tokens, passwords (AWS, OpenAI, GitHub, Stripe, etc.)
- **Vulnerability scanning** — SQL injection, command injection, unsafe eval/pickle
- **Code quality** — AI slop detection, oversized files, missing error handling
- **Visual results** — Severity-rated findings with file locations and fix suggestions
- **No API key needed** — Works with public repos via GitHub API

## Installation

1. Download this folder
2. Open `chrome://extensions` in Chrome
3. Enable "Developer mode" (top right)
4. Click "Load unpacked" and select this folder
5. The extension icon appears in your toolbar

## How to Use

1. Navigate to any GitHub repository (e.g., `github.com/user/repo`)
2. Click the **AI Code Scanner** icon in your toolbar
3. Click **"Scan Repository"**
4. Wait 5-30 seconds (depends on repo size)
5. Review findings grouped by severity

## Findings Categories

| Severity | What It Catches |
|---|---|
| 🔴 CRITICAL | Hardcoded private keys, API tokens, passwords |
| 🟠 HIGH | SQL injection, command injection, unsafe eval/pickle |
| 🟡 MEDIUM | Hardcoded credentials, debug mode enabled, insecure HTTP |
| ℹ️ LOW | AI-generated comments, oversized files, code smells |

## Privacy

- **No data leaves your browser** — All scanning happens locally
- **No API keys required** — Uses GitHub's public API
- **No tracking** — Zero analytics or telemetry
- **Open source** — Inspect the code yourself

## Pricing

- **Free tier**: 10 scans per day
- **Pro tier** ($9.99/mo): Unlimited scans + detailed reports

## Technical Details

Built with vanilla JavaScript (no frameworks). Uses GitHub's public API to fetch repository contents, then runs pattern matching against 300+ security patterns. Results are displayed in a clean popup with severity ratings and suggested fixes.

## License

MIT License — free to use, modify, and distribute.
