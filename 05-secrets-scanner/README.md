# Project 5: Secrets scanner for public JS bundles

Crawls a website, finds all JavaScript files and inline scripts, and searches for accidentally exposed secrets: API keys, tokens, passwords, internal URLs, and cloud credentials that developers left in client-side code.

```bash
cd 05-secrets-scanner
python scanner.py https://example.com --max-pages 10
```

## Why this matters

Everything shipped to the browser is public. Frontend builds often inline environment variables, and developers forget that a `const API_KEY = "sk_live_..."` in a minified bundle is just as readable as writing it on a billboard.

Bug bounty hunters check JS bundles first. The payoff-to-effort ratio is unmatched.

## What it detects

| Rule | Severity | What it catches |
|---|---|---|
| AWS Access Key ID | Critical | `AKIA...` pattern — 20-char key starting with AKIA |
| AWS Secret Key | Critical | Secret key in assignment patterns |
| Stripe Secret Key | Critical | `sk_live_...` — full API access to payment processing |
| GitHub Token | Critical | `ghp_...` — personal access tokens |
| Slack Token | Critical | `xoxb-...` / `xoxp-...` — bot and user tokens |
| Private Key | Critical | `-----BEGIN RSA PRIVATE KEY-----` |
| Google API Key | High | `AIza...` — 39-char Google API key |
| Hardcoded Password | High | Password assignments in code |
| Slack Webhook | High | Incoming webhook URLs |
| JWT Token | Medium | Full JWT tokens (may contain sensitive claims) |
| Internal URL | Medium | `localhost`, `192.168.x.x`, `10.x.x.x` — reveals internal infrastructure |
| Firebase URL | Medium | `*.firebaseio.com` — often misconfigured with public read/write |
| SendGrid / Twilio / Mailgun | Critical | Email and SMS service API keys |

## How it builds on project 1

Reuses the polite crawler from project 1 to discover pages, then extracts all `<script src="...">` references and inline `<script>` blocks. The crawler's robots.txt compliance and rate limiting apply here too.

## Safety

The scanner only reads publicly served JavaScript — the same files any visitor's browser downloads. No authentication bypass, no fuzzing, no exploitation.

## What I learned

- Regex-based secret scanning has a high false-positive rate on minified code, but the critical findings (AWS keys, Stripe secrets) are distinctive enough to match reliably.
- The line between "configuration" and "secret" is blurry. A Firebase URL is not a secret, but a Firebase URL with no security rules is a vulnerability. Context matters.
- Automated secret scanning in CI (like GitHub's built-in secret scanning or tools like truffleHog) catches secrets *before* they ship. This scanner catches the ones that slipped through.
