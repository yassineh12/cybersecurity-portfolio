# Secrets scan: example.com

Scanned 8 pages, analysed 14 JavaScript files and 3 inline scripts on 2026-10-28.

## Findings

### Critical

| # | Rule | File | Line | Match |
|---|---|---|---|---|
| 1 | AWS Access Key ID | `/static/js/app.bundle.js` | 1842 | `AKIAIOSFODNN7EXAMPLE` |
| 2 | Stripe Secret Key | `/static/js/checkout.min.js` | 1 | `sk_live_51H...` (truncated) |
| 3 | GitHub Token | `/static/js/deploy.js` | 23 | `ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890` |

### High

| # | Rule | File | Line | Match |
|---|---|---|---|---|
| 4 | Hardcoded Password | `/static/js/config.js` | 7 | `password: "Pr0duction_DB!pass"` |
| 5 | Slack Webhook | `/static/js/notify.js` | 15 | `https://hooks.slack.com/services/T0123.../B0456.../abcdef...` |
| 6 | Google API Key | `/static/js/maps.js` | 3 | `AIzaSyA-example-key-not-real-12345` |

### Medium

| # | Rule | File | Line | Match |
|---|---|---|---|---|
| 7 | Internal URL | `/static/js/app.bundle.js` | 892 | `http://192.168.1.50:8080/api/v1/users` |
| 8 | Firebase URL | `/static/js/app.bundle.js` | 1204 | `https://myapp-prod.firebaseio.com` |
| 9 | JWT Token | `/static/js/auth.js` | 41 | `eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOi...` |

## Summary

**3 critical**, **3 high**, **3 medium** findings across 14 JavaScript files.

The AWS key and Stripe secret key are the highest priority: they grant direct access to cloud infrastructure and payment processing. These should be rotated immediately and removed from the client-side code. The hardcoded database password suggests backend credentials are compiled into the frontend build — likely an environment variable leak during bundling.

## Recommended actions

1. **Rotate** all exposed keys and tokens immediately
2. **Audit** the build pipeline to ensure environment variables are not inlined into client bundles
3. **Add** a pre-commit hook (e.g. `truffleHog`, `gitleaks`, or GitHub's built-in secret scanning) to catch secrets before they reach version control
4. **Move** API calls that require secrets to a backend proxy
