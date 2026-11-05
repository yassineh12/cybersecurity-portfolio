# Subdomain recon: example.com

Queried crt.sh on 2026-10-28. Found 47 unique subdomains across 83 certificates.

## Live subdomains (resolved)

| Subdomain | IP address | First seen | Last seen | Issuer |
|---|---|---|---|---|
| www.example.com | 93.184.216.34 | 2020-01-15 | 2026-09-01 | DigiCert |
| mail.example.com | 93.184.216.40 | 2019-06-22 | 2026-09-01 | DigiCert |
| api.example.com | 93.184.216.50 | 2021-03-10 | 2026-09-01 | Let's Encrypt |
| staging.example.com | 198.51.100.12 | 2023-11-02 | 2026-08-15 | Let's Encrypt |
| dev.example.com | 198.51.100.15 | 2024-01-20 | 2026-07-30 | Let's Encrypt |
| jenkins.example.com | 198.51.100.20 | 2024-06-11 | 2026-09-01 | Let's Encrypt |

## Dead subdomains (DNS lookup failed)

| Subdomain | First seen | Last seen | Notes |
|---|---|---|---|
| old-blog.example.com | 2018-05-01 | 2022-12-15 | Certificate expired, no DNS record |
| beta.example.com | 2022-08-10 | 2023-06-01 | CNAME points to decommissioned Heroku app — **subdomain takeover candidate** |

## Wildcard certificates

| Pattern | Issuer | Active |
|---|---|---|
| *.example.com | DigiCert | Yes |

## Issuer breakdown

| Issuer | Certificates | Percentage |
|---|---|---|
| DigiCert | 52 | 63% |
| Let's Encrypt | 31 | 37% |

## Key observations

- `jenkins.example.com` is a CI server exposed to the internet. Should be behind a VPN or IP allowlist.
- `staging.example.com` and `dev.example.com` are pre-production environments on public IPs. May run debug configurations.
- `beta.example.com` has a dangling CNAME pointing to Heroku — a subdomain takeover is possible.
- The wildcard certificate means any new subdomain automatically gets valid TLS, which is convenient but means a compromised server at `anything.example.com` has a trusted certificate.
