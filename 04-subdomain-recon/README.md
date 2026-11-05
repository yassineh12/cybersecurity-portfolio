# Project 4: Subdomain & certificate-transparency recon

Discovers an organisation's subdomains by querying public certificate transparency logs. Every HTTPS certificate issued by a trusted CA is logged publicly — this tool reads those logs to map the attack surface without sending a single packet to the target.

```bash
cd 04-subdomain-recon
python recon.py example.com --resolve --out report
```

## How it works

| Step | What happens | Why it matters |
|---|---|---|
| CT log query | Queries crt.sh for all certificates matching `*.domain` | CT logs are public and append-only — even revoked or expired certs stay |
| Subdomain extraction | Parses Subject Alternative Names from each certificate | One cert can cover dozens of subdomains |
| DNS resolution | Resolves each subdomain to check if it is still live | A subdomain that resolves is live attack surface |
| Issuer analysis | Counts which CAs issued certificates | Reveals the org's PKI strategy and potential weaknesses |

## What an attacker learns

- **Live subdomains** are entry points: `staging.company.com`, `dev-api.company.com`, `jenkins.company.com`
- **Dead subdomains** that still have DNS CNAME records are subdomain takeover candidates (if the CNAME points to a decommissioned cloud service, anyone can claim it)
- **Certificate issuers** reveal whether the org uses automated renewal (Let's Encrypt) or manual processes (more likely to let certs expire)
- **Wildcard certs** (`*.company.com`) mean any subdomain gets valid HTTPS automatically — convenient, but it means a compromised server at `anything.company.com` has a trusted certificate

## Safety

This tool queries only public CT log aggregators (crt.sh). No packets are sent to the target domain during the CT query phase. DNS resolution (`--resolve`) sends standard DNS lookups, which are routine internet traffic.

## What I learned

- Certificate transparency is one of the most powerful passive recon techniques. Organisations cannot hide subdomains if they use HTTPS — the certificate logs reveal them.
- Subdomain takeover is a real vulnerability class. When an org deletes a cloud resource but leaves the DNS record pointing to it, anyone can claim that subdomain.
- The difference between passive and active recon matters legally: reading public logs is research; sending probes to a target is testing, and requires authorisation.
