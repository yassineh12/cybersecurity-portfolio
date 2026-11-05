# Roadmap

How this portfolio grows, one small step at a time. Tick items off as they land.

**Rule of thumb:** one meaningful push a week beats a big burst once a month. A steady commit history is itself evidence to an employer.

## Definition of done (every project)

A project only counts as finished when it has all of these:

- [ ] Tests that pass in CI
- [ ] A README explaining *why* each check or feature matters, not just what it does
- [ ] A sample output in `examples/` (a report, a chart, a screenshot)
- [ ] A short "What I learned" section in the README
- [ ] An ethics and scope note

## Phase 1: finish what's started

- [x] Project 1: headers & TLS auditor
- [x] Project 2, lesson 1: URL collection and URL features
- [x] Project 2, lesson 2: page-content features, crawled in a disposable sandbox
- [x] Project 2, lesson 3: training and evaluating the classifier
- [x] Project 2, lesson 4: explaining predictions, `predict.py` CLI
- [x] Project 3, lessons 1–6: lab setup → recon → fingerprinting → CVE matching → safe checks → reporting

## Phase 2: make it look professional (alongside phase 1)

- [x] GitHub Actions workflow that runs `pytest` on every push, with a badge in the README
- [x] `examples/` folder per project with real output
- [ ] Tag a release (`v0.1`) when each project meets the definition of done
- [ ] Pin this repository on your GitHub profile

## Phase 3: grow outward

Each new project reuses something that already exists, so the portfolio reads as one connected story rather than a pile of exercises.

| # | Project | Builds on | Role it signals | Status |
|---|---|---|---|---|
| 4 | Subdomain and certificate-transparency recon (crt.sh) | Project 1 crawler | Attack-surface management, pentest | ✅ |
| 5 | Secrets scanner for public JS bundles | Project 1 crawler | AppSec, cloud security | ✅ |
| 6 | Web log analyser that detects scanners | Logs produced by project 3 | SOC analyst, detection engineering | ✅ |
| 7 | Phishing detector as a small web API in Docker | Project 2 model | Security engineering, MLOps | ✅ |
| 8 | Incident response toolkit | Project 6 alerts | IR automation, YARA, IOCs | ✅ |
| 9 | Threat intelligence enricher | Project 8 IOCs | Threat intel, MITRE ATT&CK, reputation scoring | ✅ |

Project 6 is the keystone: you attack your lab with project 3, then catch yourself with project 6. Offence and defence in one story is what "purple team" means, and it is rare in junior portfolios.

## Phase 4: prove it outside GitHub

- [ ] A short write-up per project (blog post or LinkedIn article) linking back here
- [ ] TryHackMe or Hack The Box: a learning path completed
- [ ] A certification: CompTIA Security+ or eJPT
- [ ] A responsible-disclosure submission to a programme that invites it (in scope only)
