# Project 2: Phishing site detector (guided)

**Goal:** given a URL, predict whether it is a phishing site, and explain why.

It is the same workflow as the heart-disease notebook in this repo (collect → features → model → evaluate). Only the data changes: here it comes from threat-intelligence feeds and from our own crawler.

## Lesson plan

| Lesson | Topic | Files | Status |
|---|---|---|---|
| 1 | Collecting labelled data, URL features | `collect_urls.py`, `url_features.py` | ✅ here |
| 2 | Page-content features, crawled safely in a sandbox | `page_features.py` | next |
| 3 | Training and evaluating a classifier | `phishing-classifier.ipynb` | |
| 4 | Explaining predictions and shipping a CLI | `predict.py` | |

---

## Lesson 1: data and URL features

### 1. Where the labels come from

A classifier learns from examples that are already labelled. Two free sources supply them:

- **OpenPhish** (`label = 1`) publishes URLs that are phishing *right now*. Phishing sites usually live only hours to days, so this feed changes constantly. Keep each snapshot, because in a week those URLs will be gone.
- **Tranco** (`label = 0`) ranks the top million domains. Security researchers use it because it is hard to manipulate. The top sites are a reasonable stand-in for "legitimate".

### 2. The trap: data leakage through shortcuts

Tranco gives bare domains (`google.com`). Phishing URLs look like `evil.xyz/secure/login.php?session=...`. Train on those as they are and the model reaches 99% accuracy by learning "has a path → phishing". Then it fails on every real legitimate URL that has a path.

That is why `collect_urls.py` uses project 1's crawler to pull a few *internal* links from each legit homepage. Now both classes contain deep URLs, and the model has to learn something real.

> **Interview gold:** "My first model scored 99% and I didn't trust it, so I went looking for leakage." Hiring managers love that sentence.

### 3. The features, and the attacker behaviour behind each

Run `python url_features.py` to see them on three sample URLs.

| Feature | The attacker behaviour it catches |
|---|---|
| `url_length`, `path_depth` | Long URLs hide the real domain off-screen on phones |
| `has_at_symbol` | `https://paypal.com@evil.xyz` actually goes to `evil.xyz`; the part before `@` is treated as a username |
| `host_is_ip` | Throwaway servers often have no domain name |
| `num_subdomains` | `paypal.com.secure-verify.evil.xyz`: the brand sits in a subdomain the attacker controls |
| `num_hyphens_host` | `paypal-login-secure.com`: brand plus reassuring words |
| `host_entropy` | Machine-generated domains (`x7kq9zp2.top`) look random |
| `is_punycode` | `xn--pypal-4ve.com` renders as `pаypal.com` with a Cyrillic "а" |
| `suspicious_tld` | Cheap TLDs (`.xyz`, `.top`, `.tk`) are overrepresented in abuse |
| `is_shortener` | Hides the destination entirely |
| `uses_https` | *Weak* signal. Most phishing uses HTTPS now (free certificates), so the padlock does **not** mean safe |
| `num_suspicious_words` | Urgency and login vocabulary: *verify, account, update, secure* |

No single feature is proof. Plenty of legitimate URLs are long, and plenty of phishing uses `.com`. The model's job is to weigh them together.

### 4. Your turn

```bash
cd 02-phishing-detector
python -m pytest tests                       # the features behave as described
python url_features.py                       # see the features on examples
python collect_urls.py --legit 300           # takes about 10 minutes; writes data/urls.csv
```

Then try the following:
1. Open `data/urls.csv` in pandas and check the class balance. Is it roughly 50/50? What would happen if it were 95/5?
2. Pick 10 phishing URLs by eye. Which brands are being impersonated?
3. Add one feature of your own to `url_features.py`, with a test. A good start: does the URL contain a well-known brand name (`paypal`, `microsoft`, `apple`) in a host that isn't that brand's real domain?

**Safety:** lesson 1 never visits a phishing page, so it is safe on your own laptop. Lesson 2 does visit them, and that happens inside a disposable container.
