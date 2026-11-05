from recon import (
    parse_ct_entries,
    check_takeover_risk,
    filter_subdomains,
    recon,
    SubdomainInfo,
    ReconResult,
)


SAMPLE_ENTRIES = [
    {
        "name_value": "mail.example.com",
        "issuer_name": "Let's Encrypt",
        "not_before": "2024-01-15",
        "not_after": "2024-04-15",
    },
    {
        "name_value": "*.example.com\nwww.example.com",
        "issuer_name": "DigiCert",
        "not_before": "2023-06-01",
        "not_after": "2025-06-01",
    },
    {
        "name_value": "api.example.com",
        "issuer_name": "Let's Encrypt",
        "not_before": "2024-03-01",
        "not_after": "2024-06-01",
    },
    {
        "name_value": "unrelated.other.com",
        "issuer_name": "Let's Encrypt",
        "not_before": "2024-01-01",
        "not_after": "2024-12-01",
    },
]


def test_parse_finds_subdomains():
    subs = parse_ct_entries(SAMPLE_ENTRIES, "example.com")
    names = set(subs.keys())
    assert "mail.example.com" in names
    assert "www.example.com" in names
    assert "api.example.com" in names


def test_parse_excludes_other_domains():
    subs = parse_ct_entries(SAMPLE_ENTRIES, "example.com")
    assert "unrelated.other.com" not in subs


def test_wildcard_detected():
    subs = parse_ct_entries(SAMPLE_ENTRIES, "example.com")
    assert subs["example.com"].is_wildcard is True


def test_earliest_date_kept():
    subs = parse_ct_entries(SAMPLE_ENTRIES, "example.com")
    assert subs["www.example.com"].first_seen == "2023-06-01"


def test_empty_entries():
    subs = parse_ct_entries([], "example.com")
    assert subs == {}


def test_wildcard_count():
    subs = parse_ct_entries(SAMPLE_ENTRIES, "example.com")
    wc = sum(1 for s in subs.values() if s.is_wildcard)
    assert wc == 1


def test_issuer_aggregation():
    subs = parse_ct_entries(SAMPLE_ENTRIES, "example.com")
    issuers = [s.issuer for s in subs.values()]
    assert "Let's Encrypt" in issuers
    assert "DigiCert" in issuers


def test_takeover_risk_dangling_cname():
    info = SubdomainInfo(
        name="old.example.com",
        still_resolves=False,
        cnames=["old-app.herokuapp.com"],
    )
    assert check_takeover_risk(info) is True


def test_takeover_no_risk_when_resolves():
    info = SubdomainInfo(
        name="live.example.com",
        still_resolves=True,
        cnames=["live-app.herokuapp.com"],
    )
    assert check_takeover_risk(info) is False


def test_takeover_no_risk_safe_cname():
    info = SubdomainInfo(
        name="cdn.example.com",
        still_resolves=False,
        cnames=["cdn.example.com.cdn77.org"],
    )
    assert check_takeover_risk(info) is False


def test_takeover_multiple_providers():
    for provider_cname in ["app.azurewebsites.net", "bucket.s3.amazonaws.com", "page.netlify.app"]:
        info = SubdomainInfo(name="x.example.com", still_resolves=False, cnames=[provider_cname])
        assert check_takeover_risk(info) is True, f"Expected takeover risk for {provider_cname}"


def test_filter_live():
    subs = [
        SubdomainInfo(name="a.example.com", still_resolves=True),
        SubdomainInfo(name="b.example.com", still_resolves=False),
    ]
    filtered = filter_subdomains(subs, "live")
    assert len(filtered) == 1
    assert filtered[0].name == "a.example.com"


def test_filter_dead():
    subs = [
        SubdomainInfo(name="a.example.com", still_resolves=True),
        SubdomainInfo(name="b.example.com", still_resolves=False, is_wildcard=False),
        SubdomainInfo(name="c.example.com", still_resolves=False, is_wildcard=True),
    ]
    filtered = filter_subdomains(subs, "dead")
    assert len(filtered) == 1
    assert filtered[0].name == "b.example.com"


def test_filter_wildcard():
    subs = [
        SubdomainInfo(name="a.example.com", is_wildcard=True),
        SubdomainInfo(name="b.example.com", is_wildcard=False),
    ]
    filtered = filter_subdomains(subs, "wildcard")
    assert len(filtered) == 1
    assert filtered[0].name == "a.example.com"


def test_filter_takeover():
    subs = [
        SubdomainInfo(name="a.example.com", takeover_risk=True),
        SubdomainInfo(name="b.example.com", takeover_risk=False),
    ]
    filtered = filter_subdomains(subs, "takeover")
    assert len(filtered) == 1
    assert filtered[0].name == "a.example.com"


def test_filter_all_returns_everything():
    subs = [SubdomainInfo(name="a.example.com"), SubdomainInfo(name="b.example.com")]
    filtered = filter_subdomains(subs, "all")
    assert len(filtered) == 2


def test_latest_date_updated():
    entries = [
        {"name_value": "api.example.com", "issuer_name": "LE", "not_before": "2024-01-01", "not_after": "2024-06-01"},
        {"name_value": "api.example.com", "issuer_name": "LE", "not_before": "2024-07-01", "not_after": "2025-01-01"},
    ]
    subs = parse_ct_entries(entries, "example.com")
    assert subs["api.example.com"].first_seen == "2024-01-01"
    assert subs["api.example.com"].last_seen == "2025-01-01"
