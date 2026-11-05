from recon import parse_ct_entries, SubdomainInfo


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
