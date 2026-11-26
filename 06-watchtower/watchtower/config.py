"""Configuration: who to trust, how sensitive each detector is, how to score.

Every threshold in WATCHTOWER is a trade-off between two failure modes. Set it
too low and the SOC drowns in false positives until people stop reading the
report (which is how real attacks get missed). Set it too high and a patient
attacker stays under it. The defaults live in ``rules/default.yaml`` with the
reasoning next to each knob; this module loads that file (or yours), merges it
over built-in defaults and refuses anything it does not understand, so a typo
cannot silently switch a detector off.
"""

from __future__ import annotations

import difflib
import ipaddress
from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .models import SEVERITIES

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parents[1] / "rules" / "default.yaml"

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

# Every rule id a stock detector can emit. Used to catch typos in `rules:`.
KNOWN_RULES: tuple[str, ...] = (
    "SIG-UA-SCANNER", "SIG-SENSITIVE-PATH", "SIG-SQLI", "SIG-XSS",
    "SIG-TRAVERSAL", "SIG-CMDI", "SIG-LOG4SHELL",
    "BEH-404-BURST", "BEH-BRUTE-FORCE", "BEH-BRUTE-SUCCESS", "BEH-RATE-SPIKE",
    "BEH-LOW-AND-SLOW", "BEH-ID-ENUM",
)

# Network-level channel of the behaviour detectors: also count activity per
# network, so an attacker rotating through many addresses of one IPv6 /64
# (trivially cheap: a single host usually owns the whole /64) still adds up.
# IPv4 grouping is off (None) by default: carrier-grade NAT and ISP blocks put
# unrelated users in the same /24, and merging them manufactures attackers.
NETWORK_DEFAULTS: dict[str, Any] = {"ipv6_prefix": 64, "ipv4_prefix": None, "min_distinct": 4}
_PREFIX_RANGES = {"ipv6_prefix": (32, 128), "ipv4_prefix": (8, 32)}

# Detector name -> its constructor options and their defaults (the brief's values).
DEFAULT_DETECTOR_OPTIONS: dict[str, dict[str, Any]] = {
    "signatures": {"max_evidence": 5},
    "enumeration": {"threshold": 20, "window_seconds": 60,
                    "slow_threshold": 100, "slow_window_seconds": 900,
                    **NETWORK_DEFAULTS},
    "brute_force": {
        "threshold": 10, "window_seconds": 300, **NETWORK_DEFAULTS,
        # Matched exactly (a query string is allowed), never as a prefix: a
        # bare "/admin" prefix would turn every admin-panel form post into a
        # "failed login".
        "login_paths": ("/login", "/signin", "/wp-login.php", "/admin", "/admin/login",
                        "/api/auth", "/api/login", "/user/login", "/xmlrpc.php"),
    },
    "rate": {"threshold": 300, "window_seconds": 60, **NETWORK_DEFAULTS},
    "low_and_slow": {"window_seconds": 21600, "min_misses": 40, "min_miss_ratio": 0.3,
                     "min_distinct_paths": 20, **NETWORK_DEFAULTS},
    "id_enumeration": {"window_seconds": 21600, "min_ids": 25, "max_step": 3,
                       "min_sequential": 0.7, **NETWORK_DEFAULTS},
}

# Options a detector accepts that have no built-in value here: they are passed
# only when the config sets them, so the detector's own default applies
# otherwise (and a WATCHTOWER default can never silently override a newer one).
OPTIONAL_DETECTOR_OPTIONS: dict[str, tuple[str, ...]] = {
    "brute_force": ("login_keywords", "path_agnostic_factor"),
}

# Scoring weights; correlate.py documents how they combine.
DEFAULT_SCORING: dict[str, Any] = {
    "severity_points": {"low": 15, "medium": 35, "high": 60, "critical": 85},
    "extra_rule": 5,
    "extra_rule_cap": 15,
    "extra_stage": 10,
    "recon_then_exploit": 10,
    "exploit_success": 15,
    "brute_success": 15,
    "severity_cutoffs": {"critical": 80, "high": 55, "medium": 30},
}

_TOP_LEVEL_KEYS = ("allowlist", "detectors", "rules", "scoring")


class ConfigError(ValueError):
    """The configuration file is unreadable or contains something we refuse to guess at."""


def _default_detectors() -> dict[str, dict[str, Any]]:
    return deepcopy(DEFAULT_DETECTOR_OPTIONS)


def _default_enabled() -> dict[str, bool]:
    return {name: True for name in DEFAULT_DETECTOR_OPTIONS}


def _default_scoring() -> dict[str, Any]:
    return deepcopy(DEFAULT_SCORING)


@dataclass
class Config:
    """A validated configuration. ``Config()`` alone gives the brief's defaults."""
    allowlist: tuple[IPNetwork, ...] = ()
    detectors: dict[str, dict[str, Any]] = field(default_factory=_default_detectors)
    detectors_enabled: dict[str, bool] = field(default_factory=_default_enabled)
    rules: dict[str, bool] = field(default_factory=dict)      # rule_id -> enabled
    scoring: dict[str, Any] = field(default_factory=_default_scoring)
    source: str | None = None                                 # file it came from

    def is_allowlisted(self, ip: str) -> bool:
        """True when ``ip`` falls inside an allowlisted address or network.

        Unparseable addresses are never allowlisted: an attacker who can make
        the log show garbage in the client field must not be able to hide by it.
        """
        if not self.allowlist:
            return False
        try:
            addr = ipaddress.ip_address(ip.strip())
        except (ValueError, AttributeError):
            return False
        candidates = [addr]
        mapped = getattr(addr, "ipv4_mapped", None)
        if mapped is not None:                 # ::ffff:192.0.2.10 behind a dual-stack proxy
            candidates.append(mapped)
        return any(a in net for a in candidates for net in self.allowlist)

    def rule_enabled(self, rule_id: str) -> bool:
        """Rules are on unless the config explicitly turns them off."""
        return self.rules.get(rule_id, True)

    def detector_enabled(self, name: str) -> bool:
        return self.detectors_enabled.get(name, True)

    def detector_options(self, name: str) -> dict[str, Any]:
        """Constructor keyword arguments for detector ``name``."""
        return dict(self.detectors.get(name, {}))


# ---------------------------------------------------------------- loading ---

def load_config(path: str | Path | None) -> Config:
    """Load and validate a YAML config. ``None`` loads ``rules/default.yaml``.

    Values you leave out keep their defaults, so a file holding only an
    ``allowlist`` is valid. Raises ConfigError with the file name and the
    offending key on anything unknown or out of range.
    """
    if path is None:
        if not DEFAULT_CONFIG_PATH.is_file():      # e.g. package copied without rules/
            return Config()
        path = DEFAULT_CONFIG_PATH
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise ConfigError(f"config file not found: {path}") from None
    except OSError as exc:
        raise ConfigError(f"cannot read config file {path}: {exc}") from None
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path}: invalid YAML: {exc}") from None
    return config_from_dict(data, source=str(path))


def config_from_dict(data: Any, source: str | None = None) -> Config:
    """Validate an already-parsed mapping (what ``yaml.safe_load`` returned)."""
    where = source or "config"
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise ConfigError(f"{where}: top level must be a mapping, got {type(data).__name__}")
    _reject_unknown(data, _TOP_LEVEL_KEYS, where)

    allowlist = _parse_allowlist(data.get("allowlist"), where)
    detectors, enabled = _parse_detectors(data.get("detectors"), where)
    rules = _parse_rules(data.get("rules"), where)
    scoring = _parse_scoring(data.get("scoring"), where)
    return Config(allowlist=allowlist, detectors=detectors, detectors_enabled=enabled,
                  rules=rules, scoring=scoring, source=source)


# ------------------------------------------------------------- validation ---

def _reject_unknown(mapping: dict, allowed, where: str) -> None:
    for key in mapping:
        if key not in allowed:
            hint = difflib.get_close_matches(str(key), list(allowed), n=1)
            suggestion = f" (did you mean '{hint[0]}'?)" if hint else ""
            raise ConfigError(f"{where}: unknown key '{key}'{suggestion}; "
                              f"allowed: {', '.join(allowed)}")


def _parse_allowlist(raw: Any, where: str) -> tuple[IPNetwork, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise ConfigError(f"{where}: 'allowlist' must be a list of IPs or CIDRs")
    nets = []
    for item in raw:
        try:
            # strict=False accepts 10.0.0.1/8 as 10.0.0.0/8, which is what people mean.
            nets.append(ipaddress.ip_network(str(item).strip(), strict=False))
        except ValueError:
            raise ConfigError(f"{where}: allowlist entry '{item}' is not an IP address "
                              f"or CIDR network") from None
        if nets[-1].prefixlen == 0:
            raise ConfigError(f"{where}: allowlist entry '{item}' trusts the whole "
                              f"Internet; that disables detection entirely")
    return tuple(nets)


def _positive_int(value: Any, where: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ConfigError(f"{where} must be a positive integer, got {value!r}")
    return value


def _non_negative_int(value: Any, where: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ConfigError(f"{where} must be a non-negative integer, got {value!r}")
    return value


def _bool(value: Any, where: str) -> bool:
    if not isinstance(value, bool):
        raise ConfigError(f"{where} must be true or false, got {value!r}")
    return value


def _prefix(value: Any, key: str, where: str) -> int | None:
    lo, hi = _PREFIX_RANGES[key]
    if value is None and key == "ipv4_prefix":
        return None                                     # IPv4 grouping off
    if isinstance(value, bool) or not isinstance(value, int) or not lo <= value <= hi:
        off = " or null to disable" if key == "ipv4_prefix" else ""
        raise ConfigError(f"{where} must be an integer from {lo} to {hi}{off}, got {value!r}")
    return value


def _login_paths(value: Any, where: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise ConfigError(f"{where} must be a non-empty list of paths")
    for p in value:
        if not isinstance(p, str) or not p.startswith("/"):
            raise ConfigError(f"{where}: '{p}' must be a path starting with '/'")
    return tuple(value)


def _parse_detectors(raw: Any, where: str) -> tuple[dict, dict]:
    detectors = _default_detectors()
    enabled = _default_enabled()
    if raw is None:
        return detectors, enabled
    if not isinstance(raw, dict):
        raise ConfigError(f"{where}: 'detectors' must be a mapping of detector name to options")
    _reject_unknown(raw, tuple(DEFAULT_DETECTOR_OPTIONS), f"{where}: detectors")
    for name, opts in raw.items():
        ctx = f"{where}: detectors.{name}"
        if opts is None:
            continue
        if not isinstance(opts, dict):
            raise ConfigError(f"{ctx} must be a mapping of options")
        _reject_unknown(opts, ("enabled", *DEFAULT_DETECTOR_OPTIONS[name],
                               *OPTIONAL_DETECTOR_OPTIONS.get(name, ())), ctx)
        for key, value in opts.items():
            if key == "enabled":
                enabled[name] = _bool(value, f"{ctx}.enabled")
            elif key == "login_paths":
                detectors[name][key] = _login_paths(value, f"{ctx}.login_paths")
            elif key in _PREFIX_RANGES:
                detectors[name][key] = _prefix(value, key, f"{ctx}.{key}")
            elif key == "min_distinct":
                detectors[name][key] = _positive_int(value, f"{ctx}.min_distinct")
                if value < 2:
                    raise ConfigError(f"{ctx}.min_distinct must be at least 2 (one address "
                                      f"is already covered per client), got {value}")
            elif key in ("min_miss_ratio", "min_sequential"):
                detectors[name][key] = _ratio(value, f"{ctx}.{key}")
            elif key == "path_agnostic_factor":
                detectors[name][key] = _positive_int(value, f"{ctx}.{key}")
            elif key == "login_keywords":
                detectors[name][key] = _keywords(value, f"{ctx}.{key}")
            else:
                detectors[name][key] = _positive_int(value, f"{ctx}.{key}")
    return detectors, enabled


def _ratio(value: Any, where: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 < value <= 1:
        raise ConfigError(f"{where} must be a number above 0 and at most 1, got {value!r}")
    return float(value)


def _keywords(value: Any, where: str) -> tuple[str, ...]:
    """A list of keywords; an empty list is allowed and switches keyword matching off."""
    if not isinstance(value, list) or not all(isinstance(k, str) and k.strip() for k in value):
        raise ConfigError(f"{where} must be a list of non-empty strings ([] disables)")
    return tuple(k.strip().lower() for k in value)


def _parse_rules(raw: Any, where: str) -> dict[str, bool]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ConfigError(f"{where}: 'rules' must map rule ids to true/false")
    _reject_unknown(raw, KNOWN_RULES, f"{where}: rules")
    return {rule: _bool(v, f"{where}: rules.{rule}") for rule, v in raw.items()}


def _parse_scoring(raw: Any, where: str) -> dict[str, Any]:
    scoring = _default_scoring()
    if raw is None:
        return scoring
    if not isinstance(raw, dict):
        raise ConfigError(f"{where}: 'scoring' must be a mapping")
    _reject_unknown(raw, tuple(DEFAULT_SCORING), f"{where}: scoring")
    for key, value in raw.items():
        ctx = f"{where}: scoring.{key}"
        if key == "severity_points":
            scoring[key].update(_severity_map(value, SEVERITIES, ctx))
        elif key == "severity_cutoffs":
            scoring[key].update(_severity_map(value, ("medium", "high", "critical"), ctx))
        else:
            scoring[key] = _non_negative_int(value, ctx)
    cut = scoring["severity_cutoffs"]
    if not cut["medium"] <= cut["high"] <= cut["critical"] <= 100:
        raise ConfigError(f"{where}: scoring.severity_cutoffs must satisfy "
                          f"medium <= high <= critical <= 100, got {cut}")
    return scoring


def _severity_map(value: Any, allowed: tuple[str, ...], ctx: str) -> dict[str, int]:
    if not isinstance(value, dict):
        raise ConfigError(f"{ctx} must be a mapping of severity to points")
    _reject_unknown(value, allowed, ctx)
    out = {}
    for sev, pts in value.items():
        pts = _non_negative_int(pts, f"{ctx}.{sev}")
        if pts > 100:
            raise ConfigError(f"{ctx}.{sev} must be at most 100, got {pts}")
        out[sev] = pts
    return out
