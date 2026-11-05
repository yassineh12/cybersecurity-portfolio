"""Detector registry: builds the stock detectors from a Config.

Imports happen inside default_detectors() so that ``import watchtower`` (and
the config, correlation and reporting code) keeps working even if one detector
module is missing or broken. A missing detector is reported with a warning
rather than silently ignored: a scan that quietly ran half its checks would
give a false sense of safety.
"""

from __future__ import annotations

import importlib
import warnings
from typing import TYPE_CHECKING

if TYPE_CHECKING:                              # pragma: no cover
    from ..config import Config
    from ..models import Alert, Detector, LogEvent

# config name -> (module, class). Order is the order detectors see events.
_REGISTRY: tuple[tuple[str, str, str], ...] = (
    ("signatures", "watchtower.detectors.signatures", "SignatureDetector"),
    ("enumeration", "watchtower.detectors.behaviour", "EnumerationDetector"),
    ("brute_force", "watchtower.detectors.behaviour", "BruteForceDetector"),
    ("rate", "watchtower.detectors.behaviour", "RateDetector"),
)


class RuleFilter:
    """Wraps a detector and drops alerts for rules the config disabled.

    Filtering on output (rather than asking each detector to know about the
    config) keeps detectors simple and makes disabling a rule work the same
    way for every detector, including ones added later.
    """

    def __init__(self, inner: "Detector", config: "Config"):
        self.inner = inner
        self.config = config
        self.rule_ids = tuple(r for r in getattr(inner, "rule_ids", ())
                              if config.rule_enabled(r))

    def _keep(self, alerts: "list[Alert] | None") -> "list[Alert]":
        return [a for a in (alerts or []) if self.config.rule_enabled(a.rule_id)]

    def feed(self, event: "LogEvent") -> "list[Alert]":
        return self._keep(self.inner.feed(event))

    def flush(self) -> "list[Alert]":
        return self._keep(self.inner.flush())

    def __repr__(self) -> str:
        return f"RuleFilter({self.inner!r})"


def default_detectors(config: "Config") -> "list[Detector]":
    """Instantiate every enabled stock detector with its configured options.

    A detector whose rules are all disabled is skipped entirely, saving the
    per-event work. Detectors whose module cannot be imported are skipped
    with a RuntimeWarning naming the module.
    """
    detectors = []
    for name, module_name, class_name in _REGISTRY:
        if not config.detector_enabled(name):
            continue
        try:
            cls = getattr(importlib.import_module(module_name), class_name)
        except (ImportError, AttributeError) as exc:
            warnings.warn(f"detector '{name}' unavailable ({module_name}.{class_name}): {exc}",
                          RuntimeWarning, stacklevel=2)
            continue
        wrapped = RuleFilter(cls(**config.detector_options(name)), config)
        if getattr(wrapped.inner, "rule_ids", None) and not wrapped.rule_ids:
            continue                                   # every rule switched off
        detectors.append(wrapped)
    return detectors
