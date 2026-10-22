"""Paquete de detección: motor determinista, reglas MITRE ICS y línea base."""

from .baseline import Baseline, load_baseline, create_baseline_from_evidence
from .rules import Rule, RuleResult, RuleSet, DEFAULT_RULES

_ENGINE_EXPORTS = {
    "SessionState",
    "DetectionResult",
    "DetectionEngine",
}

__all__ = [
    "Baseline",
    "load_baseline",
    "create_baseline_from_evidence",
    "Rule",
    "RuleResult",
    "RuleSet",
    "DEFAULT_RULES",
    *_ENGINE_EXPORTS,
]


def __getattr__(name: str):
    if name in _ENGINE_EXPORTS:
        from . import engine
        return getattr(engine, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
