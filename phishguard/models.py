from __future__ import annotations
from dataclasses import dataclass, asdict

SEVERITIES = ("info", "low", "medium", "high", "critical")


@dataclass
class Signal:
    """One explainable finding. `weight` is risk points (negative = trust signal)."""
    id: str
    category: str          # url | content | cert | intel | web
    severity: str          # one of SEVERITIES
    weight: int
    title: str
    detail: str = ""

    def to_dict(self) -> dict:
        return asdict(self)
