"""Shared CheckResult model for all service checkers."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Optional


@dataclass
class CheckResult:
    service: str = "Unknown"
    valid: bool = False
    category: str = "unknown"  # valid | invalid | unknown
    plan_live: str = "Unknown"
    email: Optional[str] = None
    name: Optional[str] = None
    user_id: Optional[str] = None
    session_status: str = "unknown"
    reason: str = ""
    models_hint: list[str] = field(default_factory=list)
    stripe: bool = False
    oai_wm: bool = False
    source_file: Optional[str] = None
    extras: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.category not in ("valid", "invalid", "unknown"):
            if self.valid:
                self.category = "valid"
            elif self.session_status in ("challenge", "error"):
                self.category = "unknown"
            else:
                self.category = "invalid"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def finalize(
    *,
    service: str,
    valid: bool,
    category: str | None = None,
    plan_live: str = "Unknown",
    email: str | None = None,
    name: str | None = None,
    user_id: str | None = None,
    session_status: str = "unknown",
    reason: str = "",
    models_hint: list[str] | None = None,
    stripe: bool = False,
    oai_wm: bool = False,
    source_file: str | None = None,
    extras: dict | None = None,
    **kwargs: Any,  # Absorbe cualquier parámetro imprevisto de nuevos servicios
) -> CheckResult:
    """Build a CheckResult with consistent category and safe extras absorption."""
    if category is None:
        category = "valid" if valid else "invalid"

    merged_extras = dict(extras or {})
    if kwargs:
        merged_extras.update(kwargs)

    return CheckResult(
        service=service,
        valid=valid,
        category=category,
        plan_live=plan_live or "Unknown",
        email=email,
        name=name,
        user_id=str(user_id) if user_id is not None else None,
        session_status=session_status,
        reason=reason or "",
        models_hint=list(models_hint or []),
        stripe=stripe,
        oai_wm=oai_wm,
        source_file=source_file,
        extras=merged_extras,
    )