"""Banner, per-jar print helpers, run stamps."""
from __future__ import annotations

import hashlib
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .models import CheckResult


def build_id(root: Path) -> str:
    h = hashlib.sha256()
    for rel in (
        "main.py",
        "src/models.py",
        "src/load.py",
        "src/write.py",
        "requirements.txt",
    ):
        p = root / rel
        if p.is_file():
            h.update(rel.encode())
            h.update(p.read_bytes())
    return h.hexdigest()[:12]


def run_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S") + "_" + uuid.uuid4().hex[:8]


def print_banner(root: Path, n_files: int, services: set[str] | None = None) -> tuple[str, str]:
    bid = build_id(root)
    stamp = run_stamp()
    svc = f"  services={','.join(sorted(services))}" if services else ""
    line = f"amai-check — {n_files} file(s){svc}  build={bid}  run={stamp}"
    print(line, flush=True)
    print("-" * 56, flush=True)
    return bid, stamp


def print_result(result: CheckResult, label: str | None = None, out_path: Path | None = None) -> None:
    cat = (result.category or ("valid" if result.valid else "invalid")).lower()
    flag = {"valid": "OK", "invalid": "NO", "unknown": "??"}.get(cat, cat.upper()[:2])
    shown = label or result.source_file or "-"
    if len(shown) > 48:
        shown = shown[:40] + "…" + shown[-6:]
    extra = ""
    if result.plan_live and result.plan_live != "Unknown":
        extra += f"  plan_live={result.plan_live}"
    elif result.valid:
        extra += f"  plan_live={result.plan_live}"
    if result.oai_wm:
        extra += "  oai-wm=info"
    reason = result.reason or result.session_status or ""
    print(f"[{flag}] {result.service:12} {shown:48} {reason}{extra}", flush=True)
    if out_path:
        print(f"  -> {out_path}", flush=True)


def print_skip(service: str, src: str, why: str) -> None:
    print(f"[SKIP] {service:12} {src[:36]:36} {why}", flush=True)


def print_summary(counts: dict, valid_by_plan: dict | None = None) -> None:
    print("-" * 56, flush=True)
    print(
        f"valid={counts.get('valid', 0)}  invalid={counts.get('invalid', 0)}  "
        f"unknown={counts.get('unknown', 0)}  "
        f"skipped_dup={counts.get('skipped_dup', 0)}  "
        f"skipped_write={counts.get('skipped_write', 0)}",
        flush=True,
    )
    if valid_by_plan:
        for k, v in sorted(valid_by_plan.items()):
            print(f"  {k}: {v}", flush=True)
