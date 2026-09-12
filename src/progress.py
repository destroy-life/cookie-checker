"""Banner, per-jar print helpers, run stamps."""
from __future__ import annotations

import hashlib
import json
import os
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

def _norm_source(value: str | Path) -> str:
    return os.path.normcase(os.path.abspath(str(value)))


def load_completed_sources(progress_path: Path | str) -> set[str]:
    """Return sources with a final status that should be skipped on resume."""
    p = Path(progress_path)
    if not p.is_file():
        return set()
    completed: set[str] = set()
    try:
        with p.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except (json.JSONDecodeError, TypeError, ValueError):
                    continue
                src = row.get("source")
                status = str(row.get("status") or "").lower()
                if src and status in {"valid", "invalid", "skipped_dup"}:
                    completed.add(_norm_source(src))
    except OSError:
        return set()
    return completed


def load_seen_fingerprints(progress_path: Path | str) -> set[str]:
    """Restore fingerprints only from final statuses; transient unknowns are retried."""
    p = Path(progress_path)
    if not p.is_file():
        return set()
    out: set[str] = set()
    try:
        with p.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except (json.JSONDecodeError, TypeError, ValueError):
                    continue
                status = str(row.get("status") or "").lower()
                fp = row.get("fp")
                if fp and status in {"valid", "invalid", "skipped_dup"}:
                    out.add(str(fp))
    except OSError:
        return set()
    return out


def summarize_progress(
    progress_path: Path | str,
    sources: list[Path] | tuple[Path, ...] | None = None,
) -> tuple[dict[str, int], dict[str, int]]:
    """Summarize the latest progress row per source, optionally scoped to this batch."""
    p = Path(progress_path)
    allowed = {_norm_source(s) for s in sources} if sources is not None else None
    latest: dict[str, dict] = {}
    if p.is_file():
        try:
            with p.open("r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        row = json.loads(line)
                    except (json.JSONDecodeError, TypeError, ValueError):
                        continue
                    src = row.get("source")
                    if not src:
                        continue
                    key = _norm_source(src)
                    if allowed is not None and key not in allowed:
                        continue
                    latest[key] = row
        except OSError:
            pass

    counts = {
        "valid": 0,
        "invalid": 0,
        "unknown": 0,
        "skipped_dup": 0,
        "skipped_write": 0,
    }
    valid_by_plan: dict[str, int] = {}
    for row in latest.values():
        status = str(row.get("status") or "unknown").lower()
        if status in counts:
            counts[status] += 1
        else:
            counts["unknown"] += 1
        if status == "valid":
            service = str(row.get("service") or "unknown").lower()
            plan = str(row.get("plan_live") or "Unknown")
            key = f"{service}:{plan}"
            valid_by_plan[key] = valid_by_plan.get(key, 0) + 1
    return counts, valid_by_plan


def prune_progress_for_services(progress_path: Path | str, services: set[str]) -> None:
    """Drop old rows for services explicitly cleaned, preserving unrelated history."""
    p = Path(progress_path)
    if not p.is_file() or not services:
        return
    wanted = {str(s).lower() for s in services}
    kept: list[str] = []
    try:
        with p.open("r", encoding="utf-8") as fh:
            for raw in fh:
                line = raw.rstrip("\n")
                if not line.strip():
                    continue
                try:
                    row = json.loads(line)
                except (json.JSONDecodeError, TypeError, ValueError):
                    kept.append(line)
                    continue
                service = str(row.get("service") or "").lower()
                if service not in wanted:
                    kept.append(line)
        tmp = p.with_name(p.name + ".tmp")
        with tmp.open("w", encoding="utf-8") as fh:
            for line in kept:
                fh.write(line + "\n")
            fh.flush()
            try:
                os.fsync(fh.fileno())
            except OSError:
                pass
        os.replace(tmp, p)
    except OSError:
        return

