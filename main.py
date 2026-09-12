#!/usr/bin/env python3
"""
amai-check CLI entrypoint — multi-service live session validator.

  python main.py
  python main.py --clean
  python main.py --services chatgpt,grok
  python main.py --services claude --clean
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.load import detect_service, discover_jars, requests_cookie_dict
from src.models import CheckResult, finalize
from src.progress import (
    load_completed_sources,
    load_seen_fingerprints,
    print_banner,
    print_result,
    print_skip,
    print_summary,
    prune_progress_for_services,
    summarize_progress,
)
from src.services import ALL_SERVICES, REGISTRY, SERVICE_FOLDER
from src.write import (
    is_real_email,
    jar_digest,
    label_from_jar,
    safe_stem,
    save_cookie_editor_json,
    to_cookie_editor,
    uniquify_label,
)

COOKIES = ROOT / "cookies"
OUTPUT = ROOT / "output"


def _jar_fingerprint(jar) -> str:
    prefer = {
        "sp_dc", "sp_key", ".roblosecurity", "roblosecurity",
        "netflixid", "securenetflixid",
        "sessionkey", "sessionkeyv3",
        "workoscursorsessiontoken",
        "auth_token", "ct0", "etp_rt",
        "session", "sessionid", "sso", "sso-rw",
    }
    scored = []
    for c in jar.cookies or []:
        n = (c.name or "").lower()
        if not n:
            continue
        weight = 0
        if n in prefer or n.startswith("__secure-next-auth.session-token"):
            weight = 2
        elif n in {"session-token", "sid", "ssid"}:
            weight = 1
        if weight:
            scored.append((weight, n, (c.domain or "").lower(), c.value or ""))
    parts: list[str] = []
    if scored:
        scored.sort(key=lambda x: (-x[0], x[1], x[2]))
        for _, n, d, v in scored[:12]:
            parts.append(f"{n}|{d}|{v}")
    else:
        for c in sorted(jar.cookies or [], key=lambda x: ((x.name or ""), (x.domain or ""))):
            if c.name:
                parts.append(f"{c.name}|{c.domain or ''}|{(c.value or '')[:80]}")
    blob = "\n".join(parts) or (str(jar.source) if jar.source else "empty")
    return hashlib.sha1(blob.encode("utf-8", errors="replace")).hexdigest()


def _sync_progress(progress) -> None:
    """Flush one progress row all the way to disk when possible."""
    progress.flush()
    try:
        os.fsync(progress.fileno())
    except OSError:
        pass


def _seed_serial_counters(services: set[str]) -> dict[str, int]:
    """Continue Alive#/Dead#/Maybe# labels cleanly after a resumed run."""
    counters: dict[str, int] = {}
    pattern = re.compile(r"^(Alive|Dead|Maybe)#(\d+)(?:_|$)", re.I)
    for service in services:
        folder = SERVICE_FOLDER.get(service, service.capitalize())
        for bucket in ("valid", "invalid", "unknown"):
            base = OUTPUT / bucket / folder
            if not base.exists():
                continue
            for path in base.rglob("*.json"):
                m = pattern.match(path.stem)
                if not m:
                    continue
                prefix = m.group(1).capitalize()
                key = f"{service}:{prefix}"
                counters[key] = max(counters.get(key, 0), int(m.group(2)))
    return counters


def _payload_digest(payload) -> str:
    raw = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()


def _build_output_index() -> dict[tuple[str, str], Path]:
    """Index existing Cookie-Editor exports so a crash cannot create _2/_3 copies."""
    out: dict[tuple[str, str], Path] = {}
    for bucket in ("valid", "invalid", "unknown"):
        base = OUTPUT / bucket
        if not base.exists():
            continue
        for path in base.rglob("*.json"):
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
                digest = _payload_digest(payload)
            except (OSError, ValueError, TypeError, json.JSONDecodeError):
                continue
            parent = os.path.normcase(os.path.abspath(str(path.parent)))
            out[(parent, digest)] = path
    return out


def _jar_output_key(dest_dir: Path, jar) -> tuple[str, str]:
    parent = os.path.normcase(os.path.abspath(str(dest_dir)))
    return parent, _payload_digest(to_cookie_editor(jar))


def _clean_services(services: set[str]) -> None:
    for bucket in ("valid", "invalid", "unknown"):
        base = OUTPUT / bucket
        base.mkdir(parents=True, exist_ok=True)
        for svc in services:
            folder = SERVICE_FOLDER.get(svc, svc.capitalize())
            target = base / folder
            if target.exists():
                shutil.rmtree(target)
    (OUTPUT / "reports").mkdir(parents=True, exist_ok=True)


def _next_serial(counters: dict[str, int], key: str, prefix: str) -> str:
    counters[key] = counters.get(key, 0) + 1
    return f"{prefix}#{counters[key]}"


def _label_for_result(
    service: str,
    result: CheckResult,
    jar,
    alive_counters: dict[str, int],
) -> str:
    st = (result.category or ("valid" if result.valid else "invalid")).lower()
    if st == "valid":
        serial_prefix = "Alive"
    elif st == "invalid":
        serial_prefix = "Dead"
    else:
        serial_prefix = "Maybe"
    serial_key = f"{service}:{serial_prefix}"
    extras = result.extras or {}

    if service == "twitter":
        handle = extras.get("handle") or extras.get("screen_name") or result.name
        if isinstance(handle, str) and handle.strip():
            h = handle.strip()
            return safe_stem(h if h.startswith("@") else f"@{h}")

    if service == "roblox":
        name = result.name or extras.get("username") or extras.get("name")
        if isinstance(name, str) and name.strip():
            return safe_stem(name.strip().lstrip("@"))

    if service in ("chatgpt", "grok", "spotify", "claude"):
        if is_real_email(result.email):
            return safe_stem(str(result.email).strip())
        return _next_serial(alive_counters, serial_key, serial_prefix)

    if is_real_email(result.email):
        return safe_stem(str(result.email).strip())
    return label_from_jar(jar, preferred=result.email if isinstance(result.email, str) else None)


def _parse_services(raw: str | None) -> set[str] | None:
    if raw is None:
        return None
    if not str(raw).strip():
        raise SystemExit(
            "--services was set but empty. Pass a comma list or omit the flag. "
            f"Use: {', '.join(sorted(ALL_SERVICES))}"
        )
    out: set[str] = set()
    for part in raw.replace(" ", ",").split(","):
        p = part.strip().lower()
        if not p:
            continue
        if p in ("x", "twitter"):
            out.add("twitter")
        elif p in ALL_SERVICES:
            out.add(p)
        else:
            raise SystemExit(f"Unknown service: {part!r}. Use: {', '.join(sorted(ALL_SERVICES))}")
    if not out:
        raise SystemExit(
            "--services had no recognized names. "
            f"Use: {', '.join(sorted(ALL_SERVICES))}"
        )
    return out


def _run_check(jar, service: str, timeout: int) -> CheckResult:
    fn = REGISTRY.get(service)
    src = jar.source.name if jar.source else None
    cookies = requests_cookie_dict(jar)
    if not fn:
        return finalize(
            service=service or "Unknown",
            valid=False,
            category="unknown",
            reason="unknown service",
            source_file=src,
        )
    try:
        return fn(cookies, source_file=src, jar=jar, timeout=timeout)
    except TypeError:
        # checkers that don't accept timeout/jar kwargs
        try:
            return fn(cookies, source_file=src, jar=jar)
        except TypeError:
            return fn(cookies, source_file=src)
    except Exception as e:
        return finalize(
            service=SERVICE_FOLDER.get(service, service),
            valid=False,
            category="unknown",
            session_status="error",
            reason=f"checker_error:{type(e).__name__}:{e}",
            source_file=src,
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="amai-check — ChatGPT/Grok/Spotify/Netflix/Crunchyroll/Claude/Cursor/Twitter/Roblox"
    )
    parser.add_argument(
        "--clean",
        action="store_true",
        help="wipe ONLY services present in this run (never other services)",
    )
    parser.add_argument(
        "--services",
        type=str,
        default=None,
        help="comma list: chatgpt,spotify,grok,claude,cursor,twitter|x,netflix,crunchyroll,roblox",
    )
    parser.add_argument("--timeout", type=int, default=25)
    parser.add_argument(
        "--reset",
        action="store_true",
        help="ignore saved resume state without deleting existing output",
    )
    args = parser.parse_args(argv)
    only = _parse_services(args.services)

    # Solo creamos reports por adelantado; valid/invalid/unknown se crearán solo si hay archivos
    (OUTPUT / "reports").mkdir(parents=True, exist_ok=True)

    if not COOKIES.exists():
        COOKIES.mkdir(parents=True, exist_ok=True)

    jars = discover_jars(COOKIES)
    if only:
        filtered = []
        for jar in jars:
            svc = detect_service(jar)
            if svc in only:
                filtered.append(jar)
        jars = filtered

    if not jars:
        print("No cookies found.", flush=True)
        print(
            "Drop files into:\n"
            f"  {COOKIES}  (loose files: only admitted services)\n"
            f"  {COOKIES / 'ChatGPT' / 'Plus'}\n"
            f"  {COOKIES / 'Spotify'}\n"
            f"  {COOKIES / 'Grok'}\n"
            f"  {COOKIES / 'Claude'}\n"
            f"  {COOKIES / 'Cursor'}\n"
            f"  {COOKIES / 'Twitter'}\n"
            f"  {COOKIES / 'Netflix'}\n"
            f"  {COOKIES / 'Crunchyroll'}\n"
            f"  {COOKIES / 'Roblox'}",
            flush=True,
        )
        if only:
            print(f"(filtered to --services {','.join(sorted(only))})", flush=True)
        return 1

    resolved = [(jar, detect_service(jar)) for jar in jars]
    services_in_run = {s for _, s in resolved if s != "unknown"}
    if only:
        services_in_run |= only

    progress_path = OUTPUT / "reports" / "progress.jsonl"
    if args.clean and services_in_run:
        _clean_services(services_in_run)
        prune_progress_for_services(progress_path, services_in_run)

    bid, stamp = print_banner(ROOT, len(jars), only)
    counts: dict[str, int] = defaultdict(int)
    used_labels: dict[str, set[str]] = defaultdict(set)
    alive_counters = _seed_serial_counters(services_in_run)
    output_index = _build_output_index()

    if args.reset or args.clean:
        already_done: set[str] = set()
        seen_fps: set[str] = set()
    else:
        already_done = load_completed_sources(progress_path)
        seen_fps = load_seen_fingerprints(progress_path)
        if already_done:
            print(f"[RESUME] {len(already_done)} completed source(s) will be skipped", flush=True)

    with progress_path.open("a", encoding="utf-8") as progress:
        # LIVE per-file loop: check → atomic write → print (amai style)
        for jar, service in resolved:
            src_name = jar.source.name if jar.source else "?"
            src_key = os.path.normcase(os.path.abspath(str(jar.source))) if jar.source else ""
            if src_key and src_key in already_done:
                counts["skipped_resume"] += 1
                continue

            fp_key = _jar_fingerprint(jar)[:16]
            if fp_key in seen_fps:
                counts["skipped_dup"] += 1
                print_skip(service, src_name, "duplicate jar (same session cookies)")
                progress.write(
                    json.dumps({
                        "ts": stamp, "build": bid,
                        "source": str(jar.source) if jar.source else "",
                        "service": service, "status": "skipped_dup",
                        "reason": "duplicate jar fingerprint", "fp": fp_key,
                    }, ensure_ascii=False) + "\n"
                )
                _sync_progress(progress)
                if src_key:
                    already_done.add(src_key)
                continue
            seen_fps.add(fp_key)

            result = _run_check(jar, service, args.timeout)
            bucket = (result.category or ("valid" if result.valid else "invalid")).lower()
            if bucket not in ("valid", "invalid", "unknown"):
                bucket = "valid" if result.valid else "invalid"

            svc_folder = SERVICE_FOLDER.get(service, result.service or service.capitalize())
            plan_path = result.plan_live if (bucket == "valid" and result.plan_live) else "Unknown"
            if bucket == "valid" and not result.plan_live:
                plan_path = "Unknown"

            # output paths: valid/<Service>/<plan>/ ; invalid flat; roblox flat
            if bucket in ("invalid", "unknown") or service == "roblox":
                dest_dir = OUTPUT / bucket / svc_folder
            else:
                dest_dir = OUTPUT / bucket / svc_folder / plan_path
            dest_dir.mkdir(parents=True, exist_ok=True)

            label = _label_for_result(service, result, jar, alive_counters)
            digest = jar_digest(jar, str(jar.source or "jar"))
            dest_key = str(dest_dir)
            label_set = used_labels[dest_key]

            export_key = _jar_output_key(dest_dir, jar)
            existing = output_index.get(export_key)
            if existing is not None and existing.is_file():
                out_cookie = existing
                candidate = existing.stem
            else:
                candidate = uniquify_label(dest_dir, label, digest, label_set, need_cookie=True)
                if candidate is None:
                    counts["skipped_write"] += 1
                    print(f"[WARN] could not uniquify label for {src_name}; skip write", flush=True)
                    progress.write(
                        json.dumps({
                            "ts": stamp, "build": bid, "source": str(jar.source or ""),
                            "service": service, "status": "skipped_write",
                            "reason": "could not uniquify label", "fp": fp_key,
                        }, ensure_ascii=False) + "\n"
                    )
                    _sync_progress(progress)
                    continue

                # packaging only: Cookie-Editor {label}.json (no sibling .result.json)
                out_cookie = dest_dir / f"{candidate}.json"
                owned: list[Path] = []
                try:
                    save_cookie_editor_json(jar, out_cookie)
                    owned.append(out_cookie)
                    output_index[export_key] = out_cookie
                except (FileExistsError, OSError, ValueError) as exc:
                    for p in owned:
                        try:
                            p.unlink(missing_ok=True)
                        except OSError:
                            pass
                    reason = "export exists" if isinstance(exc, FileExistsError) else f"write failed: {type(exc).__name__}"
                    print(f"[WARN] {reason} for {candidate}; skip write", flush=True)
                    counts["skipped_write"] += 1
                    progress.write(
                        json.dumps({
                            "ts": stamp, "build": bid, "source": str(jar.source or ""),
                            "service": service, "status": "skipped_write", "reason": reason,
                            "label": candidate, "fp": fp_key,
                        }, ensure_ascii=False) + "\n"
                    )
                    _sync_progress(progress)
                    continue

            label_set.add(candidate.lower())
            counts[bucket] += 1

            # PRINT IMMEDIATELY (amai live loop) — never buffer all then dump
            print_result(result, label=candidate, out_path=out_cookie)
            progress.write(
                json.dumps({
                    "ts": stamp, "build": bid,
                    "source": str(jar.source) if jar.source else "",
                    "service": service, "status": bucket,
                    "reason": result.reason, "plan_live": result.plan_live,
                    "email": result.email, "label": candidate,
                    "output": str(out_cookie.relative_to(OUTPUT)), "fp": fp_key,
                }, ensure_ascii=False) + "\n"
            )
            _sync_progress(progress)
            if src_key and bucket in ("valid", "invalid"):
                already_done.add(src_key)

    batch_sources = [jar.source for jar, _ in resolved if jar.source is not None]
    total_counts, valid_by_plan = summarize_progress(progress_path, batch_sources)
    total_counts["skipped_resume"] = counts.get("skipped_resume", 0)

    summary_path = OUTPUT / "reports" / "summary.txt"
    summary = [
        "amai-check summary",
        f"run: {stamp}",
        f"build: {bid}",
        f"files: {len(jars)}",
        f"valid: {total_counts['valid']}",
        f"invalid: {total_counts['invalid']}",
        f"unknown: {total_counts['unknown']}",
        f"skipped_dup: {total_counts.get('skipped_dup', 0)}",
        f"skipped_write: {total_counts.get('skipped_write', 0)}",
        f"skipped_resume: {counts.get('skipped_resume', 0)}",
        "",
        "valid by service (plan_live):",
    ]
    if valid_by_plan:
        for k, v in sorted(valid_by_plan.items()):
            summary.append(f"  {k}: {v}")
    else:
        summary.append("  (none)")
    summary_path.write_text("\n".join(summary) + "\n", encoding="utf-8")
    print_summary(total_counts, valid_by_plan)
    if counts.get("skipped_resume", 0):
        print(f"skipped_resume={counts['skipped_resume']}", flush=True)
    print(f"reports: {summary_path}", flush=True)

    # Limpieza final: borra carpetas en output que hayan quedado completamente vacías
    for bucket in ("valid", "invalid", "unknown"):
        b_dir = OUTPUT / bucket
        if b_dir.exists() and not any(b_dir.iterdir()):
            try:
                b_dir.rmdir()
            except OSError:
                pass

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\n[!] Ejecucion interrumpida por el usuario.", flush=True)
        print("[*] El progreso guardado se conservara para la proxima ejecucion.", flush=True)
        raise SystemExit(130)
