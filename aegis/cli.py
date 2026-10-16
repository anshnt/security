"""Command-line interface: `aegis <command>` (or `python -m aegis`).

Exit codes: 0 = clean, 1 = findings at/above --fail-on severity (default: high), 2 = usage/runtime error.
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys
import threading
from pathlib import Path
from typing import List, Optional

from aegis import __app_name__, __version__
from aegis.core.config import Config, setup_logging
from aegis.core.models import ScanResult, Severity
from aegis.core.platform import enable_ansi, host_info

EXIT_CLEAN, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2


def _color() -> bool:
    return enable_ansi()


def _print(msg: str = "") -> None:
    try:
        print(msg)
    except UnicodeEncodeError:  # legacy Windows code pages
        print(msg.encode("ascii", "replace").decode("ascii"))


def _progress(quiet: bool):
    lock = threading.Lock()

    def cb(scanner: str, message: str) -> None:
        if quiet:
            return
        with lock:
            sys.stderr.write(f"\r\033[K[{scanner}] {message[:110]}" if sys.stderr.isatty() else f"[{scanner}] {message}\n")
            sys.stderr.flush()

    return cb


def _engine(cfg: Config):
    from aegis.core.engine import ScanEngine

    return ScanEngine(cfg)


# ----------------------------------------------------------------------------- scan

def cmd_scan(args, cfg: Config) -> int:
    if args.no_cache:
        cfg.use_cache = False
    if args.cloud:
        cfg.cloud_lookup = True
    if args.auto_quarantine:
        cfg.auto_quarantine = True
    for ex in args.exclude or []:
        cfg.exclusions.append(ex)
    engine = _engine(cfg)
    profile = args.profile
    scanners = [s.strip() for s in args.scanners.split(",")] if args.scanners else None
    if scanners and profile not in ("custom",) and not args.path:
        profile = "custom"
    if args.path and not scanners and profile == "quick":
        profile, scanners = "custom", ["files"]
    cancel = threading.Event()
    try:
        result = engine.scan(profile=profile, scanners=scanners, paths=[Path(p) for p in args.path or []] or None,
                             progress=_progress(args.quiet or args.json), cancel=cancel,
                             deep=True if args.deep else None)
    except KeyboardInterrupt:
        cancel.set()
        _print("\nScan cancelled.")
        return EXIT_ERROR
    except ValueError as exc:
        _print(f"error: {exc}")
        return EXIT_ERROR
    if sys.stderr.isatty() and not (args.quiet or args.json):
        sys.stderr.write("\r\033[K")
    return _finish(result, args, cfg)


def _finish(result: ScanResult, args, cfg: Config) -> int:
    from aegis.core.report import render_text, write_report

    min_sev = Severity.parse(args.min_severity)
    if args.json:
        _print(result.to_json())
    else:
        _print(render_text(result, color=_color(), verbose=args.verbose, min_severity=min_sev))
    if args.report:
        target = Path(args.report)
        if target.suffix == "" or target.is_dir() or args.report in ("html", "json", "csv", "txt"):
            fmt = args.report if args.report in ("html", "json", "csv", "txt") else "html"
            stamp = result.started.replace(":", "").replace("-", "")
            target = cfg.reports_dir / f"aegis-report-{stamp}.{fmt}"
        out = write_report(result, target)
        if not args.json:
            _print(f"\nReport written to {out}")
    if args.fix or args.auto_fix:
        _remediate(result, cfg, interactive=bool(args.fix), auto_min=Severity.parse(args.auto_fix) if args.auto_fix else None)
    fail_on = Severity.parse(args.fail_on)
    return EXIT_FINDINGS if any(f.severity >= fail_on for f in result.findings) else EXIT_CLEAN


def _remediate(result: ScanResult, cfg: Config, interactive: bool, auto_min: Optional[Severity]) -> None:
    from aegis.core.remediation import apply_remediation

    fixable = [f for f in result.sorted_findings() if f.remediation]
    if not fixable:
        _print("\nNo automatically fixable findings.")
        return
    _print(f"\n{len(fixable)} finding(s) have an automatic fix.")
    for f in fixable:
        if auto_min is not None:
            if f.severity < auto_min:
                continue
        elif interactive:
            desc = f.remediation.description or f.remediation.action
            ans = input(f"  Fix [{f.severity.name}] {f.title} @ {f.location}\n    -> {desc}? [y/N/q] ").strip().lower()
            if ans == "q":
                break
            if ans != "y":
                continue
        ok, msg = apply_remediation(f, cfg)
        _print(f"  {'OK ' if ok else 'ERR'} {msg}")


# ----------------------------------------------------------------------------- other commands

def cmd_fix(args, cfg: Config) -> int:
    from aegis.core.engine import last_scan
    from aegis.core.remediation import apply_remediation
    from aegis.core.report import finding_by_fingerprint

    result = ScanResult.from_dict(json.loads(Path(args.input).read_text(encoding="utf-8"))) if args.input else last_scan(cfg)
    if not result:
        _print("No scan results found. Run `aegis scan` first.")
        return EXIT_ERROR
    if args.id:
        rc = EXIT_CLEAN
        for fp in args.id:
            try:
                f = finding_by_fingerprint(result, fp)
            except KeyError:
                _print(f"no finding with id {fp}")
                rc = EXIT_ERROR
                continue
            ok, msg = apply_remediation(f, cfg)
            _print(f"{'OK ' if ok else 'ERR'} {f.title}: {msg}")
            rc = rc if ok else EXIT_ERROR
        return rc
    _remediate(result, cfg, interactive=not args.yes, auto_min=Severity.parse(args.min_severity) if args.yes else None)
    return EXIT_CLEAN


def cmd_allow(args, cfg: Config) -> int:
    for fp in args.id:
        if fp.lower() not in cfg.allowlist_fingerprints:
            cfg.allowlist_fingerprints.append(fp.lower())
    for h in args.hash or []:
        cfg.allowlist_hashes.append(h.lower())
    for p in args.path or []:
        cfg.exclusions.append(p)
    _print(f"Saved to {cfg.save()}")
    return EXIT_CLEAN


def cmd_quarantine(args, cfg: Config) -> int:
    from aegis.core.quarantine import Quarantine

    q = Quarantine(cfg)
    if args.action == "list":
        items = q.list()
        if not items:
            _print("Quarantine is empty.")
        for i in items:
            _print(f"{i.id}  {i.quarantined_at}  {i.size:>10}  {i.threat}\n    {i.original_path}")
    elif args.action == "add":
        for p in args.target:
            item = q.add(p, threat="manual")
            _print(f"Quarantined {item.original_path} as {item.id}")
    elif args.action == "restore":
        for t in args.target:
            _print(f"Restored to {q.restore(t, to=args.to, overwrite=args.force)}")
    elif args.action == "delete":
        for t in args.target:
            q.delete(t)
            _print(f"Deleted {t}")
    return EXIT_CLEAN


def cmd_update(args, cfg: Config) -> int:
    from aegis.tools.updater import update_signatures

    res = update_signatures(cfg, progress=lambda name, msg: _print(f"[{name}] {msg}") if not args.quiet else None)
    bad = 0
    for feed, info in res.items():
        status = "OK " if info.get("ok") else "ERR"
        bad += 0 if info.get("ok") else 1
        _print(f"{status} {feed:<28} {info.get('count', 0):>8} entries  {info.get('error', '')}")
    # Re-apply web/IP protection (if switched on) with the fresh threat intelligence.
    try:
        from aegis.core.signatures import SignatureDB
        from aegis.protect.webguard import refresh_protections

        for kind, r in refresh_protections(cfg, SignatureDB(cfg)).items():
            if r.get("changed") or not r.get("ok"):
                _print(f"{'OK ' if r.get('ok') else 'ERR'} protection:{kind:<17} {r.get('message', '')}")
    except Exception as exc:  # protections are optional; never fail the update because of them
        _print(f"ERR protection refresh failed: {exc}")
    return EXIT_CLEAN if bad < len(res) else EXIT_ERROR


def _print_result(r: dict) -> int:
    _print(("OK  " if r.get("ok") else "ERR ") + str(r.get("message", "")))
    for k, v in (r.get("details") or {}).items():
        if isinstance(v, (str, int, float, bool)) or v is None:
            _print(f"    {k}: {v}")
    return EXIT_CLEAN if r.get("ok") else EXIT_ERROR


def cmd_history(args, cfg: Config) -> int:
    from aegis.core import history

    if args.action == "show":
        if not args.ids:
            _print("usage: aegis history show ID")
            return EXIT_ERROR
        res = history.get_scan(cfg, int(args.ids[0]))
        if not res:
            _print(f"no scan {args.ids[0]}")
            return EXIT_ERROR
        from aegis.core.report import render_text

        _print(render_text(res, color=_color(), verbose=args.verbose))
        return EXIT_CLEAN
    if args.action == "diff":
        if len(args.ids) >= 2:
            old, new = history.get_scan(cfg, int(args.ids[0])), history.get_scan(cfg, int(args.ids[1]))
            if not old or not new:
                _print("scan not found")
                return EXIT_ERROR
            d = history.diff(old, new)
        else:
            cmp = history.compare_latest(cfg, profile=args.profile)
            if not cmp:
                _print("Need at least two scans of the same kind to compare.")
                return EXIT_CLEAN
            d = cmp["diff"]
        _print(history.render_diff_text(d))
        return EXIT_FINDINGS if d.get("new") else EXIT_CLEAN
    if args.action == "trend":
        rows = history.trend(cfg, profile=args.profile, days=args.days)
        if args.json:
            _print(json.dumps(rows))
            return EXIT_CLEAN
        for day, score in rows:
            _print(f"{day}  {score:>3}  " + "#" * (score // 4))
        if not rows:
            _print("No scans recorded yet.")
        return EXIT_CLEAN
    scans = history.list_scans(cfg, limit=args.limit, profile=args.profile)
    if args.json:
        _print(json.dumps([s.to_dict() for s in scans], indent=2, default=str))
        return EXIT_CLEAN
    if not scans:
        _print("No scans recorded yet.")
    def num(v) -> str:  # first scan of a profile has no baseline -> no new/resolved counts
        return "-" if v is None else str(v)

    for sc in scans:
        d = sc.to_dict()
        _print(f"#{num(d.get('id')):<5} {d.get('started', '')}  {d.get('profile', ''):<7} score {num(d.get('score')):>3} "
               f"({d.get('grade') or '?'})  findings {num(d.get('finding_count')):>3}  new {num(d.get('new_findings')):>3}  "
               f"resolved {num(d.get('resolved_findings')):>3}")
    return EXIT_CLEAN


def cmd_doctor(args, cfg: Config) -> int:
    from aegis.core import doctor

    results = doctor.doctor(cfg)
    if args.json:
        _print(json.dumps([r.to_dict() for r in results], indent=2, default=str))
    else:
        _print(doctor.render_doctor(results, color=_color()))
    if args.fix:
        for fix_id, ok, msg in doctor.apply_fixes(cfg, results):
            _print(f"{'OK ' if ok else 'ERR'} fix {fix_id}: {msg}")
    return EXIT_FINDINGS if doctor.has_failures(results) else EXIT_CLEAN


def cmd_alert(args, cfg: Config) -> int:
    from aegis.core import alerts

    channels = alerts.configured_channels(cfg)
    problems = alerts.validate_config(cfg)
    if args.action == "status":
        _print("Configured channels: " + (", ".join(channels) if channels else "none"))
        _print(f"Alert on: {cfg.alert_on} findings at/above {cfg.alert_min_severity}")
        for p in problems:
            _print(f"  problem: {p}")
        return EXIT_ERROR if problems else EXIT_CLEAN
    if not channels:
        _print("No alert channel configured. Set one, e.g.: aegis config set alert_slack_webhook https://hooks.slack.com/...")
        return EXIT_ERROR
    res = alerts.test_alert(cfg)
    for ch, r in res.items():
        _print(f"{'OK ' if r.get('ok') else 'ERR'} {ch:<10} {r.get('error') or 'sent'}")
    return EXIT_CLEAN if all(r.get("ok") for r in res.values()) else EXIT_ERROR


def cmd_sigma(args, cfg: Config) -> int:
    from aegis.core import sigma

    if args.action == "test":
        if len(args.paths) != 2:
            _print("usage: aegis sigma test RULE_OR_DIR EVENTS.json")
            return EXIT_ERROR
        r = sigma.test_rule_on_events(args.paths[0], args.paths[1])
        _print(json.dumps(r, indent=2, default=str))
        return EXIT_FINDINGS if r.get("matches") else (EXIT_CLEAN if r.get("ok") else EXIT_ERROR)
    rules = sigma.load_rules(cfg)
    if not rules.available:
        _print("Sigma support needs PyYAML: pip install pyyaml (included in the packaged exe).")
        return EXIT_ERROR
    _print(json.dumps(rules.summary(), indent=2, default=str))
    return EXIT_CLEAN


def cmd_protect(args, cfg: Config) -> int:
    from aegis.protect import webguard as wg

    if args.what == "web":
        if args.action == "status":
            return _print_result(wg.web_protection_status(cfg))
        if args.action == "off":
            return _print_result(wg.disable_web_protection(cfg, dry_run=args.dry_run))
        from aegis.core.signatures import SignatureDB

        return _print_result(wg.enable_web_protection(cfg, SignatureDB(cfg), dry_run=args.dry_run))
    if args.action == "status":
        return _print_result(wg.ip_blocking_status(cfg))
    if args.action == "off":
        return _print_result(wg.disable_ip_blocking(cfg, dry_run=args.dry_run))
    from aegis.core.signatures import SignatureDB

    return _print_result(wg.enable_ip_blocking(cfg, SignatureDB(cfg), dry_run=args.dry_run))


def cmd_harden(args, cfg: Config) -> int:
    from aegis.protect import harden

    if args.list:
        for a in harden.describe_catalogue():
            d = a if isinstance(a, dict) else getattr(a, "__dict__", {})
            _print(f"{d.get('id', ''):<28} {d.get('title', '')}")
        return EXIT_CLEAN
    options = {}
    if args.asr_mode:
        options["asr_mode"] = {"audit": "AuditMode", "block": "Enabled", "warn": "Warn"}[args.asr_mode]
    only = [x.strip() for x in args.only.split(",")] if args.only else None
    try:
        items = harden.plan("custom" if only else args.profile, only=only, options=options or None)
    except ValueError as exc:
        _print(f"error: {exc}")
        return EXIT_ERROR
    labels = {"compliant": "ok      ", "will_change": "CHANGE  ", "not_applicable": "n/a     ", "needs_admin": "ADMIN   "}
    for it in items:
        d = it.to_dict()
        _print(f"  {labels.get(d.get('state'), d.get('state', ''))} {d.get('id', ''):<28} {d.get('title', '')}")
        if d.get("state") == "will_change" and d.get("detail"):
            _print(f"           {d['detail']}")
    pending = [it for it in items if it.to_dict().get("state") == "will_change"]
    if not args.apply:
        _print(f"\n{len(pending)} change(s) planned. Re-run with --apply to make them (every change can be undone "
               f"with `aegis undo latest`).")
        return EXIT_CLEAN
    if not pending:
        _print("\nNothing to change.")
        return EXIT_CLEAN
    r = harden.apply(items, cfg, options=options or None, profile="custom" if only else args.profile)
    rc = _print_result(r)
    for res in r.get("results", []):
        res = res if isinstance(res, dict) else getattr(res, "__dict__", {})
        _print(f"    {'OK ' if res.get('ok') else 'ERR'} {res.get('id', '')}: {res.get('message', '')}")
    if r.get("journal"):
        _print(f"\nUndo journal: {r['journal']}  (revert with `aegis undo latest`)")
    if r.get("reboot_required"):
        _print("A restart is required for some changes to take effect.")
    return rc


def cmd_undo(args, cfg: Config) -> int:
    from aegis.protect import undo

    if args.target in (None, "list"):
        rows = undo.list_backups(cfg)
        if not rows:
            _print("No backups yet.")
        for b in rows:
            state = "undone" if b.get("undone") else ("" if b.get("undoable") else "not undoable")
            _print(f"{b['id']:<44} {b.get('kind', ''):<9} {b.get('timestamp', '')}  {b.get('summary', '')}  {state}")
        return EXIT_CLEAN
    r = undo.undo(cfg, args.target, dry_run=args.dry_run, force=args.force, restore_to=args.to)
    rc = _print_result(r)
    for res in r.get("results", []):
        res = res if isinstance(res, dict) else getattr(res, "__dict__", {})
        _print(f"    {'OK ' if res.get('ok') else 'ERR'} {res.get('message', res)}")
    if r.get("reboot_required"):
        _print("A restart is required for some changes to take effect.")
    return rc


def cmd_check_url(args, cfg: Config) -> int:
    from aegis.core.signatures import SignatureDB
    from aegis.tools.urlcheck import check_url

    sigs = SignatureDB(cfg)
    worst = EXIT_CLEAN
    for url in args.url:
        r = check_url(url, signatures=sigs, config=cfg)
        if args.json:
            _print(json.dumps(r, indent=2))
        else:
            _print(f"{r['verdict'].upper():<10} score {r['score']:>3}  {url}")
            for reason in r.get("reasons", []):
                _print(f"    - {reason}")
        if r["verdict"] != "safe":
            worst = EXIT_FINDINGS
    return worst


def cmd_check_password(args, cfg: Config) -> int:
    from aegis.tools.password import check_password

    pw = sys.stdin.readline().rstrip("\r\n") if args.stdin else getpass.getpass("Password to check (input hidden): ")
    r = check_password(pw, online=not args.offline)
    labels = ["very weak", "weak", "fair", "strong", "very strong"]
    _print(f"Strength: {labels[r['strength']]} ({r['entropy_bits']:.0f} bits)")
    if r.get("pwned_count") is None:
        _print(f"Breach check: unavailable{(' - ' + r['online_error']) if r.get('online_error') else ''}")
    elif r["pwned_count"]:
        _print(f"BREACHED: this password appears {r['pwned_count']:,} times in known data breaches. Do not use it.")
    else:
        _print("Breach check: not found in known breaches (Have I Been Pwned, k-anonymity - your password never left this PC).")
    for tip in r.get("feedback", []):
        _print(f"  - {tip}")
    return EXIT_FINDINGS if (r.get("pwned_count") or r["strength"] < 2) else EXIT_CLEAN


def cmd_check_file(args, cfg: Config) -> int:
    from aegis.core import fileanalysis as fa
    from aegis.core.signatures import SignatureDB
    from aegis.scanners.base import ScanContext
    from aegis.scanners.files import defender_scan, hash_file, scan_file

    if args.cloud:
        cfg.cloud_lookup = True
    cfg.use_windows_defender_engine = False  # run it explicitly below for every file
    ctx = ScanContext(config=cfg, signatures=SignatureDB(cfg), deep=True)
    worst = EXIT_CLEAN
    for p in map(Path, args.file):
        if not p.is_file():
            _print(f"{p}: not a file")
            worst = EXIT_ERROR
            continue
        sha256, sha1, md5 = hash_file(p)
        data = p.read_bytes()[:32 * 1024 * 1024]
        kind = fa.classify(data[:4096], p.suffix.lower().lstrip("."))
        info = {"file": str(p), "size": p.stat().st_size, "type": kind, "sha256": sha256, "sha1": sha1, "md5": md5,
                "entropy": round(fa.entropy(data[:4 * 1024 * 1024]), 3)}
        if kind == "pe":
            pe = fa.parse_pe(data)
            info["pe"] = {"64bit": pe.is_64, "dll": pe.is_dll, "signed": pe.has_signature, "dotnet": pe.has_dotnet,
                          "timestamp": pe.timestamp, "overlay": pe.overlay_size,
                          "sections": [{"name": s.name, "entropy": s.entropy, "raw_size": s.raw_size} for s in pe.sections],
                          "imports": {k: len(v) for k, v in pe.imports.items()}}
        findings = scan_file(ctx, p)
        info["findings"] = [f.to_dict() for f in findings]
        threat = defender_scan(p)
        if threat:
            info["microsoft_defender"] = threat
        if cfg.cloud_lookup and cfg.virustotal_api_key:
            try:
                from aegis.tools.reputation import virustotal_lookup

                info["virustotal"] = virustotal_lookup(sha256, cfg.virustotal_api_key)
            except Exception as exc:
                info["virustotal_error"] = str(exc)
        if args.json:
            _print(json.dumps(info, indent=2, default=str))
        else:
            _print(f"{p}\n  type {kind}, {info['size']} bytes, entropy {info['entropy']}\n  sha256 {sha256}\n  md5    {md5}")
            if "pe" in info:
                pi = info["pe"]
                _print(f"  PE: {'64' if pi['64bit'] else '32'}-bit {'DLL' if pi['dll'] else 'EXE'}, "
                       f"{'signed' if pi['signed'] else 'UNSIGNED'}{', .NET' if pi['dotnet'] else ''}, "
                       f"sections: {', '.join(s['name'] + '(' + str(s['entropy']) + ')' for s in pi['sections'])}")
            if threat:
                _print(f"  Microsoft Defender: {threat}")
            if info.get("virustotal"):
                vt = info["virustotal"]
                _print(f"  VirusTotal: {vt.get('malicious', 0)}/{vt.get('total', 0)} malicious  {vt.get('link', '')}")
            if not findings:
                _print("  Verdict: no detections")
            for f in findings:
                _print(f"  [{f.severity.name}] {f.title}")
                for ind in f.evidence.get("indicators", []):
                    _print(f"      - {ind['title']} {('(' + ind['detail'] + ')') if ind.get('detail') else ''}")
        if findings or threat:
            worst = max(worst, EXIT_FINDINGS)
    return worst


def cmd_check_project(args, cfg: Config) -> int:
    from aegis.core.models import ScanResult
    from aegis.core.platform import host_info
    from aegis.core.signatures import SignatureDB
    from aegis.scanners.base import ScanContext
    from aegis.scanners.supplychain import scan_project_results

    ctx = ScanContext(config=cfg, signatures=SignatureDB(cfg))
    if args.offline:
        ctx.options["supplychain_online"] = False
    import time as _time

    t0 = _time.time()
    result = ScanResult(profile="custom", host=host_info(), scanners=["supplychain"])
    for path in args.path:
        findings, checks = scan_project_results(path, ctx)
        for f in findings:
            result.add(f)
        result.checks.extend(checks)
    result.stats = dict(ctx.stats)
    result.stats["duration_s"] = round(_time.time() - t0, 2)
    return _finish(result, args, cfg)


def cmd_autoruns(args, cfg: Config) -> int:
    from aegis.scanners.persistence import collect_entries

    entries = collect_entries()
    if args.json:
        _print(json.dumps(entries, indent=2, default=str))
        return EXIT_CLEAN
    for e in entries:
        _print(f"[{e.get('type', '?')}] {e.get('name', '')}\n    {e.get('command', '')}\n    @ {e.get('location', '')}")
    _print(f"\n{len(entries)} autostart entries.")
    return EXIT_CLEAN


def cmd_monitor(args, cfg: Config) -> int:
    from aegis.core.signatures import SignatureDB
    from aegis.realtime.monitor import RealtimeMonitor

    if args.auto_quarantine:
        cfg.auto_quarantine = True
    if args.kill:
        cfg.realtime_kill_malicious_processes = True

    def on_event(f) -> None:
        _print(f"[{f.timestamp}] {f.severity.name:<8} {f.title}  {f.location}")

    _print(f"{__app_name__} real-time protection running. Press Ctrl+C to stop.")
    RealtimeMonitor(cfg, SignatureDB(cfg), on_event=on_event).run_forever()
    return EXIT_CLEAN


def cmd_integrity(args, cfg: Config) -> int:
    from aegis.tools.integrity import compare_baseline, create_baseline

    if args.action == "baseline":
        b = create_baseline(cfg, paths=args.path or None)
        _print(f"Baseline saved with {len(b.get('files', b))} files.")
        return EXIT_CLEAN
    findings = compare_baseline(cfg)
    for f in findings:
        _print(f"[{f.severity.name}] {f.title}: {f.location}")
    if not findings:
        _print("No changes since baseline.")
    return EXIT_FINDINGS if findings else EXIT_CLEAN


def cmd_report(args, cfg: Config) -> int:
    from aegis.core.engine import last_scan
    from aegis.core.report import write_report

    result = ScanResult.from_dict(json.loads(Path(args.input).read_text(encoding="utf-8"))) if args.input else last_scan(cfg)
    if not result:
        _print("No scan results found.")
        return EXIT_ERROR
    _print(f"Report written to {write_report(result, args.output)}")
    return EXIT_CLEAN


def cmd_info(args, cfg: Config) -> int:
    from aegis.core.engine import ScanEngine, last_scan
    from aegis.core.signatures import HAVE_YARA

    eng = ScanEngine(cfg)
    info = {
        "version": __version__,
        "host": host_info(),
        "data_dir": str(cfg.home),
        "yara_engine": HAVE_YARA,
        "signatures": eng.signatures.summary(),
        "scanners": eng.available_scanners(),
    }
    last = last_scan(cfg)
    if last:
        d = last.to_dict()
        info["last_scan"] = {"profile": d["profile"], "finished": d["finished"], "score": d["score"], "grade": d["grade"],
                             "counts": d["counts"]}
    if args.json:
        _print(json.dumps(info, indent=2, default=str))
        return EXIT_CLEAN
    _print(f"{__app_name__} {__version__}")
    h = info["host"]
    _print(f"Host: {h['hostname']} - {h['platform']} - admin: {h['admin']}")
    _print(f"Data directory: {info['data_dir']}")
    _print(f"YARA engine: {'available' if HAVE_YARA else 'not installed (pip install yara-python) - Aegis-Lite rules active'}")
    _print("Signatures: " + ", ".join(f"{k}={v}" for k, v in info["signatures"].items()))
    _print("Scanners:")
    for name, desc in info["scanners"].items():
        _print(f"  {name:<14} {desc}")
    if last:
        ls = info["last_scan"]
        _print(f"Last scan: {ls['profile']} at {ls['finished']} - score {ls['score']} ({ls['grade']})")
    return EXIT_CLEAN


def cmd_config(args, cfg: Config) -> int:
    from dataclasses import asdict

    if args.action == "show":
        d = asdict(cfg)
        try:
            from aegis.core.alerts import SECRET_FIELDS
        except Exception:
            SECRET_FIELDS = ()
        for k in ("virustotal_api_key", "abusech_auth_key", "google_safebrowsing_api_key", *SECRET_FIELDS):
            if d.get(k):
                d[k] = str(d[k])[:4] + "****"
        _print(json.dumps(d, indent=2))
        _print(f"\n(file: {cfg.path})")
        return EXIT_CLEAN
    key, value = args.key, args.value
    if key not in Config.__dataclass_fields__:
        _print(f"unknown setting {key}")
        return EXIT_ERROR
    current = getattr(cfg, key)
    if isinstance(current, bool):
        new = value.lower() in ("1", "true", "yes", "on")
    elif isinstance(current, int):
        new = int(value)
    elif isinstance(current, list):
        new = [v for v in value.split(";") if v]
    else:
        new = value
    setattr(cfg, key, new)
    _print(f"{key} = {new!r}  (saved to {cfg.save()})")
    return EXIT_CLEAN


def cmd_gui(args, cfg: Config) -> int:
    from aegis.ui.gui import launch_gui

    launch_gui()
    return EXIT_CLEAN


def cmd_service(args, cfg: Config) -> int:
    from aegis.core import service

    actions = service.install_service(cfg) if args.command == "install-service" else service.uninstall_service()
    for a in actions:
        _print(f"  - {a}")
    return EXIT_CLEAN


# ----------------------------------------------------------------------------- parser

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="aegis",
        description=f"{__app_name__} {__version__} - anti-malware, threat detection and security audit toolkit.",
        epilog="Examples:\n  aegis scan quick\n  aegis scan full --report html\n  aegis scan --path D:\\Downloads\n"
               "  aegis audit\n  aegis scan custom --scanners browser,network\n  aegis fix\n  aegis monitor\n"
               "  aegis check-url https://example.com\n  aegis update",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("-v", "--verbose", action="store_true", help="verbose output and debug logging")
    sub = p.add_subparsers(dest="command", metavar="<command>")

    def output_opts(sp):
        sp.add_argument("--report", metavar="PATH|FORMAT", help="write a report (file path ending .html/.json/.csv/.txt, or just a format)")
        sp.add_argument("--json", action="store_true", help="print JSON instead of text")
        sp.add_argument("--min-severity", default="low", choices=["info", "low", "medium", "high", "critical"],
                        help="hide console findings below this severity (default: low)")
        sp.add_argument("--fail-on", default="high", choices=["info", "low", "medium", "high", "critical"],
                        help="exit code 1 when findings at/above this severity exist (default: high)")
        sp.add_argument("--fix", action="store_true", help="interactively apply available fixes after the scan")
        sp.add_argument("--auto-fix", metavar="SEVERITY", choices=["low", "medium", "high", "critical"],
                        help="apply fixes without asking for findings at/above SEVERITY")
        sp.add_argument("-q", "--quiet", action="store_true", help="no progress output")
        sp.add_argument("-v", "--verbose", action="store_true", help="show descriptions, evidence and all checks")

    s = sub.add_parser("scan", help="run a scan (quick | full | audit | custom)")
    s.add_argument("profile", nargs="?", default="quick", choices=["quick", "full", "audit", "custom"])
    s.add_argument("--path", action="append", help="file or folder to scan (repeatable)")
    s.add_argument("--scanners", help="comma-separated scanners: files,processes,persistence,browser,network,"
                   "system_audit,software,secrets,eventlog,drivers,sideload,usb,email,memory (see `aegis info`)")
    s.add_argument("--exclude", action="append", help="path prefix or glob to skip (repeatable)")
    s.add_argument("--deep", action="store_true", help="content-scan every file type, not only risky ones")
    s.add_argument("--no-cache", action="store_true", help="ignore the clean-file cache")
    s.add_argument("--cloud", action="store_true", help="look up suspicious hashes on VirusTotal (needs API key)")
    s.add_argument("--auto-quarantine", action="store_true", help="quarantine high-severity files automatically")
    output_opts(s)
    s.set_defaults(func=cmd_scan)

    a = sub.add_parser("audit", help="security hardening audit (system, software, network, browser)")
    output_opts(a)
    a.set_defaults(func=cmd_scan, profile="audit", path=None, scanners=None, exclude=None, deep=False, no_cache=False,
                   cloud=False, auto_quarantine=False)

    f = sub.add_parser("fix", help="apply fixes for findings from the last scan (or --input JSON)")
    f.add_argument("--id", action="append", help="finding id (fingerprint shown in brackets); repeatable")
    f.add_argument("--input", help="scan result JSON (default: last scan)")
    f.add_argument("-y", "--yes", action="store_true", help="don't ask; fix everything at/above --min-severity")
    f.add_argument("--min-severity", default="high", choices=["low", "medium", "high", "critical"])
    f.set_defaults(func=cmd_fix)

    al = sub.add_parser("allow", help="allow-list findings, hashes or paths so they are no longer reported")
    al.add_argument("--id", action="append", default=[], help="finding id to suppress")
    al.add_argument("--hash", action="append", help="SHA-256 to trust")
    al.add_argument("--path", action="append", help="path prefix or glob to exclude from scans")
    al.set_defaults(func=cmd_allow)

    q = sub.add_parser("quarantine", help="list / restore / delete / add quarantined files")
    q.add_argument("action", choices=["list", "restore", "delete", "add"])
    q.add_argument("target", nargs="*", help="quarantine id(s), or file path(s) for add")
    q.add_argument("--to", help="restore to a different path")
    q.add_argument("--force", action="store_true", help="overwrite on restore")
    q.set_defaults(func=cmd_quarantine)

    u = sub.add_parser("update", help="download latest threat intelligence (hashes, C2 IPs, malicious URLs/extensions, YARA)")
    u.add_argument("-q", "--quiet", action="store_true")
    u.set_defaults(func=cmd_update)

    m = sub.add_parser("monitor", help="real-time protection: file, process, ransomware and persistence guards")
    m.add_argument("--auto-quarantine", action="store_true", help="quarantine detected files automatically")
    m.add_argument("--kill", action="store_true", help="terminate confirmed-malicious processes automatically")
    m.set_defaults(func=cmd_monitor)

    cu = sub.add_parser("check-url", help="phishing / malicious URL analysis")
    cu.add_argument("url", nargs="+")
    cu.add_argument("--json", action="store_true")
    cu.set_defaults(func=cmd_check_url)

    cp = sub.add_parser("check-password", help="password strength + breach check (k-anonymity, password never sent)")
    cp.add_argument("--stdin", action="store_true", help="read the password from stdin")
    cp.add_argument("--offline", action="store_true", help="skip the online breach check")
    cp.set_defaults(func=cmd_check_password)

    cf = sub.add_parser("check-file", help="deep static analysis of specific files")
    cf.add_argument("file", nargs="+")
    cf.add_argument("--cloud", action="store_true", help="include VirusTotal reputation (needs API key)")
    cf.add_argument("--json", action="store_true")
    cf.set_defaults(func=cmd_check_file)

    cpj = sub.add_parser("check-project", help="supply-chain check of code projects: malicious / vulnerable "
                         "dependencies (OSV.dev), install-script droppers, typosquats, Shai-Hulud worm")
    cpj.add_argument("path", nargs="+", help="project folder(s) or lockfile(s)")
    cpj.add_argument("--offline", action="store_true", help="no OSV.dev lookups (local heuristics + cache only)")
    output_opts(cpj)
    cpj.set_defaults(func=cmd_check_project)

    ar = sub.add_parser("autoruns", help="list every autostart / persistence entry (like Sysinternals Autoruns)")
    ar.add_argument("--json", action="store_true")
    ar.set_defaults(func=cmd_autoruns)

    it = sub.add_parser("integrity", help="file integrity monitoring: create a baseline or check against it")
    it.add_argument("action", choices=["baseline", "check"])
    it.add_argument("--path", action="append", help="extra paths for the baseline")
    it.set_defaults(func=cmd_integrity)

    r = sub.add_parser("report", help="render the last (or a given) scan as HTML/JSON/CSV/TXT")
    r.add_argument("output", help="output file (.html, .json, .csv, .txt)")
    r.add_argument("--input", help="scan result JSON (default: last scan)")
    r.set_defaults(func=cmd_report)

    i = sub.add_parser("info", help="show version, environment, signatures and scanners")
    i.add_argument("--json", action="store_true")
    i.set_defaults(func=cmd_info)

    hi = sub.add_parser("history", help="past scans, what changed since the previous scan, and score trend")
    hi.add_argument("action", nargs="?", default="list", choices=["list", "show", "diff", "trend"])
    hi.add_argument("ids", nargs="*", help="scan id(s) for show / diff")
    hi.add_argument("--profile", help="only scans of this profile (quick, full, audit, custom)")
    hi.add_argument("--limit", type=int, default=20)
    hi.add_argument("--days", type=int, default=90)
    hi.add_argument("--json", action="store_true")
    hi.add_argument("-v", "--verbose", action="store_true")
    hi.set_defaults(func=cmd_history)

    dr = sub.add_parser("doctor", help="self-check: privileges, signature freshness, data-folder permissions, services")
    dr.add_argument("--fix", action="store_true", help="apply the safe fixes (folder permissions, signature update)")
    dr.add_argument("--json", action="store_true")
    dr.set_defaults(func=cmd_doctor)

    al = sub.add_parser("alert", help="Slack / Teams / Discord / webhook / email alerts")
    al.add_argument("action", choices=["status", "test"])
    al.set_defaults(func=cmd_alert)

    sg = sub.add_parser("sigma", help="Sigma detection rules: list what's loaded, or test rules against events")
    sg.add_argument("action", choices=["list", "test"])
    sg.add_argument("paths", nargs="*", help="for test: RULE_OR_DIR EVENTS.json")
    sg.set_defaults(func=cmd_sigma)

    pr = sub.add_parser("protect", help="web protection (malicious-domain blocklist) and C2 IP blocking")
    pr.add_argument("what", choices=["web", "ips"], help="web = hosts-file domain blocklist, ips = firewall block rules")
    pr.add_argument("action", choices=["on", "off", "status"])
    pr.add_argument("--dry-run", action="store_true", help="show what would change")
    pr.set_defaults(func=cmd_protect)

    hd = sub.add_parser("harden", help="plan or apply recommended security settings (reversible with `aegis undo`)")
    hd.add_argument("--profile", default="recommended", choices=["recommended", "strict"])
    hd.add_argument("--only", help="comma-separated action ids (see --list)")
    hd.add_argument("--asr-mode", choices=["audit", "block", "warn"], help="attack surface reduction rule mode")
    hd.add_argument("--apply", action="store_true", help="make the changes (default: show the plan only)")
    hd.add_argument("--list", action="store_true", help="list every hardening action")
    hd.set_defaults(func=cmd_harden)

    ud = sub.add_parser("undo", help="list backups or revert a fix / hardening run / protection change")
    ud.add_argument("target", nargs="?", help="'list' (default), 'latest', or a backup id")
    ud.add_argument("--dry-run", action="store_true")
    ud.add_argument("--force", action="store_true", help="undo even if already undone or the system changed since")
    ud.add_argument("--to", help="destination folder (for restoring removed folders)")
    ud.set_defaults(func=cmd_undo)

    c = sub.add_parser("config", help="show or change settings")
    c.add_argument("action", choices=["show", "set"])
    c.add_argument("key", nargs="?")
    c.add_argument("value", nargs="?")
    c.set_defaults(func=cmd_config)

    g = sub.add_parser("gui", help="open the desktop application")
    g.set_defaults(func=cmd_gui)

    for name, hlp in (("install-service", "schedule real-time protection, daily scans and signature updates"),
                      ("uninstall-service", "remove the scheduled tasks / services")):
        sp = sub.add_parser(name, help=hlp)
        sp.set_defaults(func=cmd_service)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    import os

    # Windowed builds (aegis-gui.exe running background tasks) have no console streams.
    if sys.stdout is None:
        sys.stdout = open(os.devnull, "w", encoding="utf-8")
    if sys.stderr is None:
        sys.stderr = open(os.devnull, "w", encoding="utf-8")
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return EXIT_CLEAN
    if args.command == "config" and args.action == "set" and (not args.key or args.value is None):
        parser.error("config set needs KEY VALUE")
    cfg = Config.load()
    setup_logging(cfg, verbose=getattr(args, "verbose", False))
    try:
        return args.func(args, cfg)
    except KeyboardInterrupt:
        return EXIT_ERROR
    except (FileNotFoundError, KeyError, FileExistsError, PermissionError) as exc:
        _print(f"error: {exc}")
        return EXIT_ERROR


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
