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
    return EXIT_CLEAN if bad < len(res) else EXIT_ERROR


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
        for k in ("virustotal_api_key", "abusech_auth_key", "google_safebrowsing_api_key"):
            if d.get(k):
                d[k] = d[k][:4] + "****"
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
