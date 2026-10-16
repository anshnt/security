"""Configuration and on-disk layout.

Data directory (signatures updates, quarantine, logs, reports, caches):
  Windows (admin):   %ProgramData%\\Aegis
  Windows (user):    %LOCALAPPDATA%\\Aegis
  Linux/macOS:       ~/.local/share/aegis   (or /var/lib/aegis as root)
Override with the AEGIS_HOME environment variable.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from aegis.core.platform import IS_WINDOWS, is_admin

log = logging.getLogger("aegis.config")

PACKAGE_DATA = Path(__file__).resolve().parent.parent / "data"


def data_home() -> Path:
    override = os.environ.get("AEGIS_HOME")
    if override:
        base = Path(override)
    elif IS_WINDOWS:
        if is_admin() and os.environ.get("ProgramData"):
            base = Path(os.environ["ProgramData"]) / "Aegis"
        else:
            base = Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local"))) / "Aegis"
    else:
        base = Path("/var/lib/aegis") if is_admin() else Path.home() / ".local" / "share" / "aegis"
    base.mkdir(parents=True, exist_ok=True)
    return base


def shared_signatures_dir() -> Optional[Path]:
    """Machine-wide signature directory maintained by the elevated update task
    (%ProgramData%\\Aegis\\signatures). Non-admin sessions (e.g. the GUI) read it
    in addition to their own, so they benefit from scheduled updates."""
    if not IS_WINDOWS or not os.environ.get("ProgramData"):
        return None
    p = Path(os.environ["ProgramData"]) / "Aegis" / "signatures"
    return p if p.is_dir() else None


@dataclass
class Config:
    # Scanning
    max_file_size_mb: int = 100  # files larger than this are hashed only
    archive_max_depth: int = 2
    archive_max_members: int = 500
    scan_threads: int = max(2, min(8, (os.cpu_count() or 4)))
    follow_symlinks: bool = False
    use_cache: bool = True
    exclusions: List[str] = field(default_factory=list)  # path prefixes or glob patterns
    allowlist_hashes: List[str] = field(default_factory=list)
    allowlist_fingerprints: List[str] = field(default_factory=list)  # suppressed findings

    # Protection
    auto_quarantine: bool = False
    auto_quarantine_min_severity: str = "high"
    realtime_watch_dirs: List[str] = field(default_factory=list)  # empty = defaults
    realtime_kill_malicious_processes: bool = False
    realtime_clipboard_guard: bool = True  # ClickFix / fake-CAPTCHA commands and crypto address swaps (checked in memory only)
    realtime_clear_malicious_clipboard: bool = True  # and empty the clipboard when the command carries the lure text
    realtime_extension_guard: bool = True  # alert when a browser extension is installed (rated with the browser scanner's rules)
    ransomware_canaries: bool = True
    notifications: bool = True

    # Cloud / threat intel (all optional, keys stay local)
    virustotal_api_key: str = ""
    abusech_auth_key: str = ""
    google_safebrowsing_api_key: str = ""
    cloud_lookup: bool = False  # send SHA-256 of suspicious files to VirusTotal
    use_windows_defender_engine: bool = True  # second opinion via MpCmdRun if present

    # Reporting
    report_dir: str = ""

    # Outbound alerts (aegis.core.alerts). Opt-in: nothing is sent unless a channel below is configured.
    alert_webhook_url: str = ""  # generic JSON POST
    alert_slack_webhook: str = ""
    alert_teams_webhook: str = ""  # Teams Workflows / Power Automate "when a webhook request is received"
    alert_discord_webhook: str = ""
    alert_email_smtp_host: str = ""
    alert_email_smtp_port: int = 587
    alert_email_smtp_user: str = ""
    alert_email_smtp_password: str = ""  # env AEGIS_SMTP_PASSWORD overrides (keeps it off disk)
    alert_email_from: str = ""
    alert_email_to: str = ""  # one or more addresses separated by comma or semicolon
    alert_email_starttls: bool = True
    alert_min_severity: str = "high"  # info | low | medium | high | critical
    alert_on: str = "new"  # "new": only findings that appeared since the previous comparable scan; "all"

    @property
    def home(self) -> Path:
        return data_home()

    @property
    def path(self) -> Path:
        return self.home / "config.json"

    def save(self) -> Path:
        self.path.write_text(json.dumps(asdict(self), indent=2), encoding="utf-8")
        if not IS_WINDOWS:  # may hold API keys / webhook URLs / SMTP password: owner-only
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass
        return self.path

    @classmethod
    def load(cls, path: Optional[Path] = None) -> "Config":
        cfg = cls()
        p = path or cfg.path
        if p.exists():
            try:
                raw: Dict[str, Any] = json.loads(p.read_text(encoding="utf-8"))
                known = set(cls.__dataclass_fields__)
                for k, v in raw.items():
                    if k in known:
                        setattr(cfg, k, v)
            except Exception as exc:
                log.warning("could not read config %s: %s", p, exc)
        # Environment overrides for secrets so they never need to touch disk.
        cfg.virustotal_api_key = os.environ.get("AEGIS_VT_API_KEY", cfg.virustotal_api_key)
        cfg.abusech_auth_key = os.environ.get("AEGIS_ABUSECH_KEY", cfg.abusech_auth_key)
        cfg.google_safebrowsing_api_key = os.environ.get("AEGIS_GSB_API_KEY", cfg.google_safebrowsing_api_key)
        return cfg

    def subdir(self, name: str) -> Path:
        p = self.home / name
        p.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def quarantine_dir(self) -> Path:
        return self.subdir("quarantine")

    @property
    def signatures_dir(self) -> Path:
        return self.subdir("signatures")

    @property
    def reports_dir(self) -> Path:
        return Path(self.report_dir) if self.report_dir else self.subdir("reports")

    @property
    def backups_dir(self) -> Path:
        return self.subdir("backups")

    @property
    def logs_dir(self) -> Path:
        return self.subdir("logs")


def setup_logging(cfg: Config, verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    root = logging.getLogger("aegis")
    root.setLevel(logging.DEBUG)
    if not any(isinstance(h, logging.StreamHandler) and not isinstance(h, logging.FileHandler) for h in root.handlers):
        sh = logging.StreamHandler()
        sh.setLevel(level)
        sh.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
        root.addHandler(sh)
    try:
        from logging.handlers import RotatingFileHandler

        fh = RotatingFileHandler(cfg.logs_dir / "aegis.log", maxBytes=5_000_000, backupCount=3, encoding="utf-8")
        fh.setLevel(logging.INFO)
        fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
        root.addHandler(fh)
    except Exception:  # read-only data dir etc.
        pass
