"""Signature & threat-intelligence database: malware hashes, content rules,
YARA rules, malicious IPs / domains and malicious browser-extension IDs.

Bundled data ships in aegis/data; `aegis update` downloads fresh feeds into
<data>/signatures which are merged on top."""

from __future__ import annotations

import ipaddress
import logging
import threading
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set

from aegis.core.config import PACKAGE_DATA, Config
from aegis.core.rules import Rule, load_rule_files

log = logging.getLogger("aegis.signatures")

try:  # optional native YARA engine
    import yara  # type: ignore

    HAVE_YARA = True
except Exception:  # pragma: no cover - depends on environment
    yara = None
    HAVE_YARA = False


def _read_list(path: Path) -> Iterable[str]:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith(("#", ";", "//")):
                    yield line
    except FileNotFoundError:
        return


class SignatureDB:
    def __init__(self, config: Config):
        self.config = config
        self.hashes: Dict[str, str] = {}  # sha256 or md5 (lowercase) -> threat name
        self.rules: List[Rule] = []
        self.yara_rules = None
        self.yara_count = 0
        self.bad_ips: Set[str] = set()
        self.bad_networks: List[ipaddress._BaseNetwork] = []
        self.bad_domains: Set[str] = set()
        self.bad_extensions: Set[str] = set()
        self.pup_names: List[str] = []
        self._lock = threading.Lock()
        self.load()

    # ------------------------------------------------------------------ loading
    def _sources(self, name: str) -> List[Path]:
        out = []
        for base in (PACKAGE_DATA, self.config.signatures_dir):
            p = base / name
            if p.exists():
                out.append(p)
        return out

    def load(self) -> None:
        with self._lock:
            self.hashes.clear()
            for p in self._sources("hashes.tsv") + self._sources("malwarebazaar_recent.txt"):
                default_name = "MalwareBazaar.RecentSample" if "bazaar" in p.name else "Known.Malware"
                for line in _read_list(p):
                    parts = line.replace(",", "\t").split("\t")
                    h = parts[0].strip().strip('"').lower()
                    if len(h) in (32, 40, 64) and all(c in "0123456789abcdef" for c in h):
                        self.hashes[h] = parts[1].strip() if len(parts) > 1 and parts[1].strip() else default_name

            rule_files: List[Path] = []
            for base in (PACKAGE_DATA / "rules", self.config.signatures_dir / "rules"):
                if base.is_dir():
                    rule_files += sorted(base.glob("*.json"))
            self.rules = load_rule_files(rule_files)

            self.bad_ips.clear()
            self.bad_networks = []
            for p in self._sources("ip_blocklist.txt") + self._sources("feodo_ipblocklist.txt"):
                for line in _read_list(p):
                    token = line.split()[0].split(",")[0]
                    try:
                        if "/" in token:
                            self.bad_networks.append(ipaddress.ip_network(token, strict=False))
                        else:
                            self.bad_ips.add(str(ipaddress.ip_address(token)))
                    except ValueError:
                        continue

            self.bad_domains.clear()
            for p in self._sources("domain_blocklist.txt") + self._sources("urlhaus_hosts.txt"):
                for line in _read_list(p):
                    parts = line.split()
                    dom = parts[-1].lower().strip(".")
                    if "." in dom and dom not in ("localhost",):
                        self.bad_domains.add(dom)

            self.bad_extensions = {x.split()[0].lower() for p in self._sources("malicious_extensions.txt")
                                   for x in _read_list(p) if len(x.split()[0]) == 32}

            self.pup_names = [x.lower() for p in self._sources("pup_names.txt") for x in _read_list(p)]

            self._load_yara()
        log.info("signatures: %d hashes, %d lite rules, %d yara files, %d IPs, %d domains, %d extensions",
                 len(self.hashes), len(self.rules), self.yara_count, len(self.bad_ips), len(self.bad_domains),
                 len(self.bad_extensions))

    def _load_yara(self) -> None:
        self.yara_rules = None
        self.yara_count = 0
        if not HAVE_YARA:
            return
        candidates: Dict[str, str] = {}
        for base in (PACKAGE_DATA / "yara", self.config.signatures_dir / "yara"):
            if base.is_dir():
                for p in sorted(base.rglob("*.yar")) + sorted(base.rglob("*.yara")):
                    candidates[f"{base.parent.name}_{p.stem}_{len(candidates)}"] = str(p)
        if not candidates:
            return
        # Fast path: one compile of everything (large community sets take seconds).
        try:
            self.yara_rules = yara.compile(filepaths=candidates)
            self.yara_count = len(candidates)
            return
        except Exception as exc:
            log.info("YARA bulk compile failed (%s); validating files individually", exc)
        # Slow path: drop the files that don't compile so one bad rule can't disable all.
        good = {}
        for ns, path in candidates.items():
            try:
                yara.compile(filepath=path)
                good[ns] = path
            except Exception as exc:
                log.warning("skipping YARA file %s: %s", path, exc)
        if good:
            try:
                self.yara_rules = yara.compile(filepaths=good)
                self.yara_count = len(good)
            except Exception as exc:
                log.warning("YARA compile failed: %s", exc)

    # ------------------------------------------------------------------ queries
    def lookup_hash(self, *hashes: Optional[str]) -> Optional[str]:
        for h in hashes:
            if h and h.lower() in self.hashes:
                return self.hashes[h.lower()]
        return None

    def is_bad_ip(self, ip: str) -> bool:
        if ip in self.bad_ips:
            return True
        if self.bad_networks:
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                return False
            return any(addr in n for n in self.bad_networks)
        return False

    def is_bad_domain(self, domain: str) -> bool:
        d = domain.lower().strip(".")
        while d:
            if d in self.bad_domains:
                return True
            if "." not in d:
                return False
            d = d.split(".", 1)[1]
        return False

    def summary(self) -> Dict[str, int]:
        return {
            "hashes": len(self.hashes),
            "content_rules": len(self.rules),
            "yara_rule_files": self.yara_count,
            "malicious_ips": len(self.bad_ips) + len(self.bad_networks),
            "malicious_domains": len(self.bad_domains),
            "malicious_extensions": len(self.bad_extensions),
            "pup_names": len(self.pup_names),
        }
