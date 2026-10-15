"""Vulnerable / untrusted kernel driver detection (BYOVD - "bring your own vulnerable driver" - defence).

Ransomware and EDR-killers load a legitimately *signed but vulnerable* driver (RTCore64.sys, dbutil_2_3.sys, gdrv.sys ...)
to get kernel code execution and switch security software off. This scanner:

* enumerates installed kernel drivers (registry ``Services`` entries with ``Type`` 1/2 plus
  ``Get-CimInstance Win32_SystemDriver`` for the running state),
* hashes each driver file (SHA-256) and compares it with ``aegis/data/vulnerable_drivers.txt`` (LOLDrivers-style, optional,
  format ``sha256<TAB>label``; ``<signatures dir>/vulnerable_drivers.txt`` is merged if present) and with the malware hashes,
* flags a small built-in list of well-known abused driver *file names* (MEDIUM "present" - legitimate software ships
  several of them; HIGH only on a hash match or when the driver sits in a user-writable folder),
* flags unsigned / invalid-signature drivers with ONE batched ``Get-AuthenticodeSignature`` call, and drivers outside the
  standard driver folders,
* checks the posture that blocks the whole attack class: Microsoft's vulnerable-driver blocklist, HVCI / memory
  integrity, test-signing / kernel-debug boot options and Secure Boot (registry and the Code Integrity
  ``NtQuerySystemInformation`` flags - no ``bcdedit`` parsing).

Decision logic (``analyse_drivers``, ``posture_results`` ...) is pure and unit-tested on any OS.
"""

from __future__ import annotations

import fnmatch
import hashlib
import logging
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple

from aegis.core.config import PACKAGE_DATA
from aegis.core.models import Category, CheckResult, CheckStatus, Finding, Remediation, Severity
from aegis.core.platform import IS_WINDOWS, as_list, powershell_json, reg_read, reg_walk_values
from aegis.scanners.base import Emitted, ScanContext, Scanner, register

log = logging.getLogger("aegis.drivers")

VULN_DRIVERS_FILE = PACKAGE_DATA / "vulnerable_drivers.txt"
MAX_HASH_SIZE = 96 * 1024 * 1024  # skip hashing absurdly large files
SIG_SCRIPT_LIMIT = 24000  # keep the PowerShell command line well under the 32k Windows limit

SERVICES_KEY = r"SYSTEM\CurrentControlSet\Services"
CI_CONFIG_KEY = r"SYSTEM\CurrentControlSet\Control\CI\Config"
HVCI_KEY = r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
SECUREBOOT_KEY = r"SYSTEM\CurrentControlSet\Control\SecureBoot\State"
CONTROL_KEY = r"SYSTEM\CurrentControlSet\Control"

# =========================================================================== reference data

# (fnmatch pattern on the lower-case file name, product / description, reference)
KNOWN_ABUSABLE: List[Tuple[str, str, str]] = [
    ("rtcore64.sys", "MSI Afterburner / RivaTuner hardware monitor (RTCore64)", "CVE-2019-16098"),
    ("rtcore32.sys", "MSI Afterburner / RivaTuner hardware monitor (RTCore32)", "CVE-2019-16098"),
    ("dbutil_*.sys", "Dell BIOS utility (dbutil)", "CVE-2021-21551"),
    ("gdrv.sys", "GIGABYTE App Center / motherboard utility", "CVE-2018-19320"),
    ("gdrv2.sys", "GIGABYTE motherboard utility (gdrv2)", "CVE-2018-19320"),
    ("asio3.sys", "ASUS AsIO3 (Armoury Crate / AI Suite)", "CVE-2020-?"),
    ("asio2.sys", "ASUS AsIO2 (AI Suite)", "CVE-2020-?"),
    ("asio.sys", "ASUS AsIO (AI Suite)", "CVE-2020-?"),
    ("asusgio*.sys", "ASUS GPU/IO driver", "CVE-2018-18537"),
    ("procexp152.sys", "Sysinternals Process Explorer driver", "abused to kill security processes"),
    ("iqvw64e.sys", "Intel Ethernet diagnostics driver", "CVE-2015-2291"),
    ("iqvw32.sys", "Intel Ethernet diagnostics driver", "CVE-2015-2291"),
    ("cpuz*.sys", "CPUID CPU-Z hardware monitor", "CVE-2017-15302"),
    ("winring0x64.sys", "WinRing0 / OpenLibSys hardware-access library", "CVE-2020-14979"),
    ("winring0x32.sys", "WinRing0 / OpenLibSys hardware-access library", "CVE-2020-14979"),
    ("winring0.sys", "WinRing0 / OpenLibSys hardware-access library", "CVE-2020-14979"),
    ("asrdrv10*.sys", "ASRock RGB / motherboard utility", "CVE-2020-15368"),
    ("atillk64.sys", "ATI Tray Tools", "CVE-2019-?"),
    ("amifldrv64.sys", "AMI BIOS flash utility", "arbitrary physical memory access"),
    ("msio64.sys", "MSI I/O driver (Dragon Center / Live Update)", "CVE-2019-18845"),
    ("msio32.sys", "MSI I/O driver (Dragon Center / Live Update)", "CVE-2019-18845"),
    ("ntiolib*.sys", "MSI NTIOLib hardware-access driver", "CVE-2019-?"),
    ("phymem*.sys", "Physical-memory access driver", "arbitrary physical memory access"),
    ("physmem.sys", "Physical-memory access driver", "arbitrary physical memory access"),
    ("bs_def64.sys", "Biostar I/O driver", "CVE-2021-44852"),
    ("bs_rcio64.sys", "Biostar I/O driver", "CVE-2021-44852"),
    ("bs_flash64.sys", "Biostar flash driver", "CVE-2021-44852"),
    ("bsmem*.sys", "Biostar memory driver", "CVE-2021-44852"),
    ("directio*.sys", "PassMark DirectIO", "arbitrary physical memory access"),
    ("inpoutx64.sys", "InpOut32/64 hardware port access", "arbitrary I/O port access"),
    ("inpout32.sys", "InpOut32/64 hardware port access", "arbitrary I/O port access"),
    ("kprocesshacker*.sys", "Process Hacker / KProcessHacker", "abused to kill security processes"),
    ("mhyprot2.sys", "miHoYo (Genshin Impact) anti-cheat", "abused by ransomware to kill security tools"),
    ("mhyprot3.sys", "miHoYo (Genshin Impact) anti-cheat", "abused by ransomware to kill security tools"),
    ("zamguard*.sys", "Zemana anti-malware driver", "abused to kill security processes"),
    ("zam64.sys", "Zemana anti-malware driver", "abused to kill security processes"),
    ("aswarpot.sys", "Avast Anti-Rootkit driver", "abused to kill security processes"),
    ("truesight.sys", "Adlice RogueKiller TrueSight driver", "abused to kill security processes"),
    ("gmer64.sys", "GMER anti-rootkit driver", "kernel access"),
    ("gmerdrv.sys", "GMER anti-rootkit driver", "kernel access"),
    ("viragt64.sys", "VirIT Agent System driver", "kernel access"),
    ("lenovodiagnosticsdriver.sys", "Lenovo diagnostics driver", "CVE-2022-3699"),
    ("eneio64.sys", "ENE Technology RGB / SMBus driver", "arbitrary physical memory access"),
    ("iobitunlocker.sys", "IObit Unlocker", "arbitrary file delete / process kill"),
    ("amdryzenmasterdriver.sys", "AMD Ryzen Master", "CVE-2020-12928"),
    ("elrawdsk.sys", "EldoS RawDisk driver", "raw disk access (used by wipers)"),
    ("rwdrv.sys", "RW-Everything", "arbitrary hardware access"),
    ("speedfan.sys", "SpeedFan hardware monitor", "arbitrary physical memory access"),
    ("hwrwdrv.sys", "Hardware read/write driver", "arbitrary physical memory access"),
]
_KNOWN_RX = [(re.compile(fnmatch.translate(p), re.I), p, desc, ref) for p, desc, ref in KNOWN_ABUSABLE]


def match_known_driver(filename: str) -> Optional[Tuple[str, str]]:
    """(product description, reference) if the driver *file name* is on the well-known abused list."""
    name = (filename or "").strip().lower().replace("\\", "/").rsplit("/", 1)[-1]
    if not name:
        return None
    for rx, _pat, desc, ref in _KNOWN_RX:
        if rx.match(name):
            return desc, ref
    return None


# =========================================================================== data model

@dataclass
class DriverInfo:
    name: str  # service name
    path: str = ""  # normalised absolute path ("" = unknown)
    raw_path: str = ""
    display: str = ""
    description: str = ""
    start: Optional[int] = None  # 0 boot, 1 system, 2 auto, 3 demand, 4 disabled
    state: str = ""  # Running / Stopped ...
    exists: Optional[bool] = None
    sha256: str = ""
    sig_status: str = ""  # '' unknown | Valid | NotSigned | HashMismatch | NotTrusted | UnknownError | ...
    signer: str = ""
    company: str = ""
    file_description: str = ""
    version: str = ""

    @property
    def running(self) -> bool:
        return self.state.lower() == "running"

    @property
    def filename(self) -> str:
        return re.split(r"[\\/]", self.path or self.raw_path)[-1] if (self.path or self.raw_path) else ""

    @property
    def start_name(self) -> str:
        return {0: "boot", 1: "system", 2: "automatic", 3: "on demand", 4: "disabled"}.get(self.start, "unknown") \
            if self.start is not None else "unknown"


def _windir() -> str:
    return os.environ.get("SystemRoot") or os.environ.get("WINDIR") or r"C:\Windows"


def normalize_driver_path(raw: str, name: str = "", windir: Optional[str] = None) -> str:
    """Turn a service ImagePath into an absolute Windows path. Handles ``\\SystemRoot\\``, ``\\??\\``, ``%SystemRoot%``,
    ``System32\\drivers\\x.sys`` and the default (no ImagePath) of ``System32\\drivers\\<service>.sys``."""
    windir = (windir or _windir()).rstrip("\\")
    p = (raw or "").strip().strip('"').strip()
    if not p:
        return f"{windir}\\System32\\drivers\\{name}.sys" if name else ""
    p = re.sub(r"(?i)%(?:systemroot|windir)%", lambda m: windir, p)
    low = p.lower()
    if low.startswith("\\??\\"):
        p = p[4:]
    elif low.startswith("\\\\?\\") and not low.startswith("\\\\?\\unc\\"):
        p = p[4:]
    elif low.startswith("\\systemroot\\"):
        p = windir + p[11:]
    elif re.match(r"(?i)^(system32|syswow64)\\", p):
        p = windir + "\\" + p
    elif not re.match(r"(?i)^[a-z]:\\", p) and not p.startswith("\\\\") and "\\" not in p and "/" not in p:
        p = f"{windir}\\System32\\drivers\\{p}"
    # image paths can carry arguments after the .sys
    m = re.match(r"(?i)^(.*?\.sys)\b", p)
    return m.group(1) if m else p


def driver_location_class(path: str, windir: Optional[str] = None) -> str:
    """'standard' (System32\\drivers, DriverStore, System32), 'vendor' (Program Files), 'userwritable'
    (Temp/Downloads/AppData/ProgramData/Public...) or 'other'."""
    from aegis.core import cmdline as cl

    if not path:
        return "other"
    windir = (windir or _windir()).rstrip("\\").lower()
    low = path.lower().replace("/", "\\")
    if (low.startswith(windir + "\\system32\\drivers\\") or low.startswith(windir + "\\system32\\driverstore\\") or
            re.match(re.escape(windir) + r"\\(?:system32|syswow64)\\[^\\]+$", low) or
            low.startswith(windir + "\\winsxs\\")):
        return "standard"
    if cl.path_risk(path) > 0:
        return "userwritable"
    if re.match(r"^[a-z]:\\program files(?: \(x86\))?\\", low) or "\\programdata\\microsoft\\" in low:
        return "vendor"
    return "other"


# =========================================================================== hash list

_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")
_CVE = re.compile(r"CVE-\d{4}-\d{3,7}", re.I)


def load_vulnerable_driver_hashes(extra_dirs: Sequence[Path] = (), base: Optional[Path] = None) -> Dict[str, str]:
    """{sha256: label} from ``vulnerable_drivers.txt`` (bundled file + optional copies in ``extra_dirs``). The file is optional:
    a missing/unreadable file simply yields fewer (or no) hashes. Lines: ``sha256<TAB>label``; ``#`` starts a comment."""
    out: Dict[str, str] = {}
    files = [base or VULN_DRIVERS_FILE] + [Path(d) / "vulnerable_drivers.txt" for d in extra_dirs]
    for f in files:
        try:
            with f.open("r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith(("#", ";", "//")):
                        continue
                    parts = re.split(r"[\t,]", line, maxsplit=1) if "\t" in line or "," in line else line.split(None, 1)
                    h = parts[0].strip().strip('"')
                    if _HEX64.match(h):
                        out[h.lower()] = (parts[1].strip() if len(parts) > 1 and parts[1].strip() else "Vulnerable driver")
        except OSError:
            continue
    return out


# =========================================================================== analysis (pure)

def _is_valid(d: DriverInfo) -> bool:
    return d.sig_status.lower() == "valid"


def _disable_fix(d: DriverInfo, why: str) -> Optional[Remediation]:
    if not d.name:
        return None
    return Remediation("disable_service", {"name": d.name},
                       f"Stop and disable the '{d.name}' driver service ({why}); the file is left in place and the "
                       "change is backed up so it can be reverted")


def _evidence(d: DriverInfo, **extra: Any) -> Dict[str, Any]:
    ev = {"service": d.name, "path": d.path, "sha256": d.sha256, "state": d.state or "unknown",
          "start": d.start_name, "signature": d.sig_status or "not checked", "signer": d.signer,
          "company": d.company, "file_description": d.file_description or d.description, "version": d.version}
    ev.update(extra)
    return ev


def analyse_drivers(drivers: Sequence[DriverInfo], vuln_hashes: Optional[Dict[str, str]] = None, signatures: Any = None,
                    windir: Optional[str] = None) -> List[Finding]:
    """Findings for a list of drivers whose sha256 / signature fields have been filled in."""
    vuln_hashes = vuln_hashes or {}
    out: List[Finding] = []
    for d in drivers:
        loc_class = driver_location_class(d.path, windir) if d.path else "other"
        label = vuln_hashes.get(d.sha256.lower()) if d.sha256 else None
        malware = None
        if d.sha256 and signatures is not None:
            try:
                malware = signatures.lookup_hash(d.sha256)
            except Exception:
                malware = None
        known = match_known_driver(d.filename) or match_known_driver(d.name + ".sys")
        label_is_mal = bool(label and "maldriver" in label.lower())

        # ---- hash matches: the definitive BYOVD signal
        if malware or label:
            cves = sorted({c.upper() for c in _CVE.findall(label or "")})
            mal = bool(malware) or label_is_mal
            sev = Severity.CRITICAL if mal else Severity.HIGH
            nm = d.filename or d.name
            out.append(Finding(
                "AEG-DRV-VULN", (f"Malicious kernel driver: {nm}" if mal else f"Vulnerable kernel driver present: {nm}"),
                sev, Category.VULNERABILITY if not mal else Category.MALWARE,
                (f"The driver file {d.path or nm} exactly matches a known " +
                 ("malicious driver (" + (malware or label) + ")." if mal else
                  f"vulnerable driver ({label}). Attackers install such signed-but-flawed drivers on purpose to get kernel "
                  "access and then switch off antivirus/EDR or hide malware (the 'BYOVD' technique).") +
                 (" It is currently loaded." if d.running else "")),
                d.path or nm, _evidence(d, matched=malware or label, cves=cves, running=d.running),
                ("Remove the software that installed it (or, if you do not recognise it, treat the PC as compromised), "
                 "disable the driver service, reboot and run a full scan. Turn on Microsoft's vulnerable driver blocklist "
                 "and memory integrity so Windows refuses to load it."),
                _disable_fix(d, "known " + ("malicious" if mal else "vulnerable") + " driver"), mitre=["T1068", "T1014", "T1685"]))
            continue  # the other checks would only repeat the point

        # ---- well-known abusable driver names
        known_reported = False
        if known:
            desc, ref = known
            skip = False
            if d.filename.lower() == "procexp152.sys":
                lowp = (d.path or "").lower().replace("/", "\\").rsplit("\\", 1)[0]  # folder only, not the file name
                legit_home = ("sysinternals" in lowp or "procexp" in lowp or "process explorer" in lowp or
                              (loc_class == "standard" and _is_valid(d) and
                               ("microsoft" in d.signer.lower() or "sysinternals" in d.signer.lower() or not d.signer)))
                skip = legit_home  # Process Explorer drops its own signed driver into System32\drivers
            if not skip:
                known_reported = True
                escalate = loc_class == "userwritable" or (d.running and d.sig_status.lower() in ("nosigned", "notsigned", "hashmismatch"))
                sev = Severity.HIGH if escalate else Severity.MEDIUM
                out.append(Finding(
                    "AEG-DRV-ABUSABLE", f"Known abusable driver present: {d.filename or d.name}", sev, Category.VULNERABILITY,
                    f"{d.filename or d.name} is {desc}. {('Reference: ' + ref + '. ') if ref else ''}The driver is legitimate "
                    "and is installed by some vendor software, but its flaws are used by ransomware and EDR-killer tools "
                    "that load a copy to gain kernel access"
                    + ("; this copy sits in a user-writable folder, which legitimate installers do not use." if loc_class == "userwritable" else ".")
                    + (" It is currently loaded." if d.running else ""),
                    d.path or d.filename, _evidence(d, reference=ref, product=desc, location_class=loc_class, running=d.running),
                    "If you do not use the product that ships this driver, uninstall that software (and the driver service). "
                    "If you do, update it to the latest version and enable Microsoft's vulnerable-driver blocklist.",
                    _disable_fix(d, "known abusable driver") if sev >= Severity.HIGH else None, mitre=["T1068", "T1014"]))

        # ---- signature problems
        st = d.sig_status.lower()
        if d.exists is not False and st and st != "valid":
            if st == "hashmismatch":
                sev, what = Severity.HIGH, "was modified after it was signed (its contents no longer match the signature)"
            elif st in ("notsigned", "nosigned"):
                sev = Severity.HIGH if d.running else Severity.MEDIUM
                what = "has no digital signature" + (" yet is loaded - Windows only allows that in test-signing mode or "
                                                     "with signature enforcement bypassed" if d.running else "")
            else:
                sev, what = Severity.MEDIUM, f"has a signature that Windows does not trust ({d.sig_status})"
            out.append(Finding(
                "AEG-DRV-UNSIGNED", f"Kernel driver {d.filename or d.name} {'is unsigned' if st in ('notsigned', 'nosigned') else 'has an invalid signature'}",
                sev, Category.SUSPICIOUS,
                f"The driver {d.path or d.name} {what}. Kernel drivers run with the highest privileges, so an unsigned or "
                "tampered one can hide malware from every security product.",
                d.path or d.name, _evidence(d, location_class=loc_class, running=d.running),
                "Find out which program installed this driver. If you do not recognise it, disable the service, reboot and run a "
                "full scan; reinstall the vendor's software if it is yours.",
                _disable_fix(d, "unsigned or tampered driver") if sev >= Severity.HIGH else None, mitre=["T1553.002", "T1014"]))

        # ---- location
        if loc_class in ("userwritable", "other") and d.path:
            userw = loc_class == "userwritable"
            if userw and known_reported:
                continue  # the abusable-driver finding already says it sits in a user-writable folder
            stale = d.exists is False and not d.running
            if userw:
                sev = Severity.LOW if stale else (Severity.HIGH if _risk_level(d.path) == 2 else Severity.MEDIUM)
            else:
                # a validly signed driver in an unusual (but not user-writable) folder is only worth a note when loaded
                if stale or (_is_valid(d) and not d.running):
                    continue
                sev = Severity.LOW
            where = ("in a folder that any program running as your user can write to" if userw
                     else "not in the standard driver folder (System32\\drivers) or Program Files")
            note = " The file no longer exists, so this is a leftover registry entry." if stale else ""
            out.append(Finding(
                "AEG-DRV-LOCATION",
                (f"Kernel driver loaded from a user-writable folder: {d.filename or d.name}" if userw
                 else f"Kernel driver outside the standard driver folders: {d.filename or d.name}"),
                sev, Category.SUSPICIOUS,
                (f"The driver {d.path} is {where}.{note} Legitimate drivers are installed into System32\\drivers or the "
                 "vendor's Program Files folder; attackers drop theirs into Temp, Downloads or AppData."),
                d.path, _evidence(d, location_class=loc_class, running=d.running),
                "If you did not install software that needs this driver, disable the service, delete the file and run a full scan.",
                _disable_fix(d, "driver in a user-writable folder") if sev >= Severity.HIGH else None,
                mitre=["T1543.003", "T1014"]))
    return out


def _risk_level(path: str) -> int:
    from aegis.core import cmdline as cl

    return int(cl.path_risk(path))


# =========================================================================== posture (blocklist / HVCI / test signing)

CI_ENABLED = 0x01
CI_TESTSIGN = 0x02
CI_UMCI = 0x04
CI_DEBUGMODE = 0x80
CI_HVCI_ENABLED = 0x400
CI_HVCI_STRICT = 0x1000
WIN11_22H2_BUILD = 22621


def decode_ci_options(opts: Optional[int]) -> Dict[str, bool]:
    """Decode ``SYSTEM_CODEINTEGRITY_INFORMATION.CodeIntegrityOptions``."""
    if opts is None:
        return {}
    return {"enabled": bool(opts & CI_ENABLED), "testsign": bool(opts & CI_TESTSIGN), "umci": bool(opts & CI_UMCI),
            "debug": bool(opts & CI_DEBUGMODE), "hvci": bool(opts & CI_HVCI_ENABLED),
            "hvci_strict": bool(opts & CI_HVCI_STRICT)}


def parse_boot_options(text: str) -> Dict[str, bool]:
    """Flags in the ``SystemStartOptions`` registry string (kernel options of the current boot)."""
    toks = set(re.split(r"[\s/;,]+", (text or "").upper()))
    return {"testsign": "TESTSIGNING" in toks, "nointegrity": bool(toks & {"NOINTEGRITYCHECKS", "DISABLE_INTEGRITY_CHECKS"}),
            "debug": bool(toks & {"DEBUG", "KERNELDEBUG"}) and "NODEBUG" not in toks}


def blocklist_status(value: Optional[int], build: Optional[int], hvci_on: Optional[bool]) -> Tuple[str, str]:
    """(status, detail) for Microsoft's vulnerable driver blocklist."""
    if value == 1:
        return CheckStatus.PASS, "Microsoft's vulnerable driver blocklist is enabled."
    if value == 0:
        return CheckStatus.FAIL, "Microsoft's vulnerable driver blocklist is explicitly turned off."
    if build is not None and build >= WIN11_22H2_BUILD:
        return CheckStatus.PASS, "Not set explicitly; the blocklist is on by default since Windows 11 22H2."
    if hvci_on:
        return CheckStatus.PASS, "Not set explicitly; the blocklist is on because memory integrity (HVCI) is on."
    return CheckStatus.WARN, ("Not enabled explicitly. On Windows 10 and early Windows 11 the blocklist only applies "
                              "with memory integrity or S mode, so known-vulnerable drivers can still load.")


def posture_results(ci_options: Optional[int], start_options: str, blocklist_value: Optional[int],
                    hvci_reg: Optional[int], secureboot_reg: Optional[int], build: Optional[int]
                    ) -> Tuple[List[CheckResult], List[Finding]]:
    checks: List[CheckResult] = []
    findings: List[Finding] = []
    ci = decode_ci_options(ci_options)
    boot = parse_boot_options(start_options)

    def fnd(rule: str, title: str, sev: Severity, desc: str, rec: str, rem: Optional[Remediation], loc: str,
            mitre: List[str], **ev: Any) -> None:
        findings.append(Finding(rule, title, sev, Category.SYSTEM, desc, loc, ev, rec, rem, mitre=mitre))

    # HVCI / memory integrity
    hvci_running = ci.get("hvci") if ci else None
    if hvci_running or (hvci_running is None and hvci_reg == 1):
        checks.append(CheckResult("AEG-DRV-HVCI", "Memory integrity (HVCI)", CheckStatus.PASS,
                                  "Memory integrity is on: only validly signed, compatible drivers can load.", Category.SYSTEM))
    else:
        why = ("It is switched on in settings but not active - a reboot or an incompatible driver is blocking it."
               if hvci_reg == 1 else "Memory integrity (virtualisation-based code-integrity protection) is off.")
        checks.append(CheckResult("AEG-DRV-HVCI", "Memory integrity (HVCI)", CheckStatus.WARN, why, Category.SYSTEM))
        fnd("AEG-DRV-HVCI", "Memory integrity (HVCI) is not active", Severity.LOW,
            why + " Memory integrity blocks most kernel-level attacks, including vulnerable-driver abuse, by refusing to "
                  "load drivers that are unsigned or known to be flawed.",
            "Open Windows Security > Device security > Core isolation > Memory integrity and turn it on (Windows lists any "
            "incompatible driver you must update first). Aegis does not change this automatically because a "
            "wrong setting can stop the PC from booting.", None, "Windows memory integrity", ["T1068", "T1685"],
            hvci_registry=hvci_reg, hvci_running=hvci_running)

    # vulnerable driver blocklist
    st, detail = blocklist_status(blocklist_value, build, bool(hvci_running) or hvci_reg == 1)
    checks.append(CheckResult("AEG-DRV-BLOCKLIST", "Microsoft vulnerable driver blocklist", st, detail, Category.SYSTEM))
    if st != CheckStatus.PASS:
        fnd("AEG-DRV-BLOCKLIST", "Microsoft's vulnerable driver blocklist is not enabled",
            Severity.MEDIUM if st == CheckStatus.FAIL else Severity.LOW,
            detail + " The blocklist is Microsoft's list of drivers that attackers abuse; with it on, Windows refuses to load them.",
            "Turn it on (Windows Security > Device security > Core isolation > Microsoft Vulnerable Driver Blocklist) or "
            "use the automatic fix, then restart the PC.",
            Remediation("set_registry_value", {"hive": "HKLM", "key": CI_CONFIG_KEY, "value": "VulnerableDriverBlocklistEnable",
                                               "data": 1}, "Enable the Microsoft vulnerable driver blocklist (takes effect after a restart)"),
            "Windows vulnerable driver blocklist", ["T1068", "T1685"], registry_value=blocklist_value, build=build)

    # test signing / disabled integrity checks / kernel debugging
    testsign = bool(ci.get("testsign")) if ci else boot["testsign"]
    nointegrity = boot["nointegrity"]
    if testsign or nointegrity:
        bad = "test-signing mode is on" if testsign else "driver-signature integrity checks are disabled"
        checks.append(CheckResult("AEG-DRV-TESTSIGN", "Test-signing / signature enforcement", CheckStatus.FAIL,
                                  f"Windows booted with {bad}: unsigned or self-signed drivers can load.", Category.SYSTEM))
        fnd("AEG-DRV-TESTSIGN", "Windows is running with driver signature enforcement weakened", Severity.HIGH,
            f"Windows started with {bad}. Anyone (or any malware) can then install a kernel driver that is unsigned or "
            "signed with a self-made certificate; a rootkit's easiest way in.",
            "Unless you are a driver developer, switch it off: in an elevated Command Prompt run 'bcdedit /set testsigning off' "
            "(and 'bcdedit /deletevalue nointegritychecks'), then reboot. Aegis does not do this automatically because "
            "developer machines rely on it.", None, "Windows boot configuration", ["T1553.006", "T1014"],
            testsign=testsign, nointegritychecks=nointegrity)
    else:
        checks.append(CheckResult("AEG-DRV-TESTSIGN", "Test-signing / signature enforcement", CheckStatus.PASS,
                                  "Driver signature enforcement is normal.", Category.SYSTEM))
    debug = bool(ci.get("debug")) if ci else boot["debug"]
    if debug or boot["debug"]:
        checks.append(CheckResult("AEG-DRV-KDEBUG", "Kernel debugging", CheckStatus.WARN,
                                  "The kernel debugger is enabled for this boot.", Category.SYSTEM))
        fnd("AEG-DRV-KDEBUG", "Kernel debugging is enabled", Severity.MEDIUM,
            "Windows started with the kernel debugger enabled. That is normal for driver developers and abnormal on a "
            "normal PC, because a kernel debugger can read and change anything, including security software.",
            "Run 'bcdedit /debug off' in an elevated Command Prompt and reboot unless you are debugging drivers.", None,
            "Windows boot configuration", ["T1014"])
    else:
        checks.append(CheckResult("AEG-DRV-KDEBUG", "Kernel debugging", CheckStatus.PASS, "Kernel debugging is off.", Category.SYSTEM))

    # Secure Boot
    if secureboot_reg == 1:
        checks.append(CheckResult("AEG-DRV-SECUREBOOT", "Secure Boot", CheckStatus.PASS, "Secure Boot is on.", Category.SYSTEM))
    elif secureboot_reg == 0:
        checks.append(CheckResult("AEG-DRV-SECUREBOOT", "Secure Boot", CheckStatus.WARN,
                                  "Secure Boot is supported but turned off.", Category.SYSTEM))
        fnd("AEG-DRV-SECUREBOOT", "Secure Boot is turned off", Severity.LOW,
            "Secure Boot makes the PC refuse to start with tampered boot software or an unsigned boot-level driver (bootkits).",
            "Turn Secure Boot on in the UEFI/BIOS settings (the PC must be using UEFI mode; check the manual of your PC).", None,
            "UEFI Secure Boot", ["T1542.003"])
    else:
        checks.append(CheckResult("AEG-DRV-SECUREBOOT", "Secure Boot", CheckStatus.SKIP,
                                  "Secure Boot state unavailable (legacy BIOS or not readable).", Category.SYSTEM))
    return checks, findings


# =========================================================================== collection (Windows)

def _int(v: Any) -> Optional[int]:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def drivers_from_registry(walk=None, windir: Optional[str] = None) -> Dict[str, DriverInfo]:
    """Kernel / file-system driver services (Type 1 or 2) from the registry, keyed by lower-case service name."""
    out: Dict[str, DriverInfo] = {}
    walk = walk or reg_walk_values
    for sub, vals in walk("HKLM", SERVICES_KEY):
        if _int(vals.get("Type")) not in (1, 2):
            continue
        name = sub.rsplit("\\", 1)[-1]
        raw = str(vals.get("ImagePath") or "")
        out[name.lower()] = DriverInfo(
            name=name, raw_path=raw, path=normalize_driver_path(raw, name, windir), display=str(vals.get("DisplayName") or ""),
            start=_int(vals.get("Start")))
    return out


def merge_cim_drivers(drivers: Dict[str, DriverInfo], cim: Any, windir: Optional[str] = None) -> None:
    """Add running state / description from ``Win32_SystemDriver`` (also adds drivers the registry walk missed)."""
    for rec in as_list(cim):
        if not isinstance(rec, dict) or not rec.get("Name"):
            continue
        key = str(rec["Name"]).lower()
        d = drivers.get(key)
        if d is None:
            d = drivers[key] = DriverInfo(name=str(rec["Name"]))
        d.state = str(rec.get("State") or d.state or "")
        d.description = str(rec.get("Description") or d.description or "")
        d.display = d.display or str(rec.get("DisplayName") or "")
        pn = str(rec.get("PathName") or "")
        if pn and not d.path:
            d.raw_path, d.path = pn, normalize_driver_path(pn, d.name, windir)
        elif pn and not d.raw_path:
            d.raw_path = pn
        if d.start is None:
            d.start = {"boot": 0, "system": 1, "auto": 2, "manual": 3, "disabled": 4}.get(str(rec.get("StartMode") or "").lower())


def _ps_quote(s: str) -> str:
    return "'" + s.replace("'", "''") + "'"


CIM_SCRIPT = ("Get-CimInstance -ClassName Win32_SystemDriver | Select-Object Name,DisplayName,PathName,State,StartMode,"
              "Description | ConvertTo-Json -Compress")


def build_signature_script(paths: Sequence[str]) -> str:
    """ONE Get-AuthenticodeSignature call for many files (+ version info). Status is the enum *name* (locale independent)."""
    quoted = ",".join(_ps_quote(p) for p in paths)
    return ("$ErrorActionPreference='SilentlyContinue'; "
            f"$p=@({quoted}); "
            "Get-AuthenticodeSignature -LiteralPath $p | ForEach-Object { $v=$null; "
            "try { $v=[System.Diagnostics.FileVersionInfo]::GetVersionInfo($_.Path) } catch { }; "
            "[pscustomobject]@{Path=$_.Path;Status=$_.Status.ToString();"
            "Signer=$(if($_.SignerCertificate){$_.SignerCertificate.Subject}else{''});"
            "Company=$(if($v){$v.CompanyName}else{''});Description=$(if($v){$v.FileDescription}else{''});"
            "Version=$(if($v){$v.FileVersion}else{''})} } | ConvertTo-Json -Compress")


def chunk_paths(paths: Sequence[str], limit: int = SIG_SCRIPT_LIMIT) -> List[List[str]]:
    """Normally a single chunk; only splits when the PowerShell command line would exceed the Windows limit."""
    chunks: List[List[str]] = []
    cur: List[str] = []
    size = 0
    for p in paths:
        n = len(p) + 4
        if cur and size + n > limit:
            chunks.append(cur)
            cur, size = [], 0
        cur.append(p)
        size += n
    if cur:
        chunks.append(cur)
    return chunks


def apply_signatures(drivers: Sequence[DriverInfo], sig_rows: Any) -> int:
    """Fill sig_status/signer/company/... from the Get-AuthenticodeSignature rows. Returns rows applied."""
    by_path: Dict[str, Dict[str, Any]] = {}
    for r in as_list(sig_rows):
        if isinstance(r, dict) and r.get("Path"):
            by_path[str(r["Path"]).lower()] = r
    n = 0
    for d in drivers:
        r = by_path.get(d.path.lower()) if d.path else None
        if not r:
            continue
        d.sig_status = str(r.get("Status") or "")
        d.signer = str(r.get("Signer") or "")
        d.company = str(r.get("Company") or "")
        d.file_description = str(r.get("Description") or "")
        d.version = str(r.get("Version") or "")
        n += 1
    return n


def hash_driver(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def code_integrity_options() -> Optional[int]:
    """``NtQuerySystemInformation(SystemCodeIntegrityInformation)`` options; None if unavailable."""
    if not IS_WINDOWS:
        return None
    try:
        import ctypes

        class _SCI(ctypes.Structure):
            _fields_ = [("Length", ctypes.c_ulong), ("CodeIntegrityOptions", ctypes.c_ulong)]

        info = _SCI()
        info.Length = ctypes.sizeof(info)
        ret = ctypes.c_ulong(0)
        status = ctypes.windll.ntdll.NtQuerySystemInformation(103, ctypes.byref(info), info.Length, ctypes.byref(ret))  # type: ignore[attr-defined]
        return int(info.CodeIntegrityOptions) if status == 0 else None
    except Exception:
        return None


def windows_build() -> Optional[int]:
    try:
        return int(sys.getwindowsversion().build)  # type: ignore[attr-defined]
    except Exception:
        return None


def _reg_int(hive: str, key: str, value: str) -> Optional[int]:
    try:
        return _int(reg_read(hive, key, value))
    except Exception:
        return None


@register
class DriverScanner(Scanner):
    name = "drivers"
    title = "Vulnerable & untrusted kernel drivers"
    description = ("BYOVD defence: matches installed drivers against known vulnerable/abused drivers, flags unsigned or "
                   "oddly-placed drivers, and checks the driver blocklist, memory integrity and test-signing.")
    platforms = ("windows",)
    needs_admin_for_full_results = False

    def run(self, ctx: ScanContext) -> Iterator[Emitted]:
        if not IS_WINDOWS:
            yield CheckResult("AEG-DRV-INVENTORY", "Kernel driver review", CheckStatus.SKIP,
                              "Kernel driver review is only available on Windows.", Category.SYSTEM)
            return
        # ---- posture first: cheap registry / ntdll reads
        try:
            checks, findings = posture_results(
                code_integrity_options(), str(reg_read("HKLM", CONTROL_KEY, "SystemStartOptions") or ""),
                _reg_int("HKLM", CI_CONFIG_KEY, "VulnerableDriverBlocklistEnable"),
                _reg_int("HKLM", HVCI_KEY, "Enabled"), _reg_int("HKLM", SECUREBOOT_KEY, "UEFISecureBootEnabled"),
                windows_build())
            yield from checks
            yield from findings
        except Exception as exc:  # pragma: no cover - defensive
            log.warning("driver posture checks failed: %s", exc)
            yield CheckResult("AEG-DRV-POSTURE", "Driver protection settings", CheckStatus.ERROR,
                              f"{type(exc).__name__}: {exc}", Category.SYSTEM)

        # ---- inventory
        ctx.report(self.name, "enumerating kernel drivers")
        try:
            drivers = drivers_from_registry()
            merge_cim_drivers(drivers, powershell_json(CIM_SCRIPT, timeout=90))
        except Exception as exc:
            log.warning("driver enumeration failed: %s", exc)
            yield CheckResult("AEG-DRV-INVENTORY", "Kernel driver inventory", CheckStatus.ERROR,
                              f"{type(exc).__name__}: {exc}", Category.SYSTEM)
            return
        items = sorted(drivers.values(), key=lambda d: d.name.lower())
        if not items:
            yield CheckResult("AEG-DRV-INVENTORY", "Kernel driver inventory", CheckStatus.SKIP,
                              "No kernel drivers could be listed (registry access failed).", Category.SYSTEM)
            return
        ctx.bump("drivers_inspected", len(items))
        for d in items:
            d.exists = bool(d.path) and os.path.isfile(d.path)

        vuln = load_vulnerable_driver_hashes([ctx.config.signatures_dir])
        hashed = 0
        for d in items:
            if ctx.cancelled:
                return
            if d.exists:
                try:
                    if os.path.getsize(d.path) <= MAX_HASH_SIZE:
                        d.sha256 = hash_driver(d.path)
                        hashed += 1
                except OSError:
                    pass

        sig_ok = False
        paths = [d.path for d in items if d.exists]
        if paths:
            ctx.report(self.name, f"checking signatures of {len(paths)} drivers")
            applied = 0
            for chunk in chunk_paths(paths):
                if ctx.cancelled:
                    return
                rows = powershell_json(build_signature_script(chunk), timeout=180)
                if rows is not None:
                    applied += apply_signatures(items, rows)
            sig_ok = applied > 0

        yield CheckResult("AEG-DRV-INVENTORY", "Kernel driver inventory", CheckStatus.PASS,
                          f"{len(items)} kernel driver(s) registered, {sum(1 for d in items if d.running)} running; "
                          f"{hashed} file(s) hashed against {len(vuln)} known vulnerable/malicious driver hashes.", Category.SYSTEM)
        try:
            found = analyse_drivers(items, vuln, ctx.signatures)
        except Exception as exc:  # pragma: no cover - defensive
            log.warning("driver analysis failed: %s", exc, exc_info=True)
            yield CheckResult("AEG-DRV-ANALYSE", "Kernel driver analysis", CheckStatus.ERROR, f"{type(exc).__name__}: {exc}",
                              Category.SYSTEM)
            return
        bad_vuln = [f for f in found if f.rule_id in ("AEG-DRV-VULN", "AEG-DRV-ABUSABLE")]
        bad_sig = [f for f in found if f.rule_id == "AEG-DRV-UNSIGNED"]
        yield CheckResult("AEG-DRV-VULN", "No known vulnerable or abused kernel drivers",
                          CheckStatus.FAIL if bad_vuln else CheckStatus.PASS,
                          f"{len(bad_vuln)} driver(s) match the vulnerable-driver lists." if bad_vuln else
                          ("None found." if vuln else "None found by name (the hash list is not installed)."), Category.VULNERABILITY)
        if sig_ok:
            yield CheckResult("AEG-DRV-SIGNED", "All kernel drivers carry a valid signature",
                              CheckStatus.FAIL if bad_sig else CheckStatus.PASS,
                              f"{len(bad_sig)} unsigned or invalid-signature driver(s)." if bad_sig else "All drivers verified.",
                              Category.SUSPICIOUS)
        else:
            yield CheckResult("AEG-DRV-SIGNED", "All kernel drivers carry a valid signature", CheckStatus.SKIP,
                              "Signature verification was not available (PowerShell failed).", Category.SUSPICIOUS)
        for f in found:
            if ctx.cancelled:
                return
            yield f
