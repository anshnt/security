"""Aegis Security Suite - desktop application (tkinter / ttk).

Design notes
* The module is import-safe: tkinter is imported inside `launch_gui()` and the
  widget toolkit is *injected* into the classes below (`tk`, `ttk` attributes),
  which keeps the module importable on headless machines and lets the unit
  tests drive the whole UI construction with a mocked toolkit.
* Anything slow (signature loading, scanning, network lookups, remediation) runs
  on a worker thread; workers never touch widgets - they post callables to a
  queue that the Tk main loop drains with `root.after`.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import os
import queue
import sys
import threading
import time
import traceback
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from aegis import __app_name__, __version__
from aegis.core.config import Config
from aegis.core.models import Finding, Severity
from aegis.core.platform import IS_WINDOWS, is_admin

log = logging.getLogger("aegis.gui")

# --------------------------------------------------------------------------- theme

C = {
    "bg": "#0e1320", "panel": "#161d2e", "panel2": "#1d2640", "border": "#2a3553", "text": "#e7ebf6",
    "muted": "#8a94b0", "accent": "#4c8dff", "accent_hi": "#6ea3ff", "accent_dn": "#3a74d8",
    "good": "#34c46a", "ok": "#7ad03a", "warn": "#f5a524", "orange": "#ff7a45", "bad": "#f0556a", "crit": "#ff3b5c",
    "select": "#27427a",
}
SEV_COLOR = {"critical": C["crit"], "high": C["orange"], "medium": C["warn"], "low": "#4fa3ff", "info": C["muted"]}
GRADE_COLOR = {"A": C["good"], "B": C["ok"], "C": C["warn"], "D": C["orange"], "F": C["crit"]}
FONT = "Segoe UI" if IS_WINDOWS else "Helvetica"
MONO = "Consolas" if IS_WINDOWS else "Courier"
SECRET_ENVS = (("virustotal_api_key", "AEGIS_VT_API_KEY"), ("abusech_auth_key", "AEGIS_ABUSECH_KEY"),
               ("google_safebrowsing_api_key", "AEGIS_GSB_API_KEY"))

NAV = [("dashboard", "Dashboard"), ("scan", "Scan"), ("protection", "Protection"), ("quarantine", "Quarantine"),
       ("tools", "Tools"), ("settings", "Settings")]


def fmt_time(iso: str) -> str:
    try:
        return dt.datetime.fromisoformat(iso).strftime("%d %b %Y, %H:%M")
    except (ValueError, TypeError):
        return iso or "never"


def human_size(n: int) -> str:
    size = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{n} B"


def restart_as_admin() -> bool:
    """Relaunch the current program elevated (UAC prompt). Windows only."""
    if not IS_WINDOWS:
        return False
    import ctypes

    if getattr(sys, "frozen", False):
        exe, params = sys.executable, " ".join(f'"{a}"' for a in sys.argv[1:])
    else:
        exe, params = sys.executable, "-m aegis.ui.gui"
    rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)  # type: ignore[attr-defined]
    return int(rc) > 32


def fixed_map(style: Any, option: str) -> list:
    """Work around the Tk 8.6.9 bug where Treeview tag colours are ignored."""
    return [e for e in style.map("Treeview", query_opt=option) if e[:2] != ("!disabled", "!selected")]


# --------------------------------------------------------------------------- UI bridge

class UiBridge:
    """Thread-safe way for workers to run code on the Tk thread."""

    def __init__(self, root: Any, interval_ms: int = 80):
        self.root = root
        self.q: "queue.Queue[tuple]" = queue.Queue()
        self.interval = interval_ms
        self._closed = False

    def post(self, fn: Callable, *args: Any) -> None:
        self.q.put((fn, args))

    def start(self) -> None:
        self._tick()

    def close(self) -> None:
        self._closed = True

    def drain(self, limit: int = 200) -> int:
        n = 0
        while n < limit:
            try:
                fn, args = self.q.get_nowait()
            except queue.Empty:
                break
            n += 1
            try:
                fn(*args)
            except Exception:
                log.error("UI callback failed: %s", traceback.format_exc())
        return n

    def _tick(self) -> None:
        if self._closed:
            return
        self.drain()
        try:
            self.root.after(self.interval, self._tick)
        except Exception:
            pass


# --------------------------------------------------------------------------- widgets

class Gauge:
    """Security score dial drawn on a Canvas: 270 degree arc, colour by grade."""

    def __init__(self, app: "GuiApp", parent: Any, size: int = 230):
        self.app, self.size = app, size
        self.canvas = app.tk.Canvas(parent, width=size, height=size, bg=C["panel"], highlightthickness=0)
        self.value = 0.0
        self._anim: Optional[str] = None
        self.score: Optional[int] = None
        self.grade = ""
        self.draw(None, "")

    def draw(self, score: Optional[int], grade: str, shown: Optional[float] = None) -> None:
        c, s = self.canvas, self.size
        pad = 22
        c.delete("all")
        box = (pad, pad, s - pad, s - pad)
        c.create_arc(*box, start=225, extent=-270, style="arc", width=16, outline=C["panel2"])
        if score is not None:
            color = GRADE_COLOR.get(grade, C["accent"])
            v = score if shown is None else shown
            if v > 0:
                c.create_arc(*box, start=225, extent=-270 * max(0.0, min(100.0, v)) / 100.0, style="arc", width=16, outline=color)
            c.create_text(s / 2, s / 2 - 8, text=str(int(round(v))), fill=C["text"], font=(FONT, 44, "bold"))
            c.create_text(s / 2, s / 2 + 38, text=f"Grade {grade}", fill=color, font=(FONT, 13, "bold"))
        else:
            c.create_text(s / 2, s / 2 - 8, text="--", fill=C["muted"], font=(FONT, 44, "bold"))
            c.create_text(s / 2, s / 2 + 38, text="No scan yet", fill=C["muted"], font=(FONT, 12))
        c.create_text(s / 2, s - 8, text="SECURITY SCORE", fill=C["muted"], font=(FONT, 8, "bold"))

    def set(self, score: Optional[int], grade: str = "") -> None:
        self.score, self.grade = score, grade
        if self._anim:
            try:
                self.canvas.after_cancel(self._anim)
            except Exception:
                pass
            self._anim = None
        if score is None:
            self.value = 0.0
            self.draw(None, "")
            return
        start, steps = self.value, 24

        def step(i: int = 1) -> None:
            v = start + (score - start) * (i / steps)
            self.draw(score, grade, v)
            if i < steps:
                self._anim = self.canvas.after(16, lambda: step(i + 1))
            else:
                self.value = float(score)
                self._anim = None

        step()


# --------------------------------------------------------------------------- application

class GuiApp:
    def __init__(self, tk: Any, ttk: Any, filedialog: Any, messagebox: Any, root: Any, config: Optional[Config] = None):
        self.tk, self.ttk, self.filedialog, self.messagebox, self.root = tk, ttk, filedialog, messagebox, root
        self.config = config or Config.load()
        self.signatures: Any = None
        self._sig_lock = threading.Lock()
        self.monitor: Any = None
        self.monitor_busy = False
        self.last_result: Any = None
        self.ui = UiBridge(root)
        self.status_var = tk.StringVar(value="Ready")
        self.pages: Dict[str, Any] = {}
        self.frames: Dict[str, Any] = {}
        self.nav_buttons: Dict[str, Any] = {}
        self.current = ""

        root.title(__app_name__)
        root.minsize(1100, 700)
        try:
            root.geometry("1220x780")
        except Exception:
            pass
        try:
            root.configure(bg=C["bg"])
        except Exception:
            pass
        self.apply_theme()
        self.build_shell()
        self.pages = {
            "dashboard": DashboardPage(self), "scan": ScanPage(self), "protection": ProtectionPage(self),
            "quarantine": QuarantinePage(self), "tools": ToolsPage(self), "settings": SettingsPage(self),
        }
        self.show("dashboard")
        self.ui.start()
        self.run_bg(self.ensure_signatures, on_done=lambda _s: self.pages["dashboard"].refresh())
        try:
            root.protocol("WM_DELETE_WINDOW", self.on_close)
        except Exception:
            pass

    # ---- infrastructure
    def run_bg(self, fn: Callable[[], Any], on_done: Optional[Callable[[Any], None]] = None,
               on_error: Optional[Callable[[BaseException], None]] = None, name: str = "aegis-worker") -> threading.Thread:
        def work() -> None:
            try:
                res = fn()
            except BaseException as exc:  # noqa: BLE001 - report everything to the UI
                log.error("background task failed: %s", traceback.format_exc())
                if on_error:
                    self.ui.post(on_error, exc)
                else:
                    self.ui.post(self.error_box, "Operation failed", f"{type(exc).__name__}: {exc}")
                return
            if on_done:
                self.ui.post(on_done, res)

        t = threading.Thread(target=work, name=name, daemon=True)
        t.start()
        return t

    def ensure_signatures(self) -> Any:
        with self._sig_lock:
            if self.signatures is None:
                from aegis.core.signatures import SignatureDB

                self.signatures = SignatureDB(self.config)
            return self.signatures

    def set_status(self, text: str) -> None:
        self.status_var.set(text)

    def error_box(self, title: str, msg: str) -> None:
        self.messagebox.showerror(title, msg)

    def save_config(self) -> None:
        """Persist the config without writing env-supplied secrets to disk."""
        cfg = self.config
        try:
            disk = json.loads(cfg.path.read_text(encoding="utf-8"))
        except Exception:
            disk = {}
        swapped: Dict[str, str] = {}
        for attr, env in SECRET_ENVS:
            val = os.environ.get(env)
            if val and getattr(cfg, attr, "") == val:
                swapped[attr] = val
                setattr(cfg, attr, disk.get(attr, ""))
        try:
            cfg.save()
        finally:
            for attr, val in swapped.items():
                setattr(cfg, attr, val)

    # ---- theme & shell
    def apply_theme(self) -> None:
        ttk = self.ttk
        s = ttk.Style(self.root)
        try:
            s.theme_use("clam")
        except Exception:
            pass
        s.configure(".", background=C["bg"], foreground=C["text"], font=(FONT, 10), bordercolor=C["border"],
                    lightcolor=C["panel"], darkcolor=C["panel"], troughcolor=C["panel2"], focuscolor=C["accent"])
        s.configure("TFrame", background=C["bg"])
        s.configure("Panel.TFrame", background=C["panel"])
        s.configure("Card.TFrame", background=C["panel"], relief="flat")
        s.configure("Side.TFrame", background=C["panel"])
        s.configure("TLabel", background=C["bg"], foreground=C["text"])
        s.configure("Panel.TLabel", background=C["panel"], foreground=C["text"])
        s.configure("Muted.TLabel", background=C["panel"], foreground=C["muted"])
        s.configure("MutedBg.TLabel", background=C["bg"], foreground=C["muted"])
        s.configure("H1.TLabel", background=C["bg"], font=(FONT, 20, "bold"))
        s.configure("H2.TLabel", background=C["panel"], font=(FONT, 12, "bold"))
        s.configure("Big.TLabel", background=C["panel"], font=(FONT, 22, "bold"))
        s.configure("Brand.TLabel", background=C["panel"], foreground=C["accent"], font=(FONT, 18, "bold"))
        s.configure("Good.TLabel", background=C["panel"], foreground=C["good"], font=(FONT, 12, "bold"))
        s.configure("Bad.TLabel", background=C["panel"], foreground=C["bad"], font=(FONT, 12, "bold"))
        s.configure("Warn.TLabel", background=C["warn"], foreground="#1b1300", font=(FONT, 10, "bold"))
        s.configure("Status.TLabel", background=C["panel"], foreground=C["muted"], font=(FONT, 9))
        s.configure("TButton", background=C["panel2"], foreground=C["text"], padding=(14, 7), borderwidth=0, relief="flat")
        s.map("TButton", background=[("active", C["border"]), ("disabled", C["panel"])],
              foreground=[("disabled", C["muted"])])
        s.configure("Accent.TButton", background=C["accent"], foreground="#ffffff", font=(FONT, 10, "bold"))
        s.map("Accent.TButton", background=[("active", C["accent_hi"]), ("pressed", C["accent_dn"]), ("disabled", C["panel2"])])
        s.configure("Danger.TButton", background="#7d2434", foreground="#ffffff")
        s.map("Danger.TButton", background=[("active", C["bad"]), ("disabled", C["panel2"])])
        s.configure("Warn.TButton", background="#1b1300", foreground=C["warn"])
        s.configure("Nav.TButton", background=C["panel"], foreground=C["muted"], anchor="w", padding=(18, 11),
                    font=(FONT, 11))
        s.map("Nav.TButton", background=[("active", C["panel2"])], foreground=[("active", C["text"])])
        s.configure("NavActive.TButton", background=C["panel2"], foreground=C["accent_hi"], anchor="w", padding=(18, 11),
                    font=(FONT, 11, "bold"))
        s.map("NavActive.TButton", background=[("active", C["panel2"])])
        s.configure("TCheckbutton", background=C["panel"], foreground=C["text"])
        s.map("TCheckbutton", background=[("active", C["panel"])])
        s.configure("TRadiobutton", background=C["panel"], foreground=C["text"])
        s.map("TRadiobutton", background=[("active", C["panel"])])
        s.configure("TEntry", fieldbackground=C["panel2"], foreground=C["text"], insertcolor=C["text"], padding=6,
                    bordercolor=C["border"])
        s.configure("TCombobox", fieldbackground=C["panel2"], foreground=C["text"], background=C["panel2"], padding=4,
                    arrowcolor=C["text"])
        s.configure("TSpinbox", fieldbackground=C["panel2"], foreground=C["text"], background=C["panel2"], padding=4,
                    arrowcolor=C["text"])
        s.configure("TProgressbar", background=C["accent"], troughcolor=C["panel2"], bordercolor=C["panel2"], thickness=8)
        s.configure("TNotebook", background=C["bg"], borderwidth=0, tabmargins=(0, 0, 0, 0))
        s.configure("TNotebook.Tab", background=C["panel"], foreground=C["muted"], padding=(16, 8), borderwidth=0)
        s.map("TNotebook.Tab", background=[("selected", C["panel2"])], foreground=[("selected", C["text"])])
        s.configure("Vertical.TScrollbar", background=C["panel2"], troughcolor=C["panel"], bordercolor=C["panel"],
                    arrowcolor=C["muted"])
        s.configure("Treeview", background=C["panel"], fieldbackground=C["panel"], foreground=C["text"], rowheight=28,
                    borderwidth=0)
        s.configure("Treeview.Heading", background=C["panel2"], foreground=C["muted"], relief="flat", padding=(8, 6),
                    font=(FONT, 9, "bold"))
        s.map("Treeview", background=[("selected", C["select"])], foreground=[("selected", "#ffffff")])
        s.map("Treeview.Heading", background=[("active", C["border"])])
        try:  # fixed_map workaround for tag colours
            s.map("Treeview", foreground=fixed_map(s, "foreground"), background=fixed_map(s, "background"))
        except Exception:
            pass
        try:
            self.root.option_add("*TCombobox*Listbox.background", C["panel2"])
            self.root.option_add("*TCombobox*Listbox.foreground", C["text"])
            self.root.option_add("*TCombobox*Listbox.selectBackground", C["select"])
        except Exception:
            pass

    def build_shell(self) -> None:
        tk, ttk = self.tk, self.ttk
        self.root.columnconfigure(1, weight=1)
        self.root.rowconfigure(0, weight=1)
        side = ttk.Frame(self.root, style="Side.TFrame", width=210)
        side.grid(row=0, column=0, sticky="ns")
        side.grid_propagate(False)
        ttk.Label(side, text="AEGIS", style="Brand.TLabel").pack(anchor="w", padx=22, pady=(24, 0))
        ttk.Label(side, text="Security Suite", style="Muted.TLabel").pack(anchor="w", padx=22, pady=(0, 22))
        for key, label in NAV:
            b = ttk.Button(side, text=label, style="Nav.TButton", command=lambda k=key: self.show(k))
            b.pack(fill="x")
            self.nav_buttons[key] = b
        ttk.Label(side, text=f"v{__version__}", style="Muted.TLabel").pack(side="bottom", anchor="w", padx=22, pady=14)
        self.content = ttk.Frame(self.root)
        self.content.grid(row=0, column=1, sticky="nsew")
        self.content.columnconfigure(0, weight=1)
        self.content.rowconfigure(0, weight=1)
        bar = ttk.Frame(self.root, style="Panel.TFrame")
        bar.grid(row=1, column=0, columnspan=2, sticky="ew")
        ttk.Label(bar, textvariable=self.status_var, style="Status.TLabel").pack(side="left", padx=14, pady=5)
        who = "Administrator" if is_admin() else "Standard user"
        ttk.Label(bar, text=f"{who}  |  user-mode protection", style="Status.TLabel").pack(side="right", padx=14)

    def page_frame(self, key: str) -> Any:
        f = self.ttk.Frame(self.content)
        f.grid(row=0, column=0, sticky="nsew")
        f.columnconfigure(0, weight=1)
        self.frames[key] = f
        return f

    def show(self, key: str) -> None:
        for k, f in self.frames.items():
            if k == key:
                f.grid()
                f.tkraise()
            else:
                f.grid_remove()
        for k, b in self.nav_buttons.items():
            b.configure(style="NavActive.TButton" if k == key else "Nav.TButton")
        self.current = key
        page = self.pages.get(key)
        if page and hasattr(page, "on_show"):
            page.on_show()

    # ---- shared widgets
    def heading(self, parent: Any, text: str, sub: str = "") -> Any:
        ttk = self.ttk
        box = ttk.Frame(parent)
        ttk.Label(box, text=text, style="H1.TLabel").pack(anchor="w")
        if sub:
            ttk.Label(box, text=sub, style="MutedBg.TLabel").pack(anchor="w", pady=(2, 0))
        return box

    def card(self, parent: Any, title: str = "") -> Any:
        ttk = self.ttk
        f = ttk.Frame(parent, style="Card.TFrame", padding=16)
        if title:
            ttk.Label(f, text=title, style="H2.TLabel").pack(anchor="w", pady=(0, 8))
        return f

    def text_box(self, parent: Any, height: int = 8, mono: bool = False) -> Any:
        tk = self.tk
        t = tk.Text(parent, height=height, wrap="word", bg=C["panel2"], fg=C["text"], insertbackground=C["text"],
                    relief="flat", borderwidth=0, padx=10, pady=8, font=(MONO if mono else FONT, 9 if mono else 10),
                    highlightthickness=0, selectbackground=C["select"])
        for sev, col in SEV_COLOR.items():
            t.tag_configure(sev, foreground=col, font=(FONT, 10, "bold"))
        t.tag_configure("h", foreground=C["accent_hi"], font=(FONT, 10, "bold"))
        t.tag_configure("muted", foreground=C["muted"])
        t.tag_configure("good", foreground=C["good"], font=(FONT, 10, "bold"))
        t.configure(state="disabled")
        return t

    def set_text(self, widget: Any, parts: List[tuple]) -> None:
        """parts: [(text, tag-or-None), ...]"""
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        for txt, tag in parts:
            widget.insert("end", txt, tag) if tag else widget.insert("end", txt)
        widget.configure(state="disabled")

    def tree(self, parent: Any, columns: List[tuple], height: int = 10, select: str = "extended") -> Any:
        """columns: [(id, heading, width)]"""
        ttk = self.ttk
        wrap = ttk.Frame(parent, style="Panel.TFrame")
        wrap.columnconfigure(0, weight=1)
        wrap.rowconfigure(0, weight=1)
        t = ttk.Treeview(wrap, columns=[c[0] for c in columns], show="headings", height=height, selectmode=select)
        for cid, head, width in columns:
            t.heading(cid, text=head)
            t.column(cid, width=width, minwidth=60, stretch=(cid == columns[-1][0] or cid == "title"))
        sb = ttk.Scrollbar(wrap, orient="vertical", command=t.yview)
        t.configure(yscrollcommand=sb.set)
        t.grid(row=0, column=0, sticky="nsew")
        sb.grid(row=0, column=1, sticky="ns")
        for sev, col in SEV_COLOR.items():
            t.tag_configure(sev, foreground=col)
        t.wrap = wrap  # type: ignore[attr-defined]
        return t

    # ---- protection control (shared by Dashboard and Protection pages)
    @property
    def protection_on(self) -> bool:
        return bool(self.monitor and self.monitor.running)

    def toggle_protection(self) -> None:
        if self.monitor_busy:
            return
        self.monitor_busy = True
        starting = not self.protection_on
        self.set_status("Starting real-time protection..." if starting else "Stopping real-time protection...")

        def work() -> Any:
            if starting:
                from aegis.realtime.monitor import RealtimeMonitor

                sigs = self.ensure_signatures()
                mon = RealtimeMonitor(self.config, sigs, on_event=lambda f: self.ui.post(self.pages["protection"].add_event, f))
                mon.start()
                return mon
            if self.monitor:
                self.monitor.stop()
            return None

        def done(mon: Any) -> None:
            self.monitor_busy = False
            if starting:
                self.monitor = mon
            self.set_status("Real-time protection is ON" if starting else "Real-time protection is OFF")
            self.pages["dashboard"].refresh()
            self.pages["protection"].refresh_state()

        def err(exc: BaseException) -> None:
            self.monitor_busy = False
            self.set_status("Real-time protection failed")
            self.error_box("Real-time protection", f"{type(exc).__name__}: {exc}")
            self.pages["protection"].refresh_state()

        self.run_bg(work, done, err)

    def on_close(self) -> None:
        if self.protection_on and not self.messagebox.askyesno(
                "Exit Aegis",
                "Real-time protection is running inside this window and will stop when you close it.\n\n"
                "For always-on protection use `aegis install-service` (runs at logon in the background).\n\nClose anyway?"):
            return
        self.ui.close()
        try:
            if self.monitor:
                self.monitor.stop(timeout=2.0)
        except Exception:
            pass
        self.root.destroy()


# --------------------------------------------------------------------------- pages

class Page:
    key = ""

    def __init__(self, app: GuiApp):
        self.app = app
        self.tk, self.ttk = app.tk, app.ttk
        self.frame = app.page_frame(self.key)
        self.frame.configure(padding=(28, 22))
        self.build()

    def build(self) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    def on_show(self) -> None:
        pass


# ---- Dashboard

class DashboardPage(Page):
    key = "dashboard"

    def build(self) -> None:
        app, ttk, tk = self.app, self.ttk, self.tk
        f = self.frame
        f.columnconfigure(0, weight=1)
        f.columnconfigure(1, weight=1)
        app.heading(f, "Dashboard", "Your device's security posture at a glance").grid(row=0, column=0, columnspan=2, sticky="w")

        self.banner = ttk.Frame(f, style="Panel.TFrame")
        self.banner_label = tk.Label(self.banner, text="", bg=C["warn"], fg="#1b1300", font=(FONT, 10, "bold"),
                                     anchor="w", padx=14, pady=10)
        self.banner_label.pack(side="left", fill="x", expand=True)
        self.banner_btn = ttk.Button(self.banner, text="Restart as Administrator", command=self.elevate)
        self.banner_btn.pack(side="right", padx=(8, 0))
        self.banner.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(14, 0))

        score = app.card(f, "Security score")
        score.grid(row=2, column=0, sticky="nsew", pady=(14, 0), padx=(0, 8), rowspan=2)
        self.gauge = Gauge(app, score)
        self.gauge.canvas.pack(pady=(4, 8))
        self.last_scan = ttk.Label(score, text="Last scan: never", style="Muted.TLabel")
        self.last_scan.pack()
        row = ttk.Frame(score, style="Panel.TFrame")
        row.pack(pady=(14, 0))
        ttk.Button(row, text="Quick scan", style="Accent.TButton", command=lambda: self.go_scan("quick")).pack(side="left", padx=4)
        ttk.Button(row, text="Full scan", command=lambda: self.go_scan("full")).pack(side="left", padx=4)
        ttk.Button(row, text="Audit", command=lambda: self.go_scan("audit")).pack(side="left", padx=4)

        threats = app.card(f, "Findings by severity")
        threats.grid(row=2, column=1, sticky="nsew", pady=(14, 0), padx=(8, 0))
        self.sev_labels: Dict[str, Any] = {}
        grid = ttk.Frame(threats, style="Panel.TFrame")
        grid.pack(fill="x")
        for i, sev in enumerate(("critical", "high", "medium", "low", "info")):
            grid.columnconfigure(i, weight=1)
            lab = tk.Label(grid, text="-", bg=C["panel"], fg=SEV_COLOR[sev], font=(FONT, 26, "bold"))
            lab.grid(row=0, column=i)
            tk.Label(grid, text=sev.capitalize(), bg=C["panel"], fg=C["muted"], font=(FONT, 9)).grid(row=1, column=i)
            self.sev_labels[sev] = lab

        prot = app.card(f, "Protection")
        prot.grid(row=3, column=1, sticky="nsew", pady=(14, 0), padx=(8, 0))
        self.prot_status = ttk.Label(prot, text="Real-time protection: OFF", style="Bad.TLabel")
        self.prot_status.pack(anchor="w")
        self.prot_detail = ttk.Label(prot, text="", style="Muted.TLabel", wraplength=460, justify="left")
        self.prot_detail.pack(anchor="w", pady=(2, 8))
        self.prot_btn = ttk.Button(prot, text="Turn on real-time protection", style="Accent.TButton", command=app.toggle_protection)
        self.prot_btn.pack(anchor="w")
        self.sig_label = ttk.Label(prot, text="Signatures: loading...", style="Muted.TLabel", wraplength=460, justify="left")
        self.sig_label.pack(anchor="w", pady=(12, 0))
        f.rowconfigure(3, weight=1)

    def go_scan(self, mode: str) -> None:
        self.app.show("scan")
        self.app.pages["scan"].start(mode)

    def elevate(self) -> None:
        if restart_as_admin():
            self.app.ui.close()
            if self.app.monitor:
                self.app.monitor.stop(timeout=2.0)
            self.app.root.destroy()
        else:
            self.app.messagebox.showinfo("Administrator rights", "Elevation was cancelled or is not available on this system.\n"
                                         "On Linux/macOS run Aegis with sudo.")

    def on_show(self) -> None:
        self.refresh()

    def refresh(self) -> None:
        app = self.app
        admin = is_admin()
        if admin:
            self.banner.grid_remove()
        else:
            self.banner_label.configure(text="Running without administrator rights - process, service, firewall and "
                                             "registry checks will be incomplete.")
            if IS_WINDOWS:
                self.banner_btn.pack(side="right", padx=(8, 0))
            else:
                self.banner_btn.pack_forget()
            self.banner.grid()
        result = app.last_result
        if result is None:
            try:
                from aegis.core.engine import last_scan

                result = last_scan(app.config)
                app.last_result = result
            except Exception:
                result = None
        if result is not None:
            from aegis.core.scoring import security_score

            score, grade = security_score(result)
            self.gauge.set(score, grade)
            self.last_scan.configure(text=f"Last scan: {fmt_time(result.finished or result.started)}  ({result.profile})")
            counts = result.counts()
            for sev, lab in self.sev_labels.items():
                lab.configure(text=str(counts.get(sev, 0)))
        else:
            self.gauge.set(None)
            self.last_scan.configure(text="Last scan: never - run a Quick scan to get started")
        on = app.protection_on
        self.prot_status.configure(text=f"Real-time protection: {'ON' if on else 'OFF'}", style="Good.TLabel" if on else "Bad.TLabel")
        self.prot_btn.configure(text="Turn off real-time protection" if on else "Turn on real-time protection",
                                style="TButton" if on else "Accent.TButton")
        if on:
            st = app.monitor.status()
            self.prot_detail.configure(text=f"File, process, ransomware and persistence guards active. Watching "
                                            f"{len(st['watched'])} folders, {st['canaries']} ransomware canaries, "
                                            f"{st['stats'].get('files_scanned', 0)} files scanned this session.")
        else:
            self.prot_detail.configure(text="Scans files as they are written, checks new processes, watches for ransomware "
                                            "behaviour and new autorun entries. User-mode protection (no kernel driver).")
        sigs = app.signatures
        if sigs is None:
            self.sig_label.configure(text="Signatures: loading...")
        else:
            s = sigs.summary()
            newest = 0.0
            try:
                for p in app.config.signatures_dir.rglob("*"):
                    if p.is_file():
                        newest = max(newest, p.stat().st_mtime)
            except OSError:
                pass
            updated = dt.datetime.fromtimestamp(newest).strftime("%d %b %Y, %H:%M") if newest else "bundled set only - run Update"
            self.sig_label.configure(text=f"Signatures: {s['hashes']:,} hashes, {s['content_rules']} content rules, "
                                          f"{s['yara_rule_files']} YARA files, {s['malicious_ips']:,} bad IPs, "
                                          f"{s['malicious_domains']:,} bad domains.  Last update: {updated}")


# ---- Scan

class ScanPage(Page):
    key = "scan"

    def build(self) -> None:
        app, ttk, tk = self.app, self.ttk, self.tk
        f = self.frame
        f.columnconfigure(0, weight=1)
        f.rowconfigure(3, weight=1)
        self.cancel_evt: Optional[threading.Event] = None
        self.scanning = False
        self.findings: Dict[str, Finding] = {}
        self._last_log = 0.0
        app.heading(f, "Scan", "Choose how deep to look").grid(row=0, column=0, sticky="w")

        ctl = app.card(f)
        ctl.grid(row=1, column=0, sticky="ew", pady=(12, 0))
        self.mode = tk.StringVar(value="quick")
        row = ttk.Frame(ctl, style="Panel.TFrame")
        row.pack(fill="x")
        for val, label in (("quick", "Quick"), ("full", "Full"), ("audit", "Audit"), ("custom", "Custom")):
            ttk.Radiobutton(row, text=label, value=val, variable=self.mode, command=self.on_mode).pack(side="left", padx=(0, 16))
        self.start_btn = ttk.Button(row, text="Start scan", style="Accent.TButton", command=lambda: self.start())
        self.start_btn.pack(side="right")
        self.cancel_btn = ttk.Button(row, text="Cancel", command=self.cancel)
        self.cancel_btn.pack(side="right", padx=8)
        self.cancel_btn.state(["disabled"])
        self.mode_hint = ttk.Label(ctl, text="", style="Muted.TLabel")
        self.mode_hint.pack(anchor="w", pady=(8, 0))

        self.custom = ttk.Frame(ctl, style="Panel.TFrame")
        prow = ttk.Frame(self.custom, style="Panel.TFrame")
        prow.pack(fill="x", pady=(10, 0))
        self.path_var = tk.StringVar()
        ttk.Entry(prow, textvariable=self.path_var).pack(side="left", fill="x", expand=True)
        ttk.Button(prow, text="Folder...", command=self.pick_folder).pack(side="left", padx=(8, 0))
        ttk.Button(prow, text="File...", command=self.pick_file).pack(side="left", padx=(8, 0))
        self.scanner_vars: Dict[str, Any] = {}
        self.scanner_box = ttk.Frame(self.custom, style="Panel.TFrame")
        self.scanner_box.pack(fill="x", pady=(10, 0))
        self._load_scanner_choices()

        prog = ttk.Frame(f)
        prog.grid(row=2, column=0, sticky="ew", pady=(12, 0))
        prog.columnconfigure(0, weight=1)
        self.progress = ttk.Progressbar(prog, mode="indeterminate")
        self.progress.grid(row=0, column=0, sticky="ew")
        self.status = ttk.Label(prog, text="Idle", style="MutedBg.TLabel")
        self.status.grid(row=1, column=0, sticky="w", pady=(4, 0))
        self.log_box = app.text_box(prog, height=4, mono=True)
        self.log_box.grid(row=2, column=0, sticky="ew", pady=(6, 0))

        res = ttk.Frame(f)
        res.grid(row=3, column=0, sticky="nsew", pady=(12, 0))
        res.columnconfigure(0, weight=3)
        res.columnconfigure(1, weight=2)
        res.rowconfigure(0, weight=1)
        self.tree = app.tree(res, [("severity", "Severity", 90), ("category", "Category", 110), ("title", "Title", 280),
                                   ("location", "Location", 260)], height=9)
        self.tree.wrap.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        self.tree.bind("<<TreeviewSelect>>", lambda _e: self.show_detail())
        self.detail = app.text_box(res, height=9)
        self.detail.grid(row=0, column=1, sticky="nsew")

        btns = ttk.Frame(f)
        btns.grid(row=4, column=0, sticky="ew", pady=(10, 0))
        self.fix_btn = ttk.Button(btns, text="Fix selected", style="Accent.TButton", command=self.fix_selected)
        self.fix_btn.pack(side="left")
        ttk.Button(btns, text="Ignore (allow-list)", command=self.ignore_selected).pack(side="left", padx=8)
        ttk.Button(btns, text="Export report", command=self.export).pack(side="left")
        self.count_label = ttk.Label(btns, text="", style="MutedBg.TLabel")
        self.count_label.pack(side="right")
        self.on_mode()

    HINTS = {
        "quick": "Processes, autoruns, downloads/desktop/temp/startup folders, browsers, network. Typically a few minutes.",
        "full": "Everything in Quick plus every file on every drive, system hardening, installed software and secrets. Can take a long time.",
        "audit": "Security configuration only: hardening checks, installed software, network exposure, browsers. No file scan.",
        "custom": "Pick a folder or file and which scanners to run.",
    }

    def _load_scanner_choices(self) -> None:
        try:
            from aegis.scanners.base import REGISTRY, load_all

            load_all()
            names = sorted(REGISTRY)
        except Exception:
            names = []
        for i, name in enumerate(names):
            var = self.tk.BooleanVar(value=name == "files")
            self.scanner_vars[name] = var
            ttk = self.ttk
            ttk.Checkbutton(self.scanner_box, text=name, variable=var).grid(row=i // 4, column=i % 4, sticky="w", padx=(0, 18), pady=2)

    def on_mode(self) -> None:
        mode = self.mode.get()
        self.mode_hint.configure(text=self.HINTS.get(mode, ""))
        if mode == "custom":
            self.custom.pack(fill="x")
        else:
            self.custom.pack_forget()

    def pick_folder(self) -> None:
        d = self.app.filedialog.askdirectory(title="Folder to scan")
        if d:
            self.path_var.set(d)

    def pick_file(self) -> None:
        d = self.app.filedialog.askopenfilename(title="File to scan")
        if d:
            self.path_var.set(d)

    # ---- running
    def log(self, text: str) -> None:
        w = self.log_box
        w.configure(state="normal")
        w.insert("end", text + "\n")
        try:
            if int(w.index("end-1c").split(".")[0]) > 400:
                w.delete("1.0", "50.0")
        except Exception:
            pass
        w.see("end")
        w.configure(state="disabled")

    def start(self, mode: Optional[str] = None) -> None:
        if self.scanning:
            return
        if mode:
            self.mode.set(mode)
            self.on_mode()
        mode = self.mode.get()
        scanners: Optional[List[str]] = None
        paths: Optional[List[Path]] = None
        if mode == "custom":
            scanners = [n for n, v in self.scanner_vars.items() if v.get()]
            if not scanners:
                self.app.messagebox.showwarning("Custom scan", "Select at least one scanner.")
                return
            p = self.path_var.get().strip()
            if p:
                paths = [Path(p)]
            elif "files" in scanners:
                self.app.messagebox.showwarning("Custom scan", "Choose a folder or file for the files scanner.")
                return
        self.scanning = True
        self.cancel_evt = threading.Event()
        self.findings.clear()
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        self.app.set_text(self.detail, [])
        self.app.set_text(self.log_box, [])
        self.start_btn.state(["disabled"])
        self.cancel_btn.state(["!disabled"])
        self.progress.start(12)
        self.status.configure(text=f"Running {mode} scan...")
        self.app.set_status(f"Scanning ({mode})...")
        cancel = self.cancel_evt
        t0 = time.time()

        def progress(scanner: str, msg: str) -> None:
            now = time.time()
            if now - self._last_log < 0.12 and msg not in ("done",) and not msg.startswith("starting"):
                return
            self._last_log = now
            self.app.ui.post(self.log, f"[{scanner}] {msg}")

        def work() -> Any:
            from aegis.core.engine import ScanEngine

            sigs = self.app.ensure_signatures()
            engine = ScanEngine(self.app.config, sigs)
            return engine.scan(profile=mode, scanners=scanners, paths=paths, progress=progress, cancel=cancel,
                               on_finding=lambda fnd: self.app.ui.post(self.add_finding, fnd))

        def done(result: Any) -> None:
            self.finish(result, time.time() - t0)

        def err(exc: BaseException) -> None:
            self.finish(None, 0, f"{type(exc).__name__}: {exc}")

        self.app.run_bg(work, done, err, name="aegis-scan")

    def cancel(self) -> None:
        if self.cancel_evt:
            self.cancel_evt.set()
            self.status.configure(text="Cancelling...")

    def finish(self, result: Any, seconds: float, error: str = "") -> None:
        self.scanning = False
        self.progress.stop()
        self.start_btn.state(["!disabled"])
        self.cancel_btn.state(["disabled"])
        if error or result is None:
            self.status.configure(text=f"Scan failed: {error}")
            self.app.set_status("Scan failed")
            return
        self.app.last_result = result
        self.populate(result)
        cancelled = bool(self.cancel_evt and self.cancel_evt.is_set())
        n = len(result.findings)
        self.status.configure(text=f"{'Cancelled' if cancelled else 'Finished'} in {seconds:.0f}s - {n} finding(s)"
                                   + (f", {len(result.errors)} scanner error(s)" if result.errors else ""))
        self.app.set_status("Scan complete" if not cancelled else "Scan cancelled")
        self.app.pages["dashboard"].refresh()

    def add_finding(self, f: Finding) -> None:
        if f.fingerprint in self.findings:
            return
        self.findings[f.fingerprint] = f
        self.tree.insert("", "end", iid=f.fingerprint, values=self._row(f), tags=(f.severity.name.lower(),))
        self._update_count()

    def _row(self, f: Finding) -> tuple:
        return (f.severity.label, f.category, f.title, f.location)

    def populate(self, result: Any) -> None:
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        self.findings = {}
        for f in result.sorted_findings():
            self.findings[f.fingerprint] = f
            self.tree.insert("", "end", iid=f.fingerprint, values=self._row(f), tags=(f.severity.name.lower(),))
        self._update_count()

    def _update_count(self) -> None:
        c: Dict[str, int] = {}
        for f in self.findings.values():
            c[f.severity.name.lower()] = c.get(f.severity.name.lower(), 0) + 1
        order = [f"{c[s]} {s}" for s in ("critical", "high", "medium", "low", "info") if c.get(s)]
        self.count_label.configure(text=f"{len(self.findings)} findings" + (f"  ({', '.join(order)})" if order else ""))

    def selected(self) -> List[Finding]:
        return [self.findings[i] for i in self.tree.selection() if i in self.findings]

    def show_detail(self) -> None:
        sel = self.selected()
        if not sel:
            return
        f = sel[0]
        parts: List[tuple] = [(f"{f.severity.label.upper()}  ", f.severity.name.lower()), (f"{f.title}\n", "h"),
                              (f"{f.rule_id}  |  {f.category}  |  {f.scanner}\n\n", "muted")]
        if f.description:
            parts.append((f"{f.description}\n\n", None))
        if f.location:
            parts += [("Location\n", "h"), (f"{f.location}\n\n", None)]
        if f.recommendation:
            parts += [("Recommendation\n", "h"), (f"{f.recommendation}\n\n", None)]
        if f.remediation:
            parts += [("Automatic fix\n", "h"), (f"{f.remediation.description or f.remediation.action}\n\n", None)]
        if f.mitre:
            parts += [("MITRE ATT&CK\n", "h"), (", ".join(f.mitre) + "\n\n", None)]
        if f.evidence:
            parts += [("Evidence\n", "h"), (json.dumps(f.evidence, indent=2, default=str)[:4000] + "\n", "muted")]
        self.app.set_text(self.detail, parts)

    # ---- actions
    def fix_selected(self) -> None:
        sel = self.selected()
        if not sel:
            self.app.messagebox.showinfo("Fix selected", "Select one or more findings first.")
            return
        fixable = [f for f in sel if f.remediation]
        if not fixable:
            self.app.messagebox.showinfo("Fix selected", "None of the selected findings has an automatic fix.\n"
                                         "Follow the recommendation shown in the detail pane.")
            return
        lines = "\n".join(f"- {f.remediation.description or f.remediation.action}: {f.title}" for f in fixable[:12])
        more = f"\n...and {len(fixable) - 12} more" if len(fixable) > 12 else ""
        if not self.app.messagebox.askyesno("Confirm fixes", f"Apply {len(fixable)} fix(es)?\n\n{lines}{more}\n\n"
                                            "Quarantined files can be restored from the Quarantine page; registry, "
                                            "hosts and task changes are backed up first."):
            return
        self.fix_btn.state(["disabled"])
        self.app.set_status("Applying fixes...")

        def work() -> List[tuple]:
            from aegis.core.remediation import apply_remediation

            return [(f, *apply_remediation(f, self.app.config)) for f in fixable]

        def done(results: List[tuple]) -> None:
            self.fix_btn.state(["!disabled"])
            ok = [r for r in results if r[1]]
            bad = [r for r in results if not r[1]]
            for f, _o, _m in ok:
                if f.fingerprint in self.findings:
                    self.tree.delete(f.fingerprint)
                    del self.findings[f.fingerprint]
                    if self.app.last_result:
                        self.app.last_result.findings = [x for x in self.app.last_result.findings
                                                         if x.fingerprint != f.fingerprint]
            self._update_count()
            self.app.set_status(f"{len(ok)} fix(es) applied, {len(bad)} failed")
            msg = f"{len(ok)} fix(es) applied."
            if bad:
                msg += "\n\nFailed:\n" + "\n".join(f"- {f.title}: {m}" for f, _o, m in bad[:8])
            (self.app.messagebox.showwarning if bad else self.app.messagebox.showinfo)("Fix results", msg)
            self.app.pages["quarantine"].refresh()
            self.app.pages["dashboard"].refresh()

        self.app.run_bg(work, done)

    def ignore_selected(self) -> None:
        sel = self.selected()
        if not sel:
            return
        if not self.app.messagebox.askyesno("Ignore findings", f"Add {len(sel)} finding(s) to the allow-list? "
                                            "They will no longer be reported in future scans."):
            return
        cfg = self.app.config
        for f in sel:
            if f.fingerprint not in cfg.allowlist_fingerprints:
                cfg.allowlist_fingerprints.append(f.fingerprint)
            if f.fingerprint in self.findings:
                self.tree.delete(f.fingerprint)
                del self.findings[f.fingerprint]
        self.app.save_config()
        self._update_count()
        self.app.set_status(f"{len(sel)} finding(s) allow-listed")

    def export(self) -> None:
        result = self.app.last_result
        if result is None:
            self.app.messagebox.showinfo("Export report", "Run a scan first.")
            return
        stamp = dt.datetime.now().strftime("%Y%m%d-%H%M")
        path = self.app.filedialog.asksaveasfilename(
            title="Export report", defaultextension=".html", initialfile=f"aegis-report-{stamp}.html",
            filetypes=[("HTML report", "*.html"), ("JSON", "*.json"), ("Text", "*.txt")])
        if not path:
            return

        def work() -> str:
            if path.lower().endswith(".json"):
                Path(path).write_text(result.to_json(), encoding="utf-8")
            else:
                from aegis.core.report import write_report

                write_report(result, path)
            return path

        self.app.run_bg(work, lambda p: self.app.set_status(f"Report saved to {p}"))


# ---- Protection

class ProtectionPage(Page):
    key = "protection"
    MAX_ROWS = 500

    def build(self) -> None:
        app, ttk, tk = self.app, self.ttk, self.tk
        f = self.frame
        f.columnconfigure(0, weight=1)
        f.rowconfigure(3, weight=1)
        app.heading(f, "Protection", "Real-time file, process, ransomware and persistence guards").grid(row=0, column=0, sticky="w")
        top = app.card(f)
        top.grid(row=1, column=0, sticky="ew", pady=(12, 0))
        top.columnconfigure(0, weight=1)
        self.state_label = ttk.Label(top, text="Real-time protection is OFF", style="Bad.TLabel")
        self.state_label.grid(row=0, column=0, sticky="w")
        self.toggle = ttk.Button(top, text="Turn on", style="Accent.TButton", command=app.toggle_protection)
        self.toggle.grid(row=0, column=1, sticky="e")
        ttk.Label(top, text="Aegis protects in user mode: it reacts within about a second of file or process activity "
                            "but, unlike a kernel driver, cannot block an action before it happens.",
                  style="Muted.TLabel", wraplength=900, justify="left").grid(row=1, column=0, columnspan=2, sticky="w", pady=(6, 10))

        cfg = app.config
        self.vars = {
            "auto_quarantine": tk.BooleanVar(value=cfg.auto_quarantine),
            "realtime_kill_malicious_processes": tk.BooleanVar(value=cfg.realtime_kill_malicious_processes),
            "ransomware_canaries": tk.BooleanVar(value=cfg.ransomware_canaries),
            "notifications": tk.BooleanVar(value=cfg.notifications),
        }
        opts = ttk.Frame(top, style="Panel.TFrame")
        opts.grid(row=2, column=0, columnspan=2, sticky="w")
        labels = {
            "auto_quarantine": "Auto-quarantine detected files",
            "realtime_kill_malicious_processes": "Kill switch: terminate malicious processes",
            "ransomware_canaries": "Ransomware canary files",
            "notifications": "Desktop notifications",
        }
        for i, (key, var) in enumerate(self.vars.items()):
            ttk.Checkbutton(opts, text=labels[key], variable=var, command=self.apply_options).grid(
                row=i // 2, column=i % 2, sticky="w", padx=(0, 28), pady=2)
        sev_row = ttk.Frame(opts, style="Panel.TFrame")
        sev_row.grid(row=2, column=0, columnspan=2, sticky="w", pady=(6, 0))
        ttk.Label(sev_row, text="Auto-quarantine minimum severity:", style="Panel.TLabel").pack(side="left")
        self.min_sev = tk.StringVar(value=cfg.auto_quarantine_min_severity.lower())
        cb = ttk.Combobox(sev_row, textvariable=self.min_sev, values=["medium", "high", "critical"], width=10, state="readonly")
        cb.pack(side="left", padx=8)
        cb.bind("<<ComboboxSelected>>", lambda _e: self.apply_options())
        tools = ttk.Frame(top, style="Panel.TFrame")
        tools.grid(row=3, column=0, columnspan=2, sticky="w", pady=(10, 0))
        ttk.Button(tools, text="Resume suspended processes", command=self.resume_suspended).pack(side="left")
        ttk.Button(tools, text="Remove canary files", command=self.remove_canaries).pack(side="left", padx=8)

        ttk.Label(f, text="Live event feed", style="H1.TLabel", font=(FONT, 13, "bold")).grid(row=2, column=0, sticky="w", pady=(14, 4))
        self.feed = app.tree(f, [("time", "Time", 80), ("severity", "Severity", 80), ("title", "Event", 320),
                                 ("location", "Details", 420)], height=10)
        self.feed.wrap.grid(row=3, column=0, sticky="nsew")
        self._load_history()

    def _load_history(self) -> None:
        p = self.app.config.logs_dir / "realtime_events.jsonl"
        try:
            lines = p.read_text(encoding="utf-8").splitlines()[-60:]
        except OSError:
            return
        for line in lines:
            try:
                d = json.loads(line)
                sev = str(d.get("severity", "info")).lower()
                self.feed.insert("", 0, values=(str(d.get("time", ""))[11:19], sev.capitalize(), d.get("title", ""),
                                                d.get("location", "")), tags=(sev,))
            except ValueError:
                continue

    def add_event(self, f: Finding) -> None:
        sev = f.severity.name.lower()
        self.feed.insert("", 0, values=(dt.datetime.now().strftime("%H:%M:%S"), f.severity.label, f.title, f.location), tags=(sev,))
        kids = self.feed.get_children()
        for iid in kids[self.MAX_ROWS:]:
            self.feed.delete(iid)
        if self.app.current == "dashboard":
            self.app.pages["dashboard"].refresh()

    def on_show(self) -> None:
        self.refresh_state()

    def refresh_state(self) -> None:
        on = self.app.protection_on
        self.state_label.configure(text=f"Real-time protection is {'ON' if on else 'OFF'}",
                                   style="Good.TLabel" if on else "Bad.TLabel")
        self.toggle.configure(text="Turn off" if on else "Turn on", style="TButton" if on else "Accent.TButton")

    def apply_options(self) -> None:
        cfg = self.app.config
        for key, var in self.vars.items():
            setattr(cfg, key, bool(var.get()))
        cfg.auto_quarantine_min_severity = self.min_sev.get()
        self.app.save_config()  # the monitor shares this Config object, so changes apply live
        self.app.set_status("Protection settings saved")

    def resume_suspended(self) -> None:
        mon = self.app.monitor
        pids = sorted(mon.ransomware.suspended) if mon else []
        if not pids:
            self.app.messagebox.showinfo("Suspended processes", "Aegis has not suspended any processes.")
            return
        if self.app.messagebox.askyesno("Resume processes", f"Resume suspended process(es) {pids}?\n"
                                        "Only do this if you are sure it was a false alarm."):
            ok = [p for p in pids if mon.ransomware.resume(p)]
            self.app.set_status(f"Resumed {len(ok)} process(es)")

    def remove_canaries(self) -> None:
        mon = self.app.monitor
        if mon is None:
            self.app.messagebox.showinfo("Canary files", "Start real-time protection first.")
            return
        if self.app.messagebox.askyesno("Remove canary files", "Delete all hidden ransomware canary files? "
                                        "They are recreated the next time protection starts."):
            self.app.set_status(f"Removed {mon.remove_canaries()} canary file(s)")


# ---- Quarantine

class QuarantinePage(Page):
    key = "quarantine"

    def build(self) -> None:
        app, ttk = self.app, self.ttk
        f = self.frame
        f.columnconfigure(0, weight=1)
        f.rowconfigure(1, weight=1)
        app.heading(f, "Quarantine", "Neutralised files are stored encrypted and cannot run").grid(row=0, column=0, sticky="w")
        self.items: Dict[str, Any] = {}
        self.tree = app.tree(f, [("when", "Quarantined", 140), ("threat", "Threat", 240), ("size", "Size", 80),
                                 ("path", "Original location", 480)], height=14)
        self.tree.wrap.grid(row=1, column=0, sticky="nsew", pady=(12, 0))
        row = ttk.Frame(f)
        row.grid(row=2, column=0, sticky="ew", pady=(10, 0))
        ttk.Button(row, text="Restore", command=self.restore).pack(side="left")
        ttk.Button(row, text="Delete permanently", style="Danger.TButton", command=self.delete).pack(side="left", padx=8)
        ttk.Button(row, text="Refresh", command=self.refresh).pack(side="left")
        self.count = ttk.Label(row, text="", style="MutedBg.TLabel")
        self.count.pack(side="right")

    def on_show(self) -> None:
        self.refresh()

    def refresh(self) -> None:
        def work() -> list:
            from aegis.core.quarantine import Quarantine

            return Quarantine(self.app.config).list()

        def done(items: list) -> None:
            for iid in self.tree.get_children():
                self.tree.delete(iid)
            self.items = {i.id: i for i in items}
            for i in items:
                self.tree.insert("", "end", iid=i.id, values=(fmt_time(i.quarantined_at), i.threat, human_size(i.size), i.original_path))
            self.count.configure(text=f"{len(items)} item(s)")

        self.app.run_bg(work, done)

    def _sel(self) -> List[Any]:
        return [self.items[i] for i in self.tree.selection() if i in self.items]

    def restore(self) -> None:
        sel = self._sel()
        if not sel:
            return
        if not self.app.messagebox.askyesno("Restore", f"Restore {len(sel)} file(s) to their original location?\n\n"
                                            "Only restore files you are certain are safe (false positive)."):
            return

        def work() -> List[str]:
            from aegis.core.quarantine import Quarantine

            q, errors = Quarantine(self.app.config), []
            for it in sel:
                try:
                    q.restore(it.id)
                except Exception as exc:
                    errors.append(f"{it.original_path}: {exc}")
            return errors

        def done(errors: List[str]) -> None:
            self.refresh()
            if errors:
                self.app.messagebox.showerror("Restore", "\n".join(errors[:8]))
            else:
                self.app.set_status(f"Restored {len(sel)} file(s)")

        self.app.run_bg(work, done)

    def delete(self) -> None:
        sel = self._sel()
        if not sel:
            return
        if not self.app.messagebox.askyesno("Delete permanently", f"Permanently delete {len(sel)} quarantined file(s)? "
                                            "This cannot be undone."):
            return

        def work() -> int:
            from aegis.core.quarantine import Quarantine

            q = Quarantine(self.app.config)
            for it in sel:
                q.delete(it.id)
            return len(sel)

        self.app.run_bg(work, lambda n: (self.refresh(), self.app.set_status(f"Deleted {n} item(s)")))


# ---- Tools

class ToolsPage(Page):
    key = "tools"

    def build(self) -> None:
        app, ttk, tk = self.app, self.ttk, self.tk
        f = self.frame
        f.rowconfigure(1, weight=1)
        app.heading(f, "Tools", "Check links, passwords and files; keep signatures fresh").grid(row=0, column=0, sticky="w")
        nb = ttk.Notebook(f)
        nb.grid(row=1, column=0, sticky="nsew", pady=(12, 0))
        self.nb = nb

        # URL checker
        t1 = ttk.Frame(nb, style="Panel.TFrame", padding=18)
        nb.add(t1, text="URL checker")
        ttk.Label(t1, text="Paste a link before you click it.", style="Muted.TLabel").pack(anchor="w")
        r = ttk.Frame(t1, style="Panel.TFrame")
        r.pack(fill="x", pady=8)
        self.url_var = tk.StringVar()
        e = ttk.Entry(r, textvariable=self.url_var)
        e.pack(side="left", fill="x", expand=True)
        e.bind("<Return>", lambda _e: self.check_url())
        ttk.Button(r, text="Check", style="Accent.TButton", command=self.check_url).pack(side="left", padx=(8, 0))
        self.url_out = app.text_box(t1, height=10)
        self.url_out.pack(fill="both", expand=True)

        # Password
        t2 = ttk.Frame(nb, style="Panel.TFrame", padding=18)
        nb.add(t2, text="Password check")
        ttk.Label(t2, text="Checks strength locally and breach exposure via the k-anonymity range API: only the first 5 "
                           "characters of the SHA-1 hash leave your PC, never the password.",
                  style="Muted.TLabel", wraplength=800, justify="left").pack(anchor="w")
        r = ttk.Frame(t2, style="Panel.TFrame")
        r.pack(fill="x", pady=8)
        self.pw_var = tk.StringVar()
        self.pw_entry = ttk.Entry(r, textvariable=self.pw_var, show="*")
        self.pw_entry.pack(side="left", fill="x", expand=True)
        self.pw_show = tk.BooleanVar(value=False)
        ttk.Checkbutton(r, text="Show", variable=self.pw_show, command=lambda: self.pw_entry.configure(show="" if self.pw_show.get() else "*")).pack(side="left", padx=8)
        self.pw_online = tk.BooleanVar(value=True)
        ttk.Checkbutton(r, text="Breach lookup", variable=self.pw_online).pack(side="left", padx=(0, 8))
        ttk.Button(r, text="Check", style="Accent.TButton", command=self.check_password).pack(side="left")
        self.pw_out = app.text_box(t2, height=10)
        self.pw_out.pack(fill="both", expand=True)

        # File analyser
        t3 = ttk.Frame(nb, style="Panel.TFrame", padding=18)
        nb.add(t3, text="File analyser")
        ttk.Label(t3, text="Deep-scan a single file (hash signatures, content rules, heuristics, archive contents).",
                  style="Muted.TLabel").pack(anchor="w")
        r = ttk.Frame(t3, style="Panel.TFrame")
        r.pack(fill="x", pady=8)
        self.file_var = tk.StringVar()
        ttk.Entry(r, textvariable=self.file_var).pack(side="left", fill="x", expand=True)
        ttk.Button(r, text="Browse...", command=self.pick_file).pack(side="left", padx=8)
        ttk.Button(r, text="Analyse", style="Accent.TButton", command=self.analyse_file).pack(side="left")
        self.file_out = app.text_box(t3, height=10)
        self.file_out.pack(fill="both", expand=True)

        # Updates
        t4 = ttk.Frame(nb, style="Panel.TFrame", padding=18)
        nb.add(t4, text="Signature update")
        ttk.Label(t4, text="Download the latest malware hashes, malicious IPs/domains and rules from the configured threat feeds.",
                  style="Muted.TLabel").pack(anchor="w")
        self.upd_btn = ttk.Button(t4, text="Update signatures now", style="Accent.TButton", command=self.update)
        self.upd_btn.pack(anchor="w", pady=8)
        self.upd_out = app.text_box(t4, height=10)
        self.upd_out.pack(fill="both", expand=True)

        # Integrity
        t5 = ttk.Frame(nb, style="Panel.TFrame", padding=18)
        nb.add(t5, text="Integrity baseline")
        ttk.Label(t5, text="Record hashes of critical system files now, then re-check later to detect tampering.",
                  style="Muted.TLabel").pack(anchor="w")
        r = ttk.Frame(t5, style="Panel.TFrame")
        r.pack(anchor="w", pady=8)
        ttk.Button(r, text="Create baseline", command=lambda: self.integrity(True)).pack(side="left")
        ttk.Button(r, text="Check against baseline", style="Accent.TButton", command=lambda: self.integrity(False)).pack(side="left", padx=8)
        self.int_out = app.text_box(t5, height=10)
        self.int_out.pack(fill="both", expand=True)

    def _busy(self, widget: Any, text: str) -> None:
        self.app.set_text(widget, [(text, "muted")])

    def check_url(self) -> None:
        url = self.url_var.get().strip()
        if not url:
            return
        self._busy(self.url_out, "Checking...")

        def work() -> dict:
            from aegis.tools.urlcheck import check_url

            return check_url(url, self.app.ensure_signatures(), self.app.config)

        def done(r: dict) -> None:
            verdict = str(r.get("verdict", "?"))
            tag = {"safe": "good", "suspicious": "medium", "malicious": "critical"}.get(verdict, "muted")
            parts: List[tuple] = [(f"{verdict.upper()}", tag), (f"   risk score {r.get('score', '?')}/100\n", "muted"),
                                  (f"{r.get('host', '')}\n\n", "h")]
            parts += [(f"- {x}\n", None) for x in r.get("reasons", [])] or [("No risk indicators found.\n", None)]
            self.app.set_text(self.url_out, parts)

        self.app.run_bg(work, done, lambda e: self.app.set_text(self.url_out, [(f"Could not check URL: {e}", "critical")]))

    def check_password(self) -> None:
        pw = self.pw_var.get()
        if not pw:
            return
        online = bool(self.pw_online.get())
        self._busy(self.pw_out, "Checking...")

        def work() -> dict:
            from aegis.tools.password import check_password

            return check_password(pw, online=online)

        def done(r: dict) -> None:
            labels = ["Very weak", "Weak", "Fair", "Strong", "Very strong"]
            strength = int(r.get("strength", 0))
            tag = "good" if strength >= 3 else "medium" if strength == 2 else "critical"
            parts: List[tuple] = [(f"{labels[max(0, min(4, strength))]}", tag),
                                  (f"   ~{r.get('entropy_bits', 0):.0f} bits of entropy\n\n", "muted")]
            pwned = r.get("pwned_count")
            if pwned:
                parts.append((f"Found in {pwned:,} known data breaches - do not use this password anywhere.\n", "critical"))
            elif pwned == 0:
                parts.append(("Not found in known breaches.\n", "good"))
            elif r.get("online_error"):
                parts.append((f"Breach lookup unavailable: {r['online_error']}\n", "muted"))
            parts += [(f"- {x}\n", None) for x in r.get("feedback", [])]
            self.app.set_text(self.pw_out, parts)

        self.app.run_bg(work, done, lambda e: self.app.set_text(self.pw_out, [(f"Check failed: {e}", "critical")]))

    def pick_file(self) -> None:
        p = self.app.filedialog.askopenfilename(title="File to analyse")
        if p:
            self.file_var.set(p)

    def analyse_file(self) -> None:
        p = self.file_var.get().strip()
        if not p or not Path(p).is_file():
            self.app.messagebox.showwarning("File analyser", "Choose an existing file.")
            return
        self._busy(self.file_out, "Analysing...")

        def work() -> tuple:
            from aegis.scanners.base import ScanContext
            from aegis.scanners.files import hash_file, scan_file

            ctx = ScanContext(config=self.app.config, signatures=self.app.ensure_signatures(), paths=[Path(p)], deep=True)
            sha256, sha1, md5 = hash_file(Path(p))
            return sha256, sha1, md5, scan_file(ctx, Path(p))

        def done(res: tuple) -> None:
            sha256, sha1, md5, findings = res
            parts: List[tuple] = [(f"{Path(p).name}\n", "h"), (f"SHA-256 {sha256}\nSHA-1   {sha1}\nMD5     {md5}\n\n", "muted")]
            if not findings:
                parts.append(("No threats detected.\n", "good"))
            for f in sorted(findings, key=lambda x: -int(x.severity)):
                parts += [(f"{f.severity.label.upper()}  ", f.severity.name.lower()), (f"{f.title}\n", "h"),
                          (f"{f.description}\n", None)]
                if f.recommendation:
                    parts.append((f"{f.recommendation}\n", "muted"))
                parts.append(("\n", None))
            self.app.set_text(self.file_out, parts)

        self.app.run_bg(work, done, lambda e: self.app.set_text(self.file_out, [(f"Analysis failed: {e}", "critical")]))

    def update(self) -> None:
        self.upd_btn.state(["disabled"])
        self.app.set_text(self.upd_out, [("Updating...\n", "muted")])

        def progress(*a: Any) -> None:
            self.app.ui.post(lambda: self.app.set_text(self.upd_out, [(" ".join(str(x) for x in a) + "\n", "muted")]))

        def work() -> dict:
            from aegis.tools.updater import update_signatures

            res = update_signatures(self.app.config, progress)
            if self.app.signatures is not None:
                self.app.signatures.load()
            return res

        def done(res: dict) -> None:
            self.upd_btn.state(["!disabled"])
            parts: List[tuple] = []
            for feed, r in res.items():
                if r.get("ok"):
                    parts.append((f"OK    {feed}: {r.get('count', 0):,} entries\n", "good"))
                else:
                    parts.append((f"FAIL  {feed}: {r.get('error', 'unknown error')}\n", "critical"))
            self.app.set_text(self.upd_out, parts or [("Nothing to update.\n", "muted")])
            self.app.pages["dashboard"].refresh()

        def err(exc: BaseException) -> None:
            self.upd_btn.state(["!disabled"])
            self.app.set_text(self.upd_out, [(f"Update failed: {exc}", "critical")])

        self.app.run_bg(work, done, err)

    def integrity(self, create: bool) -> None:
        self._busy(self.int_out, "Working...")

        def work() -> Any:
            from aegis.tools import integrity

            if create:
                return integrity.create_baseline(self.app.config)
            return integrity.compare_baseline(self.app.config)

        def done(res: Any) -> None:
            if create:
                self.app.set_text(self.int_out, [("Baseline created.\n", "good"),
                                                 (json.dumps(res, indent=2, default=str)[:3000], "muted")])
                return
            if not res:
                self.app.set_text(self.int_out, [("All files match the baseline.\n", "good")])
                return
            parts: List[tuple] = []
            for f in res:
                parts += [(f"{f.severity.label.upper()}  ", f.severity.name.lower()), (f"{f.title}\n", "h"),
                          (f"{f.location}\n\n", "muted")]
            self.app.set_text(self.int_out, parts)

        self.app.run_bg(work, done, lambda e: self.app.set_text(self.int_out, [(f"Failed: {e}", "critical")]))


# ---- Settings

class SettingsPage(Page):
    key = "settings"

    def build(self) -> None:
        app, ttk, tk = self.app, self.ttk, self.tk
        cfg = app.config
        f = self.frame
        f.columnconfigure(0, weight=1)
        f.columnconfigure(1, weight=1)
        app.heading(f, "Settings", "Stored locally in your Aegis data folder").grid(row=0, column=0, columnspan=2, sticky="w")

        excl = app.card(f, "Exclusions")
        excl.grid(row=1, column=0, sticky="nsew", pady=(12, 0), padx=(0, 8))
        ttk.Label(excl, text="Paths or patterns (e.g. C:\\Dev, *\\node_modules\\*) that are never scanned.",
                  style="Muted.TLabel", wraplength=420, justify="left").pack(anchor="w")
        self.excl_list = tk.Listbox(excl, height=8, bg=C["panel2"], fg=C["text"], relief="flat", highlightthickness=0,
                                    selectbackground=C["select"], activestyle="none", font=(FONT, 10))
        self.excl_list.pack(fill="both", expand=True, pady=8)
        r = ttk.Frame(excl, style="Panel.TFrame")
        r.pack(fill="x")
        self.excl_var = tk.StringVar()
        ttk.Entry(r, textvariable=self.excl_var).pack(side="left", fill="x", expand=True)
        ttk.Button(r, text="Add", command=self.add_exclusion).pack(side="left", padx=(6, 0))
        ttk.Button(r, text="Folder...", command=self.add_folder).pack(side="left", padx=(6, 0))
        ttk.Button(r, text="Remove selected", command=self.remove_exclusion).pack(anchor="w", pady=(8, 0))

        right = ttk.Frame(f)
        right.grid(row=1, column=1, sticky="nsew", pady=(12, 0), padx=(8, 0))
        right.columnconfigure(0, weight=1)
        keys = app.card(right, "Threat-intelligence keys (optional)")
        keys.grid(row=0, column=0, sticky="ew")
        self.key_vars = {
            "virustotal_api_key": tk.StringVar(value=cfg.virustotal_api_key),
            "abusech_auth_key": tk.StringVar(value=cfg.abusech_auth_key),
            "google_safebrowsing_api_key": tk.StringVar(value=cfg.google_safebrowsing_api_key),
        }
        for label, key in (("VirusTotal API key", "virustotal_api_key"), ("abuse.ch Auth-Key", "abusech_auth_key"),
                           ("Google Safe Browsing key", "google_safebrowsing_api_key")):
            ttk.Label(keys, text=label, style="Panel.TLabel").pack(anchor="w", pady=(4, 0))
            ttk.Entry(keys, textvariable=self.key_vars[key], show="*").pack(fill="x")
        self.flags = {
            "cloud_lookup": tk.BooleanVar(value=cfg.cloud_lookup),
            "use_windows_defender_engine": tk.BooleanVar(value=cfg.use_windows_defender_engine),
        }
        ttk.Checkbutton(keys, text="Cloud lookup: send SHA-256 of suspicious files to VirusTotal",
                        variable=self.flags["cloud_lookup"]).pack(anchor="w", pady=(10, 0))
        ttk.Checkbutton(keys, text="Use Microsoft Defender engine as a second opinion",
                        variable=self.flags["use_windows_defender_engine"]).pack(anchor="w")

        perf = app.card(right, "Scanning")
        perf.grid(row=1, column=0, sticky="ew", pady=(12, 0))
        self.threads_var = tk.IntVar(value=cfg.scan_threads)
        self.maxsize_var = tk.IntVar(value=cfg.max_file_size_mb)
        g = ttk.Frame(perf, style="Panel.TFrame")
        g.pack(fill="x")
        ttk.Label(g, text="Scan threads", style="Panel.TLabel").grid(row=0, column=0, sticky="w", pady=4)
        ttk.Spinbox(g, from_=1, to=32, textvariable=self.threads_var, width=6).grid(row=0, column=1, padx=10)
        ttk.Label(g, text="Max file size to content-scan (MB)", style="Panel.TLabel").grid(row=1, column=0, sticky="w", pady=4)
        ttk.Spinbox(g, from_=1, to=4096, textvariable=self.maxsize_var, width=6).grid(row=1, column=1, padx=10)
        ttk.Label(perf, text="Larger files are hashed only.", style="Muted.TLabel").pack(anchor="w")

        row = ttk.Frame(f)
        row.grid(row=2, column=0, columnspan=2, sticky="e", pady=(14, 0))
        self.saved = ttk.Label(row, text="", style="MutedBg.TLabel")
        self.saved.pack(side="left", padx=12)
        ttk.Button(row, text="Save settings", style="Accent.TButton", command=self.save).pack(side="left")
        self.load_exclusions()

    def load_exclusions(self) -> None:
        self.excl_list.delete(0, "end")
        for e in self.app.config.exclusions:
            self.excl_list.insert("end", e)

    def add_exclusion(self) -> None:
        v = self.excl_var.get().strip()
        if v and v not in self.app.config.exclusions:
            self.app.config.exclusions.append(v)
            self.excl_list.insert("end", v)
        self.excl_var.set("")

    def add_folder(self) -> None:
        d = self.app.filedialog.askdirectory(title="Folder to exclude")
        if d:
            self.excl_var.set(d)
            self.add_exclusion()

    def remove_exclusion(self) -> None:
        for idx in reversed(self.excl_list.curselection()):
            val = self.excl_list.get(idx)
            if val in self.app.config.exclusions:
                self.app.config.exclusions.remove(val)
            self.excl_list.delete(idx)

    def save(self) -> None:
        cfg = self.app.config
        for key, var in self.key_vars.items():
            setattr(cfg, key, var.get().strip())
        for key, var in self.flags.items():
            setattr(cfg, key, bool(var.get()))
        try:
            cfg.scan_threads = max(1, int(self.threads_var.get()))
            cfg.max_file_size_mb = max(1, int(self.maxsize_var.get()))
        except (ValueError, self.tk.TclError):
            self.app.messagebox.showerror("Settings", "Threads and max file size must be whole numbers.")
            return
        self.app.save_config()
        self.saved.configure(text="Saved " + dt.datetime.now().strftime("%H:%M:%S"))
        self.app.set_status("Settings saved")


# --------------------------------------------------------------------------- entry point

def launch_gui() -> int:
    """Start the desktop app. Returns a process exit code."""
    try:
        import tkinter as tk
        from tkinter import filedialog, messagebox, ttk
    except ImportError:
        print("The Aegis GUI needs tkinter (included with the python.org Windows installer; on Debian/Ubuntu: "
              "apt install python3-tk).", file=sys.stderr)
        return 1
    if IS_WINDOWS:  # crisp text on high-DPI displays
        try:
            import ctypes

            ctypes.windll.shcore.SetProcessDpiAwareness(1)  # type: ignore[attr-defined]
        except Exception:
            pass
    try:
        root = tk.Tk()
    except Exception as exc:  # no display
        print(f"Cannot open a window: {exc}", file=sys.stderr)
        return 1
    GuiApp(tk, ttk, filedialog, messagebox, root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(launch_gui())
