"""Drive the desktop app on a real Tk: every page renders and a real scan completes.

Skipped where tkinter or a display is unavailable. CI runs it under Xvfb on Linux and on
the Windows desktop session."""

import time

import pytest

tk = pytest.importorskip("tkinter")


@pytest.fixture
def gui(eicar_bytes, tmp_path):
    from tkinter import filedialog, messagebox, ttk

    from aegis.ui.gui import GuiApp

    try:
        root = tk.Tk()
    except tk.TclError as exc:
        pytest.skip(f"no display: {exc}")
    errors = []
    root.report_callback_exception = lambda *exc: errors.append(exc)
    root.withdraw()
    app = GuiApp(tk, ttk, filedialog, messagebox, root)
    yield app, errors
    try:
        if app.monitor:
            app.monitor.stop(timeout=2.0)
        root.destroy()
    except tk.TclError:
        pass


def pump(app, seconds, until=None):
    end = time.time() + seconds
    while time.time() < end:
        app.root.update()
        if until and until():
            return True
        time.sleep(0.02)
    return bool(until and until())


def test_every_page_renders(gui):
    app, errors = gui
    assert set(app.frames) >= {"dashboard", "scan", "protection", "quarantine", "tools", "settings"}
    for key in list(app.frames):
        app.show(key)
        pump(app, 0.3)
        assert app.current == key
    assert not errors, errors


def test_real_scan_from_the_scan_page(gui, tmp_path, eicar_bytes):
    app, errors = gui
    (tmp_path / "eicar.com").write_bytes(eicar_bytes)
    (tmp_path / "clean.txt").write_text("hello")
    scan = app.pages["scan"]
    app.show("scan")
    pump(app, 0.3)
    scan.mode.set("custom")
    scan.on_mode()
    for name, var in scan.scanner_vars.items():
        var.set(name == "files")
    scan.path_var.set(str(tmp_path))
    scan.start("custom")
    assert pump(app, 60, until=lambda: not scan.scanning), "scan did not finish"
    pump(app, 0.5)
    rows = [scan.tree.item(i, "values") for i in scan.tree.get_children()]
    assert rows and any("EICAR" in " ".join(map(str, r)) for r in rows)
    first = scan.tree.get_children()[0]
    scan.tree.selection_set(first)
    scan.show_detail()
    pump(app, 0.3)
    app.show("dashboard")
    pump(app, 0.5)
    assert not errors, errors
