"""Drive the desktop app on a real Tk: every page renders and a real scan completes.

Skipped where tkinter or a display is unavailable. CI runs it under Xvfb on Linux and on
the Windows desktop session."""

import gc
import os
import stat
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
    gc.collect()  # free this app's Tk variables on the main thread, not in a later test's worker thread


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


# --------------------------------------------------------------------------- score history + alert settings

def _record_scan(cfg, findings, started):
    from aegis.core import history
    from aegis.core.models import Category, Finding, ScanResult

    r = ScanResult(profile="quick", started=started, finished=started, host={"hostname": "gui-host"}, scanners=["files"])
    for title, sev in findings:
        r.add(Finding(f"AEG-GUI-{title}", title, sev, Category.MALWARE, location=f"C:\\x\\{title}.exe"))
    history.record_and_compare(r, cfg)


def test_dashboard_history_widget_renders(gui):
    from aegis.core.models import Severity
    from aegis.ui.gui import GRADE_COLOR

    app, errors = gui
    dash = app.pages["dashboard"]
    app.show("dashboard")
    pump(app, 0.5)
    canvas = dash.chart.canvas
    assert canvas.find_withtag("empty"), "an empty history shows a hint instead of a chart"
    assert dash.new_label.cget("text") == "New since last scan: -"

    _record_scan(app.config, [], "2026-10-14T09:00:00")  # 100, grade A
    _record_scan(app.config, [("one", Severity.HIGH)], "2026-10-15T09:00:00")  # 88, B
    _record_scan(app.config, [("two", Severity.CRITICAL)], "2026-10-16T09:00:00")  # 49, F: 1 new, 1 resolved
    dash.refresh_history(force=True)
    assert pump(app, 15, until=lambda: len(dash.chart.points) == 3), "history was not loaded"
    pump(app, 0.3)
    assert [s for _d, s in dash.chart.points] == [100, 88, 49]
    assert dash.new_label.cget("text") == "New since last scan: 1"
    assert "Resolved: 1" in dash.new_detail.cget("text") and "Score change: -39" in dash.new_detail.cget("text")
    assert len(canvas.find_withtag("line")) == 2 and len(canvas.find_withtag("dot")) == 3
    assert not canvas.find_withtag("empty")
    assert [canvas.itemcget(i, "fill") for i in canvas.find_withtag("dot")] == [GRADE_COLOR["A"], GRADE_COLOR["B"], GRADE_COLOR["F"]]
    assert [canvas.itemcget(i, "fill") for i in canvas.find_withtag("line")] == [GRADE_COLOR["B"], GRADE_COLOR["F"]]
    assert canvas.itemcget(canvas.find_withtag("value")[0], "text") == "49"
    app.root.event_generate("<Configure>")  # a resize redraws without errors
    dash.chart._on_configure(type("E", (), {"width": 900, "height": 160})())
    pump(app, 0.2)
    assert dash.chart.w == 900 and canvas.find_withtag("dot")
    assert not errors, errors


def test_dashboard_history_updates_after_a_real_scan(gui, tmp_path, eicar_bytes):
    app, errors = gui
    dash = app.pages["dashboard"]
    scan = app.pages["scan"]
    (tmp_path / "eicar.com").write_bytes(eicar_bytes)
    app.show("scan")
    scan.mode.set("custom")
    scan.on_mode()
    for name, var in scan.scanner_vars.items():
        var.set(name == "files")
    scan.path_var.set(str(tmp_path))
    for expected in (1, 2):  # two scans of the same folder: the second one has a baseline (0 new findings)
        scan.start("custom")
        assert pump(app, 60, until=lambda: not scan.scanning), "scan did not finish"
        app.show("dashboard")
        assert pump(app, 15, until=lambda n=expected: len(dash.chart.points) == n), f"dashboard chart has no point {expected}"
    pump(app, 0.3)
    assert dash.new_label.cget("text") == "New since last scan: 0"
    assert not errors, errors


def test_settings_alert_fields_are_masked_validated_and_testable(gui, monkeypatch):
    import json
    import urllib.request

    from aegis.core import alerts

    app, errors = gui
    st = app.pages["settings"]
    shown = []
    monkeypatch.setattr(app.messagebox, "showerror", lambda title, msg: shown.append(msg))  # never open a real dialog
    app.show("settings")
    pump(app, 0.3)

    assert len(st.secret_entries) == 5  # four webhook URLs + the SMTP password
    assert all(str(e.cget("show")) == "*" for e in st.secret_entries)
    st.show_secrets.set(True)
    st.toggle_secrets()
    assert all(str(e.cget("show")) == "" for e in st.secret_entries)
    st.show_secrets.set(False)
    st.toggle_secrets()
    assert all(str(e.cget("show")) == "*" for e in st.secret_entries)

    # an http:// webhook is refused and nothing is saved
    st.alert_vars["alert_discord_webhook"].set("http://discord.com/api/webhooks/1/plaintext-token")
    st.save()
    assert shown and "https://" in shown[0] and "plaintext-token" not in shown[0]
    assert app.config.alert_discord_webhook == ""
    st.alert_vars["alert_email_smtp_port"].set("not a port")
    st.save()
    assert "port" in shown[-1]
    st.alert_vars["alert_email_smtp_port"].set("2525")

    # valid values are saved to config.json
    st.alert_vars["alert_discord_webhook"].set("")
    st.alert_vars["alert_slack_webhook"].set("https://hooks.slack.com/services/T/B/tokentokentoken")
    st.alert_vars["alert_min_severity"].set("critical")
    st.alert_vars["alert_on"].set("all")
    st.alert_vars["alert_email_smtp_host"].set("smtp.example.org")
    st.alert_vars["alert_email_to"].set("ops@example.org")
    st.alert_vars["alert_email_starttls"].set(False)
    st.save()
    assert st.saved.cget("text").startswith("Saved")
    disk = json.loads(app.config.path.read_text(encoding="utf-8"))
    assert disk["alert_slack_webhook"].endswith("tokentokentoken") and disk["alert_min_severity"] == "critical"
    assert disk["alert_on"] == "all" and disk["alert_email_smtp_port"] == 2525 and disk["alert_email_starttls"] is False
    assert app.config.alert_email_to == "ops@example.org"
    if os.name == "posix":  # the file now holds a webhook URL: owner only
        assert stat.S_IMODE(os.stat(app.config.path).st_mode) == 0o600

    # "Send test alert" uses the form (even unsaved values), runs off the UI thread and reports per channel
    requests = []

    class Resp:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self, n=-1):
            return b"ok"

    def fake_urlopen(req, timeout=None, **kw):
        requests.append((req.full_url, json.loads(req.data.decode())))
        return Resp()

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(alerts, "_sleep", lambda s: None)
    st.alert_vars["alert_email_smtp_host"].set("")  # leave only the webhook channels
    st.alert_vars["alert_email_to"].set("")
    st.alert_vars["alert_teams_webhook"].set("https://example.logic.azure.com/workflows/abc/triggers/manual?sig=unsaved-sig-value")
    st.send_test()
    assert pump(app, 15, until=lambda: "sent" in st.test_out.cget("text")), st.test_out.cget("text")
    assert "slack: sent" in st.test_out.cget("text") and "teams: sent" in st.test_out.cget("text")
    assert {u.split("/")[2] for u, _b in requests} == {"hooks.slack.com", "example.logic.azure.com"}
    assert all("Aegis test alert" in json.dumps(b) for _u, b in requests)
    assert "unsaved-sig-value" not in json.dumps(json.loads(app.config.path.read_text()))  # test did not save the form
    assert str(st.test_btn.cget("state")) != "disabled"

    st.alert_vars["alert_slack_webhook"].set("")
    st.alert_vars["alert_teams_webhook"].set("")
    st.send_test()
    assert "at least one" in st.test_out.cget("text")
    assert not errors, errors
