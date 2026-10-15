"""Tests for generated Task Scheduler XML and systemd units (no system changes)."""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from aegis.core import service as S

NS = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}


def parse(xml: str) -> ET.Element:
    return ET.fromstring(xml.encode("utf-16"))  # same encoding the file is written with


def test_all_task_xmls_wellformed():
    xmls = S.windows_task_xmls(highest=True)
    assert set(xmls) == set(S.ALL_TASKS)
    for name, xml in xmls.items():
        root = parse(xml)
        assert root.tag == "{%s}Task" % NS["t"]
        assert root.findtext("t:RegistrationInfo/t:URI", namespaces=NS) == "\\" + name
        assert root.findtext("t:Principals/t:Principal/t:RunLevel", namespaces=NS) == "HighestAvailable"
        cmd = root.findtext("t:Actions/t:Exec/t:Command", namespaces=NS)
        assert cmd == sys.executable or cmd.lower().endswith("pythonw.exe")


def test_task_commands_and_triggers():
    xmls = {n: parse(x) for n, x in S.windows_task_xmls(highest=False).items()}
    rt = xmls[S.TASK_REALTIME]
    assert rt.find("t:Triggers/t:LogonTrigger", NS) is not None
    assert rt.findtext("t:Actions/t:Exec/t:Arguments", namespaces=NS).endswith("monitor")
    assert rt.findtext("t:Principals/t:Principal/t:RunLevel", namespaces=NS) == "LeastPrivilege"
    assert rt.findtext("t:Settings/t:ExecutionTimeLimit", namespaces=NS) == "PT0S"  # never time out

    scan = xmls[S.TASK_SCAN]
    assert scan.findtext("t:Triggers/t:CalendarTrigger/t:StartBoundary", namespaces=NS).endswith("T12:30:00")
    assert scan.find("t:Triggers/t:CalendarTrigger/t:ScheduleByDay", NS) is not None
    assert scan.findtext("t:Actions/t:Exec/t:Arguments", namespaces=NS).endswith("scan quick --report html")

    upd = xmls[S.TASK_UPDATE]
    assert upd.findtext("t:Triggers/t:CalendarTrigger/t:Repetition/t:Interval", namespaces=NS) == "PT6H"
    assert upd.findtext("t:Actions/t:Exec/t:Arguments", namespaces=NS).endswith("update")


def test_task_xml_escapes_and_quotes():
    xml = S.build_task_xml("Aegis <Test>", r"C:\Program Files\A&B\aegis.exe", ["scan", "quick", "--path", r"C:\My Docs"],
                           "daily", "desc & more")
    root = parse(xml)
    assert root.findtext("t:Actions/t:Exec/t:Command", namespaces=NS) == r"C:\Program Files\A&B\aegis.exe"
    assert root.findtext("t:Actions/t:Exec/t:Arguments", namespaces=NS) == r'scan quick --path "C:\My Docs"'
    assert root.findtext("t:RegistrationInfo/t:Description", namespaces=NS) == "desc & more"
    with pytest.raises(ValueError):
        S.build_task_xml("x", "y", [], "weekly")


def test_launch_command_frozen_vs_source(monkeypatch):
    exe, args = S.launch_command()
    assert exe and args == ["-m", "aegis"]
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    assert S.launch_command() == (sys.executable, [])
    xml = S.windows_task_xmls(highest=True)[S.TASK_REALTIME]
    root = parse(xml)
    assert root.findtext("t:Actions/t:Exec/t:Arguments", namespaces=NS) == "monitor"


def test_install_service_windows_uses_schtasks_xml(monkeypatch):
    calls, xml_seen = [], []

    def fake_run(cmd, timeout=60, **kw):
        calls.append(list(cmd))
        if "/Create" in cmd:
            xml_seen.append(parse(Path(cmd[cmd.index("/XML") + 1]).read_bytes().decode("utf-16")))
        return 0, "SUCCESS", ""

    monkeypatch.setattr(S, "IS_WINDOWS", True)
    monkeypatch.setattr(S, "is_admin", lambda: False)
    monkeypatch.setattr(S, "run", fake_run)
    actions = S.install_service(None)
    creates = [c for c in calls if "/Create" in c]
    assert [c[c.index("/TN") + 1] for c in creates] == list(S.ALL_TASKS)
    assert all("/XML" in c and "/F" in c for c in creates)
    assert len(xml_seen) == 3
    assert sum(a.startswith("Created scheduled task") for a in actions) == 3
    assert any("Administrator" in a for a in actions)  # told the user about reduced privileges

    calls.clear()
    out = S.uninstall_service()
    assert [c[c.index("/TN") + 1] for c in calls] == list(S.ALL_TASKS) and all("/Delete" in c for c in calls)
    assert len(out) == 3


def test_systemd_units_content():
    units = S.systemd_units("/opt/aegis/bin/python", ["-m", "aegis"])
    assert set(units) == set(S.SYSTEMD_UNIT_NAMES)
    assert "ExecStart=/opt/aegis/bin/python -m aegis monitor" in units["aegis-monitor.service"]
    assert "Restart=on-failure" in units["aegis-monitor.service"]
    assert "ExecStart=/opt/aegis/bin/python -m aegis scan quick --report html" in units["aegis-scan.service"]
    assert "OnCalendar=*-*-* 12:30:00" in units["aegis-scan.timer"]
    assert "OnCalendar=*-*-* 00,06,12,18:05:00" in units["aegis-update.timer"]
    assert "ExecStart=/opt/aegis/bin/python -m aegis update" in units["aegis-update.service"]
    for name in ("aegis-scan.timer", "aegis-update.timer"):
        assert "[Install]" in units[name] and "WantedBy=timers.target" in units[name]


def test_systemd_quoting_of_paths_with_spaces_and_percent():
    units = S.systemd_units("/home/me/my apps/aegis", [])
    assert 'ExecStart="/home/me/my apps/aegis" monitor' in units["aegis-monitor.service"]
    assert S._systemd_quote("100%") == '"100%%"'


def test_install_and_uninstall_systemd_user_units(tmp_path, monkeypatch):
    monkeypatch.setattr(S, "IS_WINDOWS", False)
    monkeypatch.setattr(S, "IS_LINUX", True)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.setattr(S.shutil, "which", lambda n: None)  # no systemctl in the test environment
    actions = S.install_service(None)
    d = tmp_path / "systemd" / "user"
    assert sorted(p.name for p in d.iterdir()) == sorted(S.SYSTEMD_UNIT_NAMES)
    assert any("systemctl not found" in a for a in actions)
    assert "monitor" in (d / "aegis-monitor.service").read_text()
    out = S.uninstall_service()
    assert not list(d.iterdir())
    assert len([a for a in out if a.startswith("Removed")]) == 5
    assert S.uninstall_service() == ["No Aegis systemd units were installed."]
