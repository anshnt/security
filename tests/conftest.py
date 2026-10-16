"""Shared fixtures: every test gets an isolated AEGIS_HOME data directory."""

import pytest


@pytest.fixture(autouse=True)
def aegis_home(tmp_path, monkeypatch):
    home = tmp_path / "aegis_home"
    home.mkdir()
    monkeypatch.setenv("AEGIS_HOME", str(home))
    return home


@pytest.fixture(autouse=True)
def _no_btm_cache(tmp_path, monkeypatch):
    """The persistence scanner keeps the last `sfltool dumpbtm` output while the Background Task Management database is
    unchanged. On a real Mac that database exists, so a fake dump would be served to the next call, in the same test or
    the next one. Tests run with a database folder that does not exist (no caching); a cache test sets its own."""
    from aegis.scanners import persistence as ps

    monkeypatch.setattr(ps, "BTM_DB_DIR", tmp_path / "no-btm-database")
    monkeypatch.setattr(ps, "_BTM_CACHE", {})


@pytest.fixture
def eicar_bytes() -> bytes:
    # Built at runtime so this repository never contains the literal test string.
    return ("X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*").encode()


@pytest.fixture
def ctx(aegis_home):
    from aegis.core.config import Config
    from aegis.core.signatures import SignatureDB
    from aegis.scanners.base import ScanContext

    cfg = Config.load()
    cfg.use_windows_defender_engine = False
    return ScanContext(config=cfg, signatures=SignatureDB(cfg))
