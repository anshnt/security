"""Shared fixtures: every test gets an isolated AEGIS_HOME data directory."""

import pytest


@pytest.fixture(autouse=True)
def aegis_home(tmp_path, monkeypatch):
    home = tmp_path / "aegis_home"
    home.mkdir()
    monkeypatch.setenv("AEGIS_HOME", str(home))
    return home


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
