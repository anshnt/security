# Contributing

1. `python -m venv .venv && .venv\Scripts\activate` (or `source .venv/bin/activate`)
2. `pip install -e .[dev,yara]`
3. `pytest -q`

Guidelines:

* New scanners: subclass `aegis.scanners.base.Scanner`, decorate with `@register`, add the module to
  `load_all()`, separate *data collection* from *decision logic* and unit-test the logic with mocks so
  tests run on any OS.
* New detection content: see [docs/RULES.md](docs/RULES.md). Never commit live malware - build test
  samples at runtime (see `tests/conftest.py::eicar_bytes`).
* Keep false positives low: prefer combining indicators over single weak strings, and allow-list
  well-known legitimate software.
* Windows checks must be locale-independent (registry / XML / JSON, not localized console text).
