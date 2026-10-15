# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec: windowed GUI build -> dist/aegis-gui.exe (onefile, no console)
#   pyinstaller packaging/aegis-gui.spec --noconfirm --clean
import os
import re
import sys

from PyInstaller.utils.hooks import collect_submodules

ROOT = os.path.abspath(os.path.join(SPECPATH, ".."))  # noqa: F821 - SPECPATH is provided by PyInstaller
NAME = "aegis-gui"

with open(os.path.join(ROOT, "aegis", "__init__.py"), encoding="utf-8") as fh:
    VERSION = re.search(r'__version__\s*=\s*"([^"]+)"', fh.read()).group(1)
VERSION_TUPLE = tuple((int(x) for x in (VERSION.split(".") + ["0", "0", "0"])[:3])) + (0,)

hiddenimports = sorted(set(
    collect_submodules("aegis.scanners") + collect_submodules("aegis.tools") + collect_submodules("aegis.realtime")
    + collect_submodules("aegis.ui") + collect_submodules("aegis.core")
    + ["psutil", "sqlite3", "tkinter", "tkinter.ttk", "tkinter.filedialog", "tkinter.messagebox"]
))
try:
    import yara  # noqa: F401

    hiddenimports.append("yara")
except Exception:
    pass


def version_info():
    if not sys.platform.startswith("win"):
        return None
    from PyInstaller.utils.win32.versioninfo import (FixedFileInfo, StringFileInfo, StringStruct, StringTable,
                                                     VarFileInfo, VarStruct, VSVersionInfo)
    v = ".".join(map(str, VERSION_TUPLE))
    return VSVersionInfo(
        ffi=FixedFileInfo(filevers=VERSION_TUPLE, prodvers=VERSION_TUPLE, mask=0x3F, flags=0x0, OS=0x40004,
                          fileType=0x1, subtype=0x0, date=(0, 0)),
        kids=[
            StringFileInfo([StringTable("040904B0", [
                StringStruct("CompanyName", "Aegis Security Suite"),
                StringStruct("FileDescription", "Aegis Security Suite - antivirus & threat detection"),
                StringStruct("FileVersion", v),
                StringStruct("InternalName", NAME),
                StringStruct("LegalCopyright", "MIT License"),
                StringStruct("OriginalFilename", NAME + ".exe"),
                StringStruct("ProductName", "Aegis Security Suite"),
                StringStruct("ProductVersion", v),
            ])]),
            VarFileInfo([VarStruct("Translation", [1033, 1200])]),
        ])


a = Analysis(  # noqa: F821
    [os.path.join(ROOT, "packaging", "entry_gui.py")],
    pathex=[ROOT],
    binaries=[],
    datas=[(os.path.join(ROOT, "aegis", "data"), os.path.join("aegis", "data"))],
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=["pytest", "pydoc", "test", "numpy", "matplotlib", "PIL"],
    noarchive=False,
)
pyz = PYZ(a.pure)  # noqa: F821
exe = EXE(  # noqa: F821
    pyz, a.scripts, a.binaries, a.datas, [],
    name=NAME,
    debug=False,
    strip=False,
    upx=False,
    console=False,  # windowed
    uac_admin=False,
    disable_windowed_traceback=False,
    version=version_info(),
)
