"""Sample macOS tool output for tests/test_persistence_macos.py.

BTM_DUMP is written after what ``sudo sfltool dumpbtm`` prints on macOS 13 to 15: a ``Records for UID`` header per user
(the system-wide daemons sit under UID 0), then numbered items of right-aligned ``Key: value`` lines. It was transcribed
from memory of real dumps and not captured from one, so the field names Aegis relies on (Name, Developer Name, Team
Identifier, Type, Disposition, Identifier, URL, Executable Path, Parent Identifier) are real and the vendors' Team IDs are
real, while the exact spacing, the order of lines and the filler lines (ServiceManagement migrated, Items:, Generation,
Embedded Item Identifiers) are a best guess. The parser must not depend on them.

CODESIGN_*: the stderr of ``codesign -dv --verbose=2`` and the output of ``codesign --verify --strict`` for the five kinds of
program Aegis tells apart (the lines are the ones codesign prints; sizes and hashes are shortened).
"""

BTM_DUMP = """========================
 Records for UID 501 : 6F1C39B2-7D4E-4B58-A2E1-90C3D5F7A8B4
========================

 ServiceManagement migrated: true
 SMAppService URL: (null)
 Items:

 #1:
                 UUID: 1A7D0C52-0B1E-4C66-9E21-5D3F6B0A9C01
                 Name: Google LLC
       Developer Name: Google LLC
      Team Identifier: EQHXZ8M8AV
                 Type: developer (0x20)
                Flags: [  ] (0)
          Disposition: [enabled, allowed, visible, notified] (0xf)
           Identifier: Unknown Developer
                  URL: (null)
           Generation: 1
 Embedded Item Identifiers:
              #1: 8.com.google.keystone.agent
              #2: 8.com.google.keystone.xpcservice

 #2:
                 UUID: 2B8E1D63-1C2F-4D77-8F32-6E4A7C1BAD12
                 Name: GoogleSoftwareUpdateAgent
       Developer Name: Google LLC
      Team Identifier: EQHXZ8M8AV
                 Type: legacy agent (0x10008)
                Flags: [ legacy ] (0x1)
          Disposition: [enabled, allowed, visible, notified] (0xf)
           Identifier: 8.com.google.keystone.agent
                  URL: file:///Users/bob/Library/LaunchAgents/com.google.keystone.agent.plist
      Executable Path: /Users/bob/Library/Google/Keystone/GoogleSoftwareUpdate.bundle/Contents/MacOS/GoogleSoftwareUpdateAgent
           Generation: 2
    Parent Identifier: Google LLC

 #3:
                 UUID: 3C9F2E74-2D30-4E88-9043-7F5B8D2CBE23
                 Name: Dropbox
       Developer Name: Dropbox, Inc.
      Team Identifier: G7HH3F8CAK
                 Type: login item (0x4)
                Flags: [  ] (0)
          Disposition: [enabled, allowed, visible, notified] (0xf)
           Identifier: 4.com.getdropbox.dropbox
                  URL: file:///Applications/Dropbox.app/
           Generation: 1

 #4:
                 UUID: 4DA03F85-3E41-4F99-A154-806C9E3DCF34
                 Name: AirPlayXPCHelper
       Developer Name: Apple Inc.
      Team Identifier: (null)
                 Type: legacy agent (0x10008)
                Flags: [ legacy ] (0x1)
          Disposition: [enabled, allowed, hidden, notified] (0xb)
           Identifier: 8.com.apple.AirPlayXPCHelper
                  URL: file:///System/Library/LaunchAgents/com.apple.AirPlayXPCHelper.plist
      Executable Path: /System/Library/CoreServices/AirPlayXPCHelper.app/Contents/MacOS/AirPlayXPCHelper
           Generation: 1

 #5:
                 UUID: 5EB140A6-4F52-40AA-B265-917DAF4EDA45
                 Name: sysupdated
       Developer Name: (null)
      Team Identifier: (null)
                 Type: legacy agent (0x10008)
                Flags: [ legacy ] (0x1)
          Disposition: [enabled, allowed, visible, notified] (0xf)
           Identifier: 8.com.sysupdate.helper
                  URL: file:///Users/bob/Library/LaunchAgents/com.sysupdate.helper.plist
      Executable Path: /Users/bob/Library/Application Support/SysUpdate/sysupdated
           Generation: 1

 #6:
                 UUID: 6FC251B7-5063-41BB-8376-A28EB05FEB56
                 Name: Acme Sync
       Developer Name: Acme Software Inc.
      Team Identifier: A1B2C3D4E5
                 Type: app (0x2)
                Flags: [  ] (0)
          Disposition: [enabled, allowed, visible, notified] (0xf)
           Identifier: 2.com.acme.sync
                  URL: file:///Applications/Acme%20Sync.app/
           Generation: 1
 Embedded Item Identifiers:
              #1: 4.com.acme.sync.helper

 #7:
                 UUID: 70D362C8-6174-42CC-9487-B39FC160FC67
                 Name: Acme Sync Helper
       Developer Name: Acme Software Inc.
      Team Identifier: A1B2C3D4E5
                 Type: login item (0x4)
                Flags: [  ] (0)
          Disposition: [enabled, allowed, hidden, notified] (0xb)
           Identifier: 4.com.acme.sync.helper
                  URL: Contents/Library/LoginItems/AcmeSyncHelper.app
           Generation: 1
    Parent Identifier: 2.com.acme.sync

 #8:
                 UUID: 81E473D9-7285-43DD-A598-C4A0D271AD78
                 Name: Dropbox
       Developer Name: Dropbox, Inc.
      Team Identifier: G7HH3F8CAK
                 Type: legacy agent (0x10008)
                Flags: [ legacy ] (0x1)
          Disposition: [disabled, allowed, visible, notified] (0xe)
           Identifier: 8.com.dropbox.DropboxMacUpdate.agent
                  URL: file:///Users/bob/Library/LaunchAgents/com.dropbox.DropboxMacUpdate.agent.plist
           Generation: 1

========================
 Records for UID 502 : 0A2B3C4D-5E6F-4071-8293-A4B5C6D7E8F9
========================

 ServiceManagement migrated: true
 Items:

 #1:
                 UUID: 92F584EA-8396-44EE-B6A9-D5B1E382BE89
                 Name: Dropbox
       Developer Name: Dropbox, Inc.
      Team Identifier: G7HH3F8CAK
                 Type: login item (0x4)
                Flags: [  ] (0)
          Disposition: [enabled, allowed, visible, notified] (0xf)
           Identifier: 4.com.getdropbox.dropbox
                  URL: file:///Applications/Dropbox.app/
           Generation: 1

========================
 Records for UID 0 : 00000000-0000-0000-0000-000000000000
========================

 Items:

 #1:
                 UUID: A305F5FB-94A7-45FF-87BA-E6C2F493CF9A
                 Name: com.microsoft.autoupdate.helper
       Developer Name: Microsoft Corporation
      Team Identifier: UBF8T346G9
                 Type: legacy daemon (0x10010)
                Flags: [ legacy ] (0x1)
          Disposition: [enabled, allowed, visible, notified] (0xf)
           Identifier: 16.com.microsoft.autoupdate.helper
                  URL: file:///Library/LaunchDaemons/com.microsoft.autoupdate.helper.plist
      Executable Path: /Library/PrivilegedHelperTools/com.microsoft.autoupdate.helper
           Generation: 1

 #2:
                 UUID: B416060C-A5B8-4600-98CB-F7D3A504D0AB
                 Name: com.example.tool
       Developer Name: (null)
      Team Identifier: (null)
                 Type: legacy daemon (0x10010)
                Flags: [ legacy ] (0x1)
          Disposition: [enabled, allowed, visible, notified] (0xf)
           Identifier: 16.com.example.tool
                  URL: file:///Library/LaunchDaemons/com.example.tool.plist
      Executable Path: /Library/PrivilegedHelperTools/com.example.tool
           Generation: 1

 #3:
                 UUID: C527171D-B6C9-4711-A9DC-08E4B615E1BC
                 Name: xprotectd
       Developer Name: (null)
      Team Identifier: (null)
                 Type: legacy daemon (0x10010)
                Flags: [ legacy ] (0x1)
          Disposition: [enabled, allowed, hidden, notified] (0xb)
           Identifier: 16.com.apple.xprotect.daemon.scan
                  URL: file:///System/Library/LaunchDaemons/com.apple.xprotect.daemon.scan.plist
      Executable Path: /Library/Apple/System/Library/CoreServices/XProtect.app/Contents/MacOS/XProtectService
           Generation: 1

 #4:
                 UUID: D638282E-C7DA-4822-BAED-19F5C726F2CD
                 Name: Backup Helper
       Developer Name: (null)
      Team Identifier: (null)
                 Type: agent (0x8)
                Flags: [  ] (0)
          Disposition: [enabled, allowed, visible, notified] (0xf)
           Identifier: 8.com.example.backup.agent
                  URL: Contents/Library/LaunchAgents/com.example.backup.agent.plist
           Generation: 1
    Parent Identifier: 2.com.example.backup

 #5:
                 UUID: E749393F-D8EB-4933-8CFE-2A06D837030E
                 Name: Example Backup
       Developer Name: (null)
      Team Identifier: (null)
                 Type: app (0x2)
                Flags: [  ] (0)
          Disposition: [enabled, allowed, visible, notified] (0xf)
           Identifier: 2.com.example.backup
                  URL: file:///Applications/Example%20Backup.app/
           Generation: 1
"""

# ---- codesign --verify --strict (exit code, output)
CODESIGN_VERIFY_OK = (0, "")
CODESIGN_VERIFY_UNSIGNED = (1, "/Users/bob/Library/Application Support/SysUpdate/sysupdated: code object is not signed at all\n")
CODESIGN_VERIFY_SEALED = (1, "/Applications/Tampered.app: a sealed resource is missing or invalid\n"
                             "In subcomponent: /Applications/Tampered.app/Contents/Resources/helper\n")
CODESIGN_VERIFY_BADSIG = (1, "/usr/local/bin/foo: invalid signature (code or signature have been modified)\n"
                             "In architecture: arm64\n")

# ---- codesign -dv --verbose=2 (stderr)
CODESIGN_DEVELOPER_ID = """Executable=/Applications/Dropbox.app/Contents/MacOS/Dropbox
Identifier=com.getdropbox.dropbox
Format=app bundle with Mach-O universal (x86_64 arm64)
CodeDirectory v=20500 size=987 flags=0x10000(runtime) hashes=21+7 location=embedded
Signature size=9012
Authority=Developer ID Application: Dropbox, Inc. (G7HH3F8CAK)
Authority=Developer ID Certification Authority
Authority=Apple Root CA
Timestamp=Oct 6, 2026 at 10:15:42
Info.plist entries=33
TeamIdentifier=G7HH3F8CAK
Runtime Version=14.0.0
Sealed Resources version=2 rules=13 files=412
Internal requirements count=1 size=188
"""

CODESIGN_APPLE = """Executable=/System/Applications/Calculator.app/Contents/MacOS/Calculator
Identifier=com.apple.calculator
Format=app bundle with Mach-O universal (x86_64 arm64e)
CodeDirectory v=20400 size=1234 flags=0x0(none) hashes=30+7 location=embedded
Platform identifier=15
Signature size=4442
Authority=Software Signing
Authority=Apple Code Signing Certification Authority
Authority=Apple Root CA
Signed Time=Sep 12, 2026 at 8:00:00
Info.plist entries=28
TeamIdentifier=not set
Sealed Resources version=2 rules=13 files=118
Internal requirements count=1 size=64
"""

CODESIGN_ADHOC = """Executable=/opt/homebrew/Cellar/foo/1.2/bin/foo
Identifier=foo-5555494477ef1d3ef01e4a4d6ce4fc5a3a46d3ac
Format=Mach-O thin (arm64)
CodeDirectory v=20400 size=3345 flags=0x20002(adhoc,linker-signed) hashes=101+0 location=embedded
Signature=adhoc
Info.plist=not bound
TeamIdentifier=not set
Sealed Resources=none
Internal requirements=none
"""

CODESIGN_UNSIGNED = "/Users/bob/Library/Application Support/SysUpdate/sysupdated: code object is not signed at all\n"
