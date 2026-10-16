"""Active protections: web/network blocking, one-command hardening and full undo.

* ``aegis.protect.webguard`` - hosts-file domain blocking and outbound IP blocking
  (Windows Firewall / nftables / iptables) fed by the threat-intelligence feeds.
* ``aegis.protect.harden``   - declarative hardening catalogue with profiles, a plan
  (current state per action) and an apply step that writes one undo journal.
* ``aegis.protect.undo``     - lists every backup kind Aegis writes and reverts them.
* ``aegis.protect.asr``      - verified Microsoft Defender Attack Surface Reduction rule table.

This package initialiser stays import-free on purpose: ``aegis.scanners.system_audit``
imports ``aegis.protect.asr`` and must not drag the heavier modules in with it.
Every protection is explicit (never automatic), needs administrator rights, and is
reversible through ``aegis.protect.undo``."""
