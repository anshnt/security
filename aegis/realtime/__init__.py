"""Real-time protection: file, process, ransomware and persistence guards.

Aegis real-time protection runs entirely in user mode (no kernel driver): it
reacts to file-system change notifications and polls process / autorun state.
That is effective for most commodity threats, but it cannot *block* an
operation before it happens the way a minifilter driver can.
"""

__all__ = ["RealtimeMonitor", "notify"]


def __getattr__(name: str):  # lazy: keep `import aegis.realtime` cheap
    if name == "RealtimeMonitor":
        from aegis.realtime.monitor import RealtimeMonitor

        return RealtimeMonitor
    if name == "notify":
        from aegis.realtime.notify import notify

        return notify
    raise AttributeError(name)
