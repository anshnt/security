"""Desktop user interface (tkinter / ttk, standard library only)."""

__all__ = ["launch_gui"]


def launch_gui() -> int:
    """Open the Aegis desktop application (imports tkinter lazily)."""
    from aegis.ui.gui import launch_gui as _launch

    return _launch()
