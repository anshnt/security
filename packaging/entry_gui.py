"""PyInstaller entry point for the windowed build (aegis-gui.exe).

With no arguments it opens the desktop app. With arguments it runs the CLI
headlessly (no console window) - used by the scheduled background tasks, e.g.
`aegis-gui.exe monitor`. Output goes to the log file in the data directory.
"""
import multiprocessing
import sys

if __name__ == "__main__":
    multiprocessing.freeze_support()
    if len(sys.argv) > 1 and sys.argv[1] != "gui":
        from aegis.cli import main

        sys.exit(main(sys.argv[1:]))
    from aegis.ui.gui import launch_gui

    sys.exit(launch_gui())
