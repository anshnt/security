"""PyInstaller entry point for the console build (aegis.exe)."""
import multiprocessing
import sys

if __name__ == "__main__":
    multiprocessing.freeze_support()
    from aegis.cli import main

    sys.exit(main())
