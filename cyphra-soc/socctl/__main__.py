"""The socctl CLI entry point — ``python -m socctl ...``.

Importing the package's submodules registers every subcommand on
import; :func:`socctl.cli.main` then parses and dispatches.
"""

from socctl import commands  # noqa: F401 — imports register every subcommand
from socctl.cli import main
import sys

if __name__ == "__main__":
    sys.exit(main())
