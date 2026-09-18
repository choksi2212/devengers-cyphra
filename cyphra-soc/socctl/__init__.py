"""socctl — the SOC console surface.

A CLI surface that exposes the platform's state to the operator. The
console is not a separate process; it is a set of subcommands that
import the same modules the rest of the platform uses. Every
subcommand's output is plain text — pipeable, greppable, and stable
across releases.

Subcommands:

* ``socctl readiness`` — the readiness report from
  :func:`core.config.readiness_report`.
* ``socctl metrics`` — the metrics tracker snapshot.
* ``socctl cases`` — the case queue (open / closed / archived).
* ``socctl crises`` — the crisis board.
* ``socctl hunts`` — the hunt library and the runner's stats.
* ``socctl regression`` — the regression harness's verdict.
* ``socctl coverage`` — the coverage matrix.
* ``socctl intel`` — the intel-store stats.

Each subcommand is a function in :mod:`socctl.commands`; the
:func:`socctl.cli.main` entry point parses arguments and dispatches.
The package has no third-party dependencies — the CLI is plain
``argparse``.
"""

from socctl.cli import Command, command, list_commands, main

__all__ = ["Command", "command", "list_commands", "main"]
