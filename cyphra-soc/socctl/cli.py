"""The CLI dispatcher — every socctl subcommand.

The dispatcher uses a registry: each subcommand registers a name,
a one-line help string, a parser-setup function, and a runner
function. The top-level :func:`main` parses arguments and dispatches.

Subcommands are defined in :mod:`socctl.commands`; this module is
the wiring.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Sequence
from dataclasses import dataclass


@dataclass
class Command:
    """One registered subcommand."""

    name: str
    help: str
    setup: Callable[[argparse.ArgumentParser], None]
    run: Callable[[argparse.Namespace], int]


_REGISTRY: dict[str, Command] = {}


def command(
    name: str,
    help: str,
    setup: Callable[[argparse.ArgumentParser], None] | None = None,
) -> Callable[[Callable[[argparse.Namespace], int]], Callable[[argparse.Namespace], int]]:
    """Register a subcommand and return the runner unchanged.

    ``name`` is the subcommand name; ``help`` is the one-line
    summary in the top-level ``--help`` output; ``setup`` (optional)
    is called with the subparser to add subcommand-specific
    arguments. The wrapped function is the runner; it receives the
    parsed :class:`argparse.Namespace` and returns an integer exit
    code (``0`` for success).
    """
    def wrap(fn: Callable[[argparse.Namespace], int]) -> Callable[[argparse.Namespace], int]:
        if name in _REGISTRY:
            raise ValueError(f"subcommand {name!r} already registered")
        _REGISTRY[name] = Command(
            name=name,
            help=help,
            setup=setup or (lambda _p: None),
            run=fn,
        )
        return fn
    return wrap


def list_commands() -> list[str]:
    """The registered command names, sorted."""
    return sorted(_REGISTRY)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="socctl",
        description="CYPHRA-SOC console surface.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    for cmd in sorted(_REGISTRY.values(), key=lambda c: c.name):
        sub = subparsers.add_parser(cmd.name, help=cmd.help)
        cmd.setup(sub)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """The CLI entry point."""
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        # ``argparse`` calls ``sys.exit(2)`` on argument errors; we
        # convert that to a return value so the test harness can
        # observe the exit code without killing the process.
        return int(exc.code or 2)
    cmd = _REGISTRY.get(args.command)
    if cmd is None:
        parser.print_help()
        return 2
    return cmd.run(args)


__all__ = ["Command", "command", "list_commands", "main"]
