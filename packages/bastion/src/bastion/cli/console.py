"""Shared console and CLI utilities."""

from __future__ import annotations

import click
import typer
from rich.console import Console

# Shared console instance for all CLI commands
console = Console()


class NaturalOrderGroup(typer.core.TyperGroup):
    """Custom group that lists commands in alphabetical order."""

    def list_commands(self, ctx: click.Context) -> list[str]:
        return sorted(super().list_commands(ctx))
