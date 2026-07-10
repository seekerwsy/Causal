from collections.abc import Callable
from typing import TypeVar

import typer

from secaware.errors import SecAwareError


T = TypeVar("T")


def run_cli_action(action: Callable[[], T]) -> T:
    try:
        return action()
    except SecAwareError as error:
        typer.echo(str(error), err=True)
        raise typer.Exit(code=int(error.code)) from None
