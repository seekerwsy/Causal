from collections.abc import Callable
from functools import wraps
from typing import ParamSpec, TypeVar

import typer

from secaware.errors import SecAwareError


P = ParamSpec("P")
T = TypeVar("T")


def run_cli_action(action: Callable[[], T]) -> T:
    try:
        return action()
    except SecAwareError as error:
        typer.echo(str(error), err=True)
        raise typer.Exit(code=int(error.code)) from None


def cli_action(action: Callable[P, T]) -> Callable[P, T]:
    @wraps(action)
    def wrapped(*args: P.args, **kwargs: P.kwargs) -> T:
        return run_cli_action(lambda: action(*args, **kwargs))

    return wrapped
