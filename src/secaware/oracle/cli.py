import typer


app = typer.Typer(help="SecAware standalone security oracle.")


@app.callback()
def main() -> None:
    """Run the SecAware standalone security oracle."""


if __name__ == "__main__":
    app()
