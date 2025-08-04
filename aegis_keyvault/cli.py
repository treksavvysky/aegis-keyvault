import typer
import uvicorn

from .database import check_database

app = typer.Typer(help="Aegis KeyVault command line interface")


@app.command()
def health():
    """Check application and database health."""
    db_available = check_database()
    typer.echo("Server: ok")
    typer.echo(f"Database: {'ok' if db_available else 'unavailable'}")


@app.command()
def runserver(host: str = "127.0.0.1", port: int = 8000):
    """Run the FastAPI server."""
    uvicorn.run("aegis_keyvault.api:app", host=host, port=port, reload=True)


if __name__ == "__main__":
    app()
