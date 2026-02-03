"""Aegis CLI - Secure secret management without chat exposure."""

import getpass
import os
import sys

import httpx
import typer

app = typer.Typer(
    name="aegis-cli",
    help="Aegis KeyVault CLI - Securely manage secrets without chat exposure.",
    no_args_is_help=True,
)

secrets_app = typer.Typer(help="Manage secrets")
app.add_typer(secrets_app, name="secrets")


def get_base_url() -> str:
    """Get Aegis API base URL from environment."""
    url = os.getenv("AEGIS_URL", "http://localhost:8000")
    return url.rstrip("/")


def get_admin_token() -> str:
    """Get admin token from environment."""
    token = os.getenv("AEGIS_ADMIN_TOKEN")
    if not token:
        typer.echo("Error: AEGIS_ADMIN_TOKEN environment variable is required", err=True)
        raise typer.Exit(1)
    return token


@secrets_app.command("add")
def add_secret(
    name: str = typer.Argument(..., help="Secret name (e.g., ssh-pass:server1)"),
    resource: str = typer.Option(None, "--resource", "-r", help="Resource binding (e.g., host:server1)"),
    no_confirm: bool = typer.Option(False, "--no-confirm", help="Skip confirmation prompt"),
) -> None:
    """
    Add a secret securely.

    The secret value is prompted interactively (no echo) and never printed or logged.

    Example:
        aegis-cli secrets add ssh-pass:server1 --resource host:server1
    """
    base_url = get_base_url()
    admin_token = get_admin_token()

    # Prompt for secret value (no echo)
    try:
        value = getpass.getpass("Enter secret value: ")
        if not value:
            typer.echo("Error: Secret value cannot be empty", err=True)
            raise typer.Exit(1)

        if not no_confirm:
            confirm = getpass.getpass("Confirm secret value: ")
            if value != confirm:
                typer.echo("Error: Values do not match", err=True)
                raise typer.Exit(1)
    except KeyboardInterrupt:
        typer.echo("\nAborted")
        raise typer.Exit(1)

    # Build request
    payload = {"name": name, "value": value}
    if resource:
        payload["resource"] = resource

    # Send to Aegis API
    try:
        response = httpx.post(
            f"{base_url}/v1/secrets",
            json=payload,
            headers={"X-Admin-Token": admin_token, "Content-Type": "application/json"},
            timeout=30,
        )
    except httpx.ConnectError:
        typer.echo(f"Error: Could not connect to Aegis at {base_url}", err=True)
        raise typer.Exit(1)

    if response.status_code == 200:
        data = response.json()
        typer.echo(f"✓ Secret '{data['name']}' stored", color=True)
        if data.get("resource"):
            typer.echo(f"  Resource: {data['resource']}")
    elif response.status_code == 409:
        typer.echo(f"Error: Secret '{name}' already exists", err=True)
        raise typer.Exit(1)
    elif response.status_code == 401:
        typer.echo("Error: Invalid admin token", err=True)
        raise typer.Exit(1)
    else:
        typer.echo(f"Error: {response.status_code} - {response.text}", err=True)
        raise typer.Exit(1)


@secrets_app.command("delete")
def delete_secret(
    name: str = typer.Argument(..., help="Secret name to delete"),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation"),
) -> None:
    """Delete a secret."""
    base_url = get_base_url()
    admin_token = get_admin_token()

    if not force:
        confirm = typer.confirm(f"Delete secret '{name}'?")
        if not confirm:
            typer.echo("Aborted")
            raise typer.Exit(0)

    try:
        response = httpx.delete(
            f"{base_url}/v1/secrets/{name}",
            headers={"X-Admin-Token": admin_token},
            timeout=30,
        )
    except httpx.ConnectError:
        typer.echo(f"Error: Could not connect to Aegis at {base_url}", err=True)
        raise typer.Exit(1)

    if response.status_code == 200:
        typer.echo(f"✓ Secret '{name}' deleted")
    elif response.status_code == 404:
        typer.echo(f"Error: Secret '{name}' not found", err=True)
        raise typer.Exit(1)
    elif response.status_code == 401:
        typer.echo("Error: Invalid admin token", err=True)
        raise typer.Exit(1)
    else:
        typer.echo(f"Error: {response.status_code} - {response.text}", err=True)
        raise typer.Exit(1)


@secrets_app.command("list")
def list_secrets() -> None:
    """List all secrets (names and metadata, not values)."""
    base_url = get_base_url()
    admin_token = get_admin_token()

    try:
        response = httpx.get(
            f"{base_url}/v1/secrets",
            headers={"X-Admin-Token": admin_token},
            timeout=30,
        )
    except httpx.ConnectError:
        typer.echo(f"Error: Could not connect to Aegis at {base_url}", err=True)
        raise typer.Exit(1)

    if response.status_code == 200:
        data = response.json()
        secrets = data.get("secrets", [])
        if not secrets:
            typer.echo("No secrets found")
            return

        # Print table header
        typer.echo(f"{'NAME':<40} {'RESOURCE':<30} {'CREATED'}")
        typer.echo("-" * 90)
        for s in secrets:
            name = s["name"]
            resource = s.get("resource") or "-"
            created = s.get("created_at", "")[:19]  # Trim to datetime without timezone
            typer.echo(f"{name:<40} {resource:<30} {created}")
        typer.echo(f"\nTotal: {len(secrets)} secret(s)")
    elif response.status_code == 401:
        typer.echo("Error: Invalid admin token", err=True)
        raise typer.Exit(1)
    else:
        typer.echo(f"Error: {response.status_code} - {response.text}", err=True)
        raise typer.Exit(1)


@app.command("health")
def health() -> None:
    """Check Aegis API health."""
    base_url = get_base_url()

    try:
        response = httpx.get(f"{base_url}/health", timeout=10)
        if response.status_code == 200:
            typer.echo(f"✓ Aegis is healthy at {base_url}")
        else:
            typer.echo(f"✗ Aegis returned {response.status_code}", err=True)
            raise typer.Exit(1)
    except httpx.ConnectError:
        typer.echo(f"✗ Could not connect to Aegis at {base_url}", err=True)
        raise typer.Exit(1)


def main() -> None:
    """Entry point for aegis-cli."""
    app()


if __name__ == "__main__":
    main()
