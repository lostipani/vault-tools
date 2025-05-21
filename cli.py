"""
CLI to perform Hashicorp's Vault operation on secrets
"""

from datetime import datetime as dt
import os
import json
import logging
from typing import Any
import click

from vault import Vault


# pylint: disable=too-many-arguments, too-many-positional-arguments
@click.group()
@click.password_option(
    "--username",
    hide_input=False,
    confirmation_prompt=False,
    default=os.environ.get("USER"),
    help="Username to login on vault",
    show_default=True,
)
@click.password_option(
    "--password",
    confirmation_prompt=False,
    hide_input=True,
    help="Password to login on vault",
)
@click.option(
    "--log-level",
    default="INFO",
    show_default=True,
    type=click.Choice(
        ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], case_sensitive=False
    ),
)
@click.option(
    "--vault-url",
    default="localhost:443/vault",
    show_default=True,
)
@click.option(
    "--vault-namespace",
    default="test",
    show_default=True,
)
@click.option(
    "--vault-mountpoint",
    default="secrets",
    show_default=True,
)
@click.pass_context
def cli(
    ctx: Any,
    username: str,
    password: str,
    vault_url: str,
    vault_namespace: str,
    vault_mountpoint: str,
    log_level: str,
) -> None:
    """
    Entrypoint CLI function

    Options:
        username
        password
        vault_url
        vault_namespace
        vault_mountpoint
        log_level
    """

    def _get_logger(log_level: str) -> logging.Logger:
        return logging.getLogger("vault_logger")

    ctx.obj = {}
    ctx.obj["vault"] = Vault(
        username=username,
        password=password,
        vault_params=(vault_url, vault_namespace, vault_mountpoint),
        logger=_get_logger(log_level),
    )


@cli.command(name="get")
@click.argument("path")
@click.pass_context
def get_secrets(ctx: Any, path: str) -> None:
    """
    Get secrets

    Args:
        path
    """

    ctx.obj.get("vault").get(path=path)


@cli.command(name="set")
@click.argument("jsonfile")
@click.option("--dry-run", is_flag=True, default=False, show_default=True)
@click.pass_context
def set_secrets(ctx: Any, jsonfile: str, dry_run: bool) -> None:
    """
    Set secrets

    Args:
        jsonfile
        dry_run
    """
    with open(jsonfile, "r", encoding="utf-8") as file:
        data = json.load(file)

    vault = ctx.obj.get("vault")
    vault.dry_run = dry_run
    for path, secret in data.items():
        ctx.obj.get("vault").set(path, secret)


@cli.command(name="add")
@click.argument("jsonfile")
@click.option("--dry-run", is_flag=True, default=False, show_default=True)
@click.pass_context
def add_secrets(ctx: Any, jsonfile: str, dry_run: bool) -> None:
    """
    Add secrets

    Args:
        jsonfile
        dry_run
    """
    with open(jsonfile, "r", encoding="utf-8") as file:
        data = json.load(file)

    vault = ctx.obj.get("vault")
    vault.dry_run = dry_run
    for path, secret in data.items():
        ctx.obj.get("vault").add(path, secret)


@cli.command(name="destroy")
@click.argument("path")
@click.option("--dry-run", is_flag=True, default=False, show_default=True)
@click.option("--recursive", is_flag=True, default=False, show_default=True)
@click.pass_context
def destroy_secrets(
    ctx: Any, path: str, dry_run: bool, recursive: bool
) -> None:
    """
    Permanently delete secrets

    Args:
        path
        dry_run
        recursive
    """

    vault = ctx.obj.get("vault")
    vault.dry_run = dry_run
    vault.destroy(path=path, recursive=recursive)


@cli.command(name="backup")
@click.argument("path")
@click.option(
    "--output",
    default=f"backup_vault_{dt.now().strftime('%Y-%m-%d_%H-%M-%S')}.json",
    show_default=True,
)
@click.pass_context
def backup_secrets(ctx: Any, path: str, output: str) -> None:
    """
    Produce a backup JSON file starting from the provided path

    Args:
        path
        output (optional)
    """

    ctx.obj.get("vault").backup(path, output)


@cli.command(name="migrate")
@click.argument("jsonfile")
@click.option("--dry-run", is_flag=True, default=False, show_default=True)
@click.pass_context
def migrate(ctx: Any, jsonfile: str, dry_run: bool) -> None:
    """
    Migrate secrets

    Args:
        jsonfile
        dry_run
    """
    with open(jsonfile, "r", encoding="utf-8") as file:
        data = json.load(file)

    vault = ctx.obj.get("vault")
    vault.dry_run = dry_run

    for scheme in data["schemes"]:
        vault.migrate(
            old_path=scheme["from"],
            new_path=scheme["to"],
            subschemes=scheme.get("subschemes"),
        )


@cli.command(name="migrate-and-destroy")
@click.argument("jsonfile")
@click.pass_context
def migrate_and_destroy(
    ctx: Any,
    jsonfile: str,
) -> None:
    """
    Migrate and destroy secrets

    Args:
        jsonfile
    """
    with open(jsonfile, "r", encoding="utf-8") as file:
        data = json.load(file)

    for scheme in data["schemes"]:
        ctx.obj.get("vault").migrate(
            old_path=scheme["from"],
            new_path=scheme["to"],
            subschemes=scheme.get("subschemes"),
        )
    for scheme in data["schemes"]:
        ctx.obj.get("vault").destroy(path=scheme["from"])


cli.add_command(get_secrets)
cli.add_command(set_secrets)
cli.add_command(add_secrets)
cli.add_command(backup_secrets)
cli.add_command(destroy_secrets)
cli.add_command(migrate)
cli.add_command(migrate_and_destroy)

if __name__ == "__main__":
    cli()
