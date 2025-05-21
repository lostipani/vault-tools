"""
Vault client custom class based on hvac.kv2 secrets engine.
"""

import os
import re
import json
from logging import Logger, getLogger
from typing import Any, Dict, List, Tuple
import hvac
from hvac.exceptions import InvalidPath


Secret = Dict[str, str]
SecretsByPath = Dict[str, Secret]
Subscheme = Dict[str, List[str] | str]
Scheme = Dict[str, Subscheme | str]


class Vault:
    """
    Vault custom client equipped with a range of utilities.

    A note on naming: a "Secret" is a dict, identified by a path, comprising at
    least one item, that is a pair of str representing a name and a value.

    Args:
        username:
        password:
        vault_params: Tuple[str, str, str] (url, namespace, mountpoint)
        logger: python logging by default
    Properties:
        dry_run: modifications are only logged and not taken into effect
    Methods:
        set_mountpoint: to set the Secret engine's mountpoint
        get: read secrets down the tree starting from a path
        set: create a new version with the provided Secret
        add: create a new version by appending to the existing secrets
        destroy: permanently delete a Secret
        migrate: migrate according to the provided schema
        migrate_and_destroy: migrate and destroy. Handle with care.
    """

    dry_run = False

    def __init__(
        self,
        username: str,
        password: str,
        vault_params: Tuple[str, str, str],
        logger: Logger = getLogger(__name__),
    ):
        """
        Establish a connection to Vault.

        Args:
            username:
            password:
            vault_params: Tuple[str, str, str] (url, namespace, mountpoint)
            logger (optional):
        """
        client = hvac.Client(
            url=vault_params[0],
            namespace=vault_params[1],
        )
        client.auth.ldap.login(
            username=username,
            password=password,
        )
        self.client = client.secrets.kv.v2

        self.logger = logger
        self.logger.debug(
            (
                "Connection established to Vault\nfor user: %s\n"
                "at: %s\nnamespace: %s"
            ),
            username,
            vault_params[0],
            vault_params[1],
        )

        try:
            self.set_mountpoint(vault_params[2])
        except IndexError:
            self.logger.warning("mountpoint not specified")

    def set_mountpoint(self, mountpoint: str) -> None:
        """
        Set a mountpoint.

        Args:
            mountpoint
        """
        self.mount_point = mountpoint
        self.logger.debug("mountpoint: %s", mountpoint)

    def _dry_run_logging(self, *args: Any, **kwargs: Any) -> None:
        """
        Log if dry run on.
        """
        if self.dry_run:
            self.logger.info(*args, **kwargs)

    def _find_valid_version(self, path: str) -> Secret:
        """
        Find most recent non-deleted version of a Secret.

        Args:
            path
        Returns:
            a Secret
        Raises:
            InvalidPath if path is a secret's engine root level, to be later 
            handled by the _fetch method. Since hvac raises a TypeError 
            in this case, the exception is converted into InvalidPath to make
            this method behave consistently with the other cases.
        """
        try:
            response = self.client.read_secret(
                path=path,
                mount_point=self.mount_point,
                raise_on_deleted_version=False,
            ).get("data")
        except TypeError as err:
            self.logger.debug("Path: %s is a secret's engine root level", path)
            raise InvalidPath from err
        while response.get("metadata").get("deletion_time"):
            previous_version = response.get("metadata").get("version") - 1
            response = self.client.read_secret_version(
                path=path,
                mount_point=self.mount_point,
                version=previous_version,
                raise_on_deleted_version=False,
            ).get("data")
        secret: Secret = response.get("data")
        return secret

    def _fetch(self, path: str) -> Secret | List[str]:
        """
        Fetch the Secret if path is tree leaf.
        OR
        Fetch a list of folders 1 level below path and at least 1 level above
        Secrets.

        Args:
            path
        Returns:
            a Secret or a list of folders names
        """
        try:
            return self._find_valid_version(path)
        except InvalidPath:
            self.logger.debug(
                (
                    "The path: %s didn't take to a Secret; "
                    "either it is an non-existing path or Secrets are below "
                    "this level: trying to descend the tree..."
                ),
                path,
            )
        try:
            folders = (
                self.client.list_secrets(
                    path=path, mount_point=self.mount_point
                )
                .get("data")
                .get("keys")
            )
            return [os.path.join(path, folder) for folder in folders]
        except InvalidPath as err:
            self.logger.error("The path: %s does not exist", path)
            raise SystemExit(f"Invalid path: {path}") from err

    def get(self, path: str, loginfo: bool = True) -> SecretsByPath:
        """
        Get secrets, recursively.

        Args:
            path: Vault path
            loginfo: to turn on/off logging at INFO level, useful when get() is
                     invoked by other methods of this class
        Returns:
            A dict of secrets indexed by the full path
        """

        def _recursive_get(path: str, secrets_by_path: SecretsByPath) -> None:
            """
            Descend the tree, recursively.

            The retrieved data is stored in the passed secrets_by_path.

            Args:
                path
                secrets_by_path
            """
            result = self._fetch(path)
            if isinstance(result, dict):
                secrets_by_path[path] = result
                self.logger.debug("Got Secret at: %s", path)
            elif isinstance(result, list):
                self.logger.debug("Non-leaf path: %s", path)
                for _path in result:
                    _recursive_get(_path, secrets_by_path)

        secrets_by_path: SecretsByPath = {}
        _recursive_get(path, secrets_by_path)
        if loginfo:
            self.logger.info(
                "Got secrets: %s", Vault._hide_secrets(secrets_by_path)
            )
        return secrets_by_path

    def backup(self, path: str, output_file: str) -> None:
        """
        Produce a backup .json file.

        Args:
            path: Vault path
            output_file: name of a JSON file
        """
        secrets = self.get(path)
        with open(f"{output_file}", "x", encoding="utf-8") as file:
            json.dump(secrets, file)
        self.logger.info(
            "Backup produced starting from path: %s and saved as: %s",
            path,
            output_file,
        )

    def set(self, path: str, secret: Secret) -> None:
        """
        Set secrets at given path by overwriting.

        In the newly produced version only the passed secrets will be present.

        Args:
            path
            secret
        """
        if not self.dry_run:
            self.client.create_or_update_secret(
                path=path, mount_point=self.mount_point, secret=secret
            )
            self.logger.debug(
                "New version: %s", Vault._hide_secrets({path: secret})
            )
        self._dry_run_logging(
            "New version would be: %s", Vault._hide_secrets({path: secret})
        )

    def add(self, path: str, secret: Secret) -> None:
        """
        Add secrets to an already existing Secret.

        Args:
            path: lowest level possible
            secret: a dict with name and value pairs of each secret
        """
        secret = self.get(path=path, loginfo=False).get(path, {}) | secret
        if not self.dry_run:
            self.set(path, secret)
            self.logger.debug(
                "New version: %s", Vault._hide_secrets({path: secret})
            )
        self._dry_run_logging(
            "New version would be: %s", Vault._hide_secrets({path: secret})
        )

    def delete(self, path: str, recursive: bool = False) -> None:
        """
        Delete last version.

        Args:
            path: Vault path
            recursive: if False, a leaf-level path has to be provided
        """
        if not recursive and isinstance(self._fetch(path), list):
            self.logger.error(
                "Delete is a leaf-level action by default. "
                "Need a path to one Secret or set recursive=True"
            )
            raise InvalidPath
        if self.dry_run:
            self._dry_run_logging(
                "Secrets would be deleted: %s",
                Vault._hide_secrets(self.get(path=path, loginfo=False)),
            )
            return
        for sub_path in self.get(path=path):
            self.client.delete_latest_version_of_secret(
                path=sub_path, mount_point=self.mount_point
            )
            self.logger.debug("Last version deleted at: %s", sub_path)

    def destroy(self, path: str, recursive: bool = True) -> None:
        """
        Destroy all versions and metadata. No way back!

        Args:
            path: Vault path
            recursive: if False, a leaf-level path has to be provided
        """
        if not recursive and isinstance(self._fetch(path), list):
            self.logger.error(
                "Destroy is a leaf-level action by default. "
                "Need a path to one Secret or set recursive=True"
            )
            raise InvalidPath
        if self.dry_run:
            self._dry_run_logging(
                "Secrets would be permanently destroyed: %s",
                Vault._hide_secrets(self.get(path=path, loginfo=False)),
            )
            return
        for sub_path in self.get(path=path, loginfo=False):
            self.client.delete_metadata_and_all_versions(
                path=sub_path, mount_point=self.mount_point
            )
            self.logger.debug("Destroyed secrets at: %s", sub_path)

    def migrate(
        self,
        old_path: str,
        new_path: str,
        subschemes: List[Dict[str, List[str] | str]],
    ) -> None:
        """
        Migrate secrets from an old_path to a new_path.

        A new Secret version is created, not appended to existing one.

        Providing subschemes allows to store secrets in subfolders relative to
        the new_path. The secret is assigned to a subfolder by matching a regex
        pattern against its name.

        If not matched by any pattern the secret is dropped from migration.

        Args:
            old_path: existing Vault path
            new_path: new Vault path
            subschemes: e.g. [{"by": [".*CLOUDSTACK.*"], "to": "cloudstack"}]
        """
        # Secrets are parsed, their new path produced piecewise and appended by
        # union of dicts new_path/subscheme. This to avoid appending secrets
        # directly to remote Vault thus producing more than one Vault version.
        secrets_by_path: SecretsByPath = {}
        for _, secrets in self.get(path=old_path, loginfo=False).items():
            for secret_name, secret_value in secrets.items():
                if path := Vault._make_path(new_path, secret_name, subschemes):
                    secrets_by_path[path] = secrets_by_path.get(path, {}) | {
                        secret_name: secret_value
                    }
                    self.logger.debug(
                        "Secret: %s found and new path would be assigned: %s",
                        secret_name,
                        path,
                    )
                else:
                    self.logger.debug(
                        "Secret: %s would be dropped from migration",
                        secret_name,
                    )
        if self.dry_run:
            self._dry_run_logging(
                "Migration resume: %s", Vault._hide_secrets(secrets_by_path)
            )
            return
        for path, secret in secrets_by_path.items():
            self.set(path=path, secret=secret)
            self.logger.debug("Migration completed")

    @staticmethod
    def _make_path(
        new_path: str,
        secret_name: str,
        subschemes: List[Dict[str, List[str] | str]],
    ) -> str | None:
        """
        Make a subfolder path starting from new_path based on subschemes.

        If no subscheme provided: return new_path itself.
        If no match found: return None.
        """
        if subschemes:
            for subscheme in subschemes:
                pattern = "|".join(subscheme["by"])
                if re.match(pattern, secret_name):
                    return os.path.join(new_path, str(subscheme.get("to")))
            return None  # secret dropped from migration
        return new_path  # no subschemes provided

    @staticmethod
    def _hide_secrets(secrets_by_path: SecretsByPath) -> SecretsByPath:
        """
        Cast secrets values to a chain of asterisks.

        Args:
            secrets_by_path
        Returns:
            secrets_by_path without secrets values
        """
        return {
            path: {secret_name: "***" for secret_name in secret.keys()}
            for path, secret in secrets_by_path.items()
        }
