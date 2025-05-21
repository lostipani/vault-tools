# Vault tools
Tools to manage Hashicorp Vault's secrets.

In particular, it provides utilities to migrate secrets from one path to another, by typing in
```
python cli.py migrate migration.json [--dry-run]
```
and
```
python cli.py destroy <path>
```

### Configuration
A `JSON` file comprising the following fields
* `url`
* `namespace`
* `mountpoint`
* `schemes`

The field `schemes` is a list of (at least one) maps with fields:
* `from`: the old path
* `to`: the new path
* `subschemes`

The optional `subschemes` allows to migrate the secrets towards a subfolders relative to the new path, by filtering over the secret's name against a regex pattern. It is made of a list of mappings with fields:
* `by`: a list of regex patterns to match against the secret's name
* `to`: the subfolder name relative to the new path

For example, a subscheme configured thusly
```json
"subschemes": [{"by": [".*HOME.*"], "to": "home"}]
```

has the effect of taking a secret item named `device_HOMEfoo` and send it to the folder `new_path/home`.

##### NB
If no subschemes are provided the new path is used without subfolders.

## Other utilities
* To list and print out secrets, descending the tree from the given path, type in

    `python cli.p get <path>`

* To add secrets to existing ones, thus creating a new version without overwriting, type in

    `python cli.py add <jsonfile>`

    where the file to provide is of the same format as the backup file.

* To set secrets creating a new version and overwriting, type in

    `python cli.py set <jsonfile>`

* To permanently delete secrets, for the provided path solely thus without descending the tree, type in

    `python cli.py destroy <path>`

## Backup secrets
A backup file is a `JSON` file structured as such
```json
{
    "pathA": {
        "NAME1": "VALUE1",
        "NAME2": "VALUE2"
    },
    "pathB": {
        "NAME3": "VALUE4",
        "NAME4": "VALUE3"
    }
}
```

* To produce a backup file named as `backup_<date>.json`, where secrets are retrieved starting from the provided path down the tree:

    `python cli.py backup <path>`

* To restore a backup file:

    `python cli.py set <backup.json>`

As a result, a new version for each Secret will be produced.

## CLI options
This CLI features the following options to be passed before calling a command
* `--username` 
* `--password`
* `--vault-url`
* `--vault-namespace`
* `--vault-mountpoint`
* `--log-level`

For further info and to show the default values, type in

```bash
python cli.py --help
```
