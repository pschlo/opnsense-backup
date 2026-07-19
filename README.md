# OPNsense Backup

Download the current OPNsense configuration and available configuration
history into a local directory.

## Run

Install [uv](https://docs.astral.sh/uv/getting-started/installation/), set
`OPNSENSE_HOST`, `OPNSENSE_API_KEY`, and `OPNSENSE_API_SECRET`, then run:

```console
uvx https://github.com/pschlo/opnsense-backup/archive/refs/heads/main.zip --out-dir path/to/backups
```

The output directory must already exist. Append `--help` to see options for
retention, timeouts, and hosts with self-signed certificates.

Configuration backups and API credentials are sensitive. Protect the output
directory, prefer environment variables over command-line credentials, and use
`--insecure` only on a trusted network when certificate verification cannot be
configured correctly.

## Development

```console
uv sync --locked
uv run pytest
uv build
```
