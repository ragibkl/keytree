# Development

## Commands

| Command | Purpose |
|---|---|
| `keytree sync [--dry-run] [--jitter 5m] [--every 1h]` | Update authorized_keys. `--every` keeps running (for containers). |
| `keytree plan [--name NAME] [FILE]` | Show who gets which account on a server |
| `keytree check FILE...` | Validate access files (for CI) |
| `keytree version` | |

Exit codes: `0` OK, `1` partial failure (old keys kept), `2` config error.

### Host path flags

`sync` and `plan` take these, so tests and CI never touch the real host:

| Flag | Default | |
|---|---|---|
| `--root DIR` | `/` | Prefix for every host path: `/etc/passwd`, home directories, and the defaults below |
| `--config FILE` | `<root>/etc/keytree/config.yaml` | Local config |
| `--state-dir DIR` | `<root>/var/lib/keytree` | Cache and state |
| `--source SRC` | from local config | Access file; with `--name` too, no local config is needed |
| `--name NAME` | from local config, else short hostname | Server name |
| `--github-url`, `--gitlab-url` | `https://github.com`, `https://gitlab.com` | For fake servers in tests |

## Layout

| Path | |
|---|---|
| `cmd/keytree` | CLI; `main_test.go` runs whole syncs under a temp `--root` |
| `internal/config` | Access file and local config parsing, validation, server matching |
| `internal/fetch` | Downloads with timeouts, size limits and a last-good cache |
| `internal/authkeys` | Block editing (pure) and the safe writer |
| `internal/syncer` | One sync run: lock, fetch, resolve, write, state |
| `internal/passwd` | `/etc/passwd` parsing |
| `install.sh` | Installer, served at `https://ragibkl.github.io/keytree/install` |
| `test/e2e.sh` | End-to-end tests in containers |

## Testing

```sh
go test -race ./...   # unit and CLI tests, no root, no network
./test/e2e.sh         # needs Docker
```

Writing into other accounts' `authorized_keys` as root is the risky part, so
it gets the most tests:

- **Block editing**: table tests for no file, no markers, a block between
  hand-added keys, CRLF, missing trailing newline, broken markers; plus 5,000
  random cases checking that applying is idempotent, only touches the block,
  and that removing the block restores the original.
- **Filesystem safety**: symlinked `authorized_keys` or `~/.ssh` (pointing at
  a stand-in `/etc/shadow`), dangling symlinks, hard links, FIFOs, directories,
  group/world-writable `~/.ssh`, oversized files. Each must be refused with
  nothing outside `~/.ssh` touched.
- **Crash safety**: fail between write and rename; the old file must be
  intact, and a leftover temp file is cleaned up on the next run.
- **Failure rules**: a fake GitHub returning timeouts, 500s, 404s, HTML with
  a 200 and empty bodies; every row of the failure table is a test.
- **End to end** (`test/e2e.sh`), in `alpine:3` and `ubuntu:24.04` as root:
  root-only ownership tests, install with `install.sh`, real `ssh` logins as
  `root` and a normal user (right key accepted, wrong key rejected), revoke
  and check the login fails, uninstall and check access remains. Also runs
  the container image against a fake host root.

## Releasing

Push a `v*` tag. The release workflow builds static `keytree_linux_amd64` and
`keytree_linux_arm64` with `checksums.txt` (what `install.sh` downloads and
verifies), and pushes `ghcr.io/ragibkl/keytree` for amd64 and arm64.
