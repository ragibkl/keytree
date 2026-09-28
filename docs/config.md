# Config reference

keytree reads two files: the shared **access file** (`keytree.yaml`, in your
config repo) and a small **local config** on each server.

## Access file: `keytree.yaml`

```yaml
version: 1

users:
  ragib:
    github: ragibkl
  anas:
    github: anasazmi571
    gitlab: anas
  backup-bot:
    keys:
      - ssh-ed25519 AAAAC3Nz... backup@nas

groups:
  admins: [ragib]
  friends: [anas]

servers:
  "vmbr1-*":
    root:
      groups: [admins]
  vmbr1-ubuntu-coder:
    anas:
      users: [anas]
  nas:
    backup:
      users: [backup-bot]
```

### `revoked`

Optional. Key fingerprints, in the `SHA256:...` form printed by
`ssh-keygen -l` and logged by sshd. A key with one of these fingerprints is
never written, whatever user or source it comes from (GitHub, GitLab or
`keys:`), and it's removed from blocks on the next sync.

```yaml
revoked:
  - SHA256:dx4kgXpncJoowp6ldMP090sbm7ZEMaAGF5uQwlnqKkU   # old laptop
```

Needs keytree v0.2.0 or later on every server. Keys added by hand outside
keytree's block aren't affected.

### `version`

Required. Must be `1`.

### `users`

A person (or bot) and where their public keys come from. A user can have
more than one source; the keys are combined.

| Field    | Keys fetched from                    |
|----------|--------------------------------------|
| `github` | `https://github.com/<name>.keys`     |
| `gitlab` | `https://gitlab.com/<name>.keys`     |
| `keys`   | the list itself (plain public keys, one per entry, no options) |

### `groups`

A name for a list of users. Groups contain users only; they don't nest.

### `servers`

A tree: server → local account → `users` and/or `groups`.

- A server key is a hostname or a glob: `*`, `vmbr1-*`, `web-[0-9]`.
- A server uses **every** entry that matches its name. For each account, the
  lists from all matching entries are combined.
- An account with empty lists (`root: {}` or `users: []`) means nobody:
  keytree removes its block. Use this to take access away on purpose.
- Accounts must already exist on the server (in `/etc/passwd`). keytree never
  creates them; a missing account is logged and skipped.

### Validation

The whole file is rejected, and nothing on any server changes, if:

- `version` is missing or unknown
- a field is unknown (a typo like `grops:` fails loudly instead of granting
  nothing)
- a user or group used under `servers` isn't defined
- a group lists an undefined user
- a user has no key source
- a GitHub or GitLab username isn't valid
- a `keys:` entry isn't exactly one valid SSH public key, or has options
  (`from=`, `command=`, ...)
- a server pattern or account name isn't valid
- a `revoked` entry isn't a `SHA256:` fingerprint

`keytree check keytree.yaml` runs exactly these checks. Run it in CI on your
config repo; [ragibkl/server-keys](https://github.com/ragibkl/server-keys/blob/main/.github/workflows/check.yml)
has a workflow you can copy.

## Local config: `/etc/keytree/config.yaml`

Written by the installer.

```yaml
source: https://raw.githubusercontent.com/ragibkl/server-keys/main/keytree.yaml
# name: vmbr1-ubuntu-coder
```

### `source`

Where the access file lives. Required. Either:

- an `https://` URL, usually the raw GitHub address
  (`https://raw.githubusercontent.com/<owner>/<repo>/<branch>/keytree.yaml`),
  so the repo must be public; or
- a `file://` path, for example a git checkout you update yourself.

### `name`

This server's name for matching `servers` entries. Optional; defaults to the
short hostname (everything before the first `.`). Set it in containers,
where the hostname is the container ID, and on hosts with generated
hostnames.
