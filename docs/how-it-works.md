# How it works

## A sync, step by step

1. Fetch the access file and validate it.
2. Collect every `servers` entry matching this server's name.
3. For each account, turn users and groups into key sources.
4. Fetch each source's keys. Every line must parse as an SSH public key;
   anything else (an HTML error page from a captive portal, say) counts as a
   failed fetch. Keys whose fingerprint is under `revoked` are dropped here,
   including keys carried over during an outage.
5. Write each account's block in `~/.ssh/authorized_keys`.
6. Remove the block from accounts keytree managed before that no longer have
   an entry.

Accounts are read from `/etc/passwd` directly, not through NSS, so LDAP or
sssd accounts aren't supported.

## The managed block

keytree owns only the lines between its markers.

```
ssh-ed25519 AAAA... breakglass
# BEGIN keytree (managed, do not edit)
ssh-ed25519 AAAA... keytree:ragib github:ragibkl
ssh-ed25519 AAAA... keytree:backup-bot key
# END keytree
```

- Everything outside the block is kept byte for byte.
- No markers yet: the block is appended.
- Broken markers (`BEGIN` without `END`, two blocks): the file is left alone
  and an error is logged.
- No keys for an account: the block is removed entirely.
- Unchanged content isn't rewritten.

## Failure rules

keytree never removes access because something went wrong, only because the
config says so.

| Situation | Result | Exit |
|---|---|---|
| Access file can't be fetched | No changes | 1 |
| Access file fails validation | No changes | 2 |
| No `servers` entry matches this server | No changes, warning | 2 |
| One user's key fetch fails (timeout, HTTP error, not SSH keys) | Their cached keys are used; with no cache, the keys already in the file are kept | 1 |
| GitHub returns an empty list for a user | That user has no keys | 0 |
| An account in the file doesn't exist on this server | Skipped, warning | 0 |
| File fetched and valid, a user removed | Their keys are removed | 0 |

State lives in `/var/lib/keytree/`: the last good copy of each user's keys,
the access file and its ETag (so an unchanged file costs a `304`), the list
of accounts keytree manages, and `last-success`, written after each clean run.

## File safety

keytree runs as root and writes inside other accounts' home directories,
which those accounts control. So:

- `~/.ssh` and `authorized_keys` are opened relative to the home directory
  with `O_NOFOLLOW`. A symlink in either place is refused, never followed.
- They must be owned by the account. `~/.ssh` must not be group- or
  world-writable, and `authorized_keys` must be a regular file with one hard
  link. Otherwise the account is skipped and an error logged.
- Checks run on the opened file, not the path, so the file can't be swapped
  between check and use.
- Writes go to a temp file in `~/.ssh`, which is fsynced, given the account's
  owner and mode `0600`, then renamed over `authorized_keys`. A crash leaves
  the old file intact; leftover temp files are removed on the next run.
- `~/.ssh` is created with mode `0700` and the account's owner if missing.
- Runs take a lock, so two syncs never overlap.

## Timing

- New keys on GitHub: next hourly sync (cron runs at a random minute per
  server, plus up to 5 minutes of jitter).
- Changes to your config repo: the same, plus up to about 5 minutes of
  `raw.githubusercontent.com` caching.

## Not in v1

- SSH key options (`from=`, `command=`) per account
- Private config repos (they'd need a token on every server)
- Signed configs
- Creating accounts
