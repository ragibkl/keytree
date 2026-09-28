# keytree

Log in to all your servers with the SSH keys on your GitHub account.

You keep one small file in a GitHub repo that says who can log in to which
server. Each server checks it every hour and updates its `authorized_keys`.

- **New laptop?** Add its key to GitHub. Every server accepts it within the hour.
- **Giving a friend access?** Add their GitHub username to the file.
- **Taking it away?** Remove them. Their keys are gone within the hour.

No `ssh-copy-id` on every machine, and nothing to change in sshd.

Works on Alpine, Debian and Ubuntu (amd64 and arm64).

## 1. Make your config repo

Create a **public** GitHub repo called `server-keys` with one file,
`keytree.yaml`:

```yaml
version: 1

users:
  me:
    github: your-github-username

servers:
  "*":            # every server
    root:         # can be logged in to as root
      users: [me] # by me
```

That's enough to start. [More examples](#more-examples) below.

## 2. Install on a server

On the server's console, as root, type:

```sh
wget -qO- https://ragibkl.github.io/keytree/install | sh -s your-github-username
```

`your-github-username` means `your-github-username/server-keys`. If your repo
has another name, use `owner/repo`; for another branch, `owner/repo@branch`.

The installer:

1. puts the `keytree` program in `/usr/local/bin`
2. saves your repo in `/etc/keytree/config.yaml`
3. adds an hourly cron job
4. runs it once, so you can log in straight away

Your server's **hostname** is how keytree finds its entry under `servers`, so
set it before installing. If you can't, add `--name the-name-in-your-file`.

No `wget`? `curl -fsSL https://ragibkl.github.io/keytree/install | sh -s your-github-username`
works too.

## Everyday use

All of these are edits to `keytree.yaml`. Servers pick them up within the hour.

| I want to... | Do this |
|---|---|
| Use a new laptop | Add the key to your GitHub account. No edit needed. |
| Give a friend access | Add them under `users`, then to a server's list. |
| Take access away | Remove them from the lists. |
| Add a new server | Install keytree on it. If an existing entry (like `"*"`) matches its hostname, that's all. |
| See who can get into a server | `keytree plan --name <server> keytree.yaml` |
| Check the file before pushing | `keytree check keytree.yaml` |

Don't want to wait an hour? Run `keytree sync` on the server.

## More examples

```yaml
version: 1

users:
  ragib:
    github: ragibkl
  anas:
    github: anasazmi571
  backup-bot:              # no GitHub account: write the key out
    keys:
      - ssh-ed25519 AAAAC3Nz... backup@nas

groups:
  admins: [ragib]
  friends: [anas]

servers:
  "vmbr1-*":               # every server whose hostname starts with vmbr1-
    root:
      groups: [admins]
  vmbr1-ubuntu-coder:      # one server: anas gets their own account here
    anas:
      users: [anas]
  nas:
    backup:
      users: [backup-bot]
```

- A server uses **every** entry that matches its hostname. Above,
  `vmbr1-ubuntu-coder` gets both the `vmbr1-*` root access and the `anas`
  account.
- Accounts (`root`, `anas`, `backup`) must already exist on the server.
  keytree doesn't create them.
- Keys can also come from GitLab: `gitlab: username`.

Full reference: [docs/config.md](docs/config.md).

## Your existing keys are safe

keytree only manages the lines between its own markers in
`~/.ssh/authorized_keys`:

```
ssh-ed25519 AAAA... my-emergency-key          <- yours, never touched
# BEGIN keytree (managed, do not edit)
ssh-ed25519 AAAA... keytree:ragib github:ragibkl
# END keytree
```

Keep an emergency key outside the markers if you like.

If GitHub or your internet is down, keytree keeps the keys it already has.
It only removes someone when your file says so.

## When something's wrong

- **See what it's doing**: `keytree sync` prints what changed and any warnings.
  `keytree sync --dry-run` shows what would change without writing anything.
- **Logs from cron**: on Alpine, `grep keytree /var/log/messages`; on
  Ubuntu, `journalctl -t keytree`.
- **"no servers entry matches"**: the hostname (short form, before the first
  `.`) isn't in your file. Check with `hostname -s`.
- **Last good sync**: `cat /var/lib/keytree/last-success`.

## Uninstall

```sh
wget -qO- https://ragibkl.github.io/keytree/install | sh -s -- --uninstall
```

This removes the program, cron job and settings. Keys it already wrote stay in
place so you aren't locked out; delete the `# BEGIN keytree` block by hand if
you want them gone.

## Running it in a container

For hosts where you'd rather not install anything, there's an image:
`ghcr.io/ragibkl/keytree`. See [`compose.example.yaml`](compose.example.yaml).
Set `--name`, because inside a container the hostname is the container ID.

## Security

- Anyone who can push to your config repo can let themselves into every
  server. Turn on branch protection and review changes.
- The config repo is public: it shows GitHub usernames, account names and
  hostnames, but no secrets. Public keys are public by design.
- keytree runs as root, because it writes into other accounts' home
  directories. It refuses symlinks and files it doesn't expect; see
  [docs/how-it-works.md](docs/how-it-works.md).

## More

- [docs/config.md](docs/config.md): config file reference and validation rules
- [docs/how-it-works.md](docs/how-it-works.md): what a sync does, failure rules, file safety
- [docs/development.md](docs/development.md): all commands and flags, building, testing
