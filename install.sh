#!/bin/sh
# Install keytree on Alpine or Debian/Ubuntu: binary, local config, hourly
# cron entry, then one sync.
#
#   wget -qO- https://ragibkl.github.io/keytree/install | sh -s <url>
#
# <url> is where your keytree.yaml lives, for example
# https://raw.githubusercontent.com/<you>/server-keys/main/keytree.yaml
#
# Options:
#   --name NAME      server name, if it isn't the short hostname
#   --version TAG    release to install (default: latest)
#   --binary PATH    install this local binary instead of downloading
#   --uninstall      remove keytree (keys already written stay in place)
set -eu

REPO=ragibkl/keytree
PREFIX=/usr/local/bin
CONFIG=/etc/keytree/config.yaml

source_url= name= version=latest binary= uninstall=
while [ $# -gt 0 ]; do
  case $1 in
    --source) source_url=$2; shift 2 ;;
    --name) name=$2; shift 2 ;;
    --version) version=$2; shift 2 ;;
    --binary) binary=$2; shift 2 ;;
    --uninstall) uninstall=1; shift ;;
    -*) echo "install.sh: unknown option $1" >&2; exit 2 ;;
    *) source_url=$1; shift ;;
  esac
done

say() { echo "keytree install: $*"; }
die() { echo "keytree install: $*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "run as root"

if [ -n "$uninstall" ]; then
  rm -f /etc/cron.d/keytree "$PREFIX/keytree"
  if [ -f /etc/crontabs/root ]; then
    grep -v 'keytree sync' /etc/crontabs/root >/etc/crontabs/root.new || true
    mv /etc/crontabs/root.new /etc/crontabs/root
  fi
  rm -rf /etc/keytree /var/lib/keytree
  say "removed. Keys keytree wrote are still in each ~/.ssh/authorized_keys,"
  say "between the '# BEGIN keytree' and '# END keytree' lines; delete them by hand."
  exit 0
fi

[ -n "$source_url" ] || [ -f "$CONFIG" ] || die "usage: sh -s <url of your keytree.yaml>"

# --- binary
if [ -z "$binary" ]; then
  case $(uname -m) in
    x86_64 | amd64) arch=amd64 ;;
    aarch64 | arm64) arch=arm64 ;;
    *) die "unsupported architecture $(uname -m)" ;;
  esac
  if [ "$version" = latest ]; then
    base="https://github.com/$REPO/releases/latest/download"
  else
    base="https://github.com/$REPO/releases/download/$version"
  fi
  if command -v curl >/dev/null; then
    get() { curl -fsSL -o "$2" "$1"; }
  elif command -v wget >/dev/null; then
    get() { wget -q -O "$2" "$1"; }
  else
    die "need curl or wget"
  fi
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  asset="keytree_linux_$arch"
  say "downloading $asset ($version)"
  get "$base/$asset" "$tmp/$asset"
  get "$base/checksums.txt" "$tmp/checksums.txt"
  (cd "$tmp" && grep " $asset\$" checksums.txt | sha256sum -c -) >/dev/null ||
    die "checksum mismatch for $asset"
  binary="$tmp/$asset"
fi
mkdir -p "$PREFIX"
install -m 0755 "$binary" "$PREFIX/keytree"
say "installed $("$PREFIX/keytree" version)"

# --- local config
if [ -n "$source_url" ]; then
  mkdir -p "$(dirname "$CONFIG")"
  {
    echo "source: $source_url"
    [ -z "$name" ] || echo "name: $name"
  } >"$CONFIG"
  chmod 0644 "$CONFIG"
  say "wrote $CONFIG"
fi

# --- hourly cron at a random minute, so servers don't all sync at once
minute=$(awk 'BEGIN { srand(); print int(rand() * 60) }')
job="$PREFIX/keytree sync --jitter 5m 2>&1 | logger -t keytree"
if command -v apk >/dev/null; then
  tab=/etc/crontabs/root
  mkdir -p "$(dirname "$tab")"
  touch "$tab"
  grep -v 'keytree sync' "$tab" >"$tab.new" || true
  echo "$minute * * * * $job" >>"$tab.new"
  mv "$tab.new" "$tab"
  if command -v rc-update >/dev/null; then
    rc-update add crond default >/dev/null 2>&1 || true
    rc-service crond start >/dev/null 2>&1 || true
  fi
  say "cron: $tab at minute $minute"
elif [ -d /etc/cron.d ] || command -v apt-get >/dev/null; then
  if ! command -v cron >/dev/null && command -v apt-get >/dev/null; then
    say "installing cron"
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq cron >/dev/null
  fi
  mkdir -p /etc/cron.d
  printf '# keytree: sync SSH access hourly\n%s * * * * root %s\n' "$minute" "$job" >/etc/cron.d/keytree
  chmod 0644 /etc/cron.d/keytree
  if command -v systemctl >/dev/null && [ -d /run/systemd/system ]; then
    systemctl enable --now cron >/dev/null 2>&1 || true
  fi
  say "cron: /etc/cron.d/keytree at minute $minute"
else
  say "no supported cron found; run '$PREFIX/keytree sync' hourly yourself"
fi

# --- first sync
say "running first sync"
if "$PREFIX/keytree" sync; then
  say "done"
else
  say "first sync reported problems (see above); cron will retry hourly"
fi
