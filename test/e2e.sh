#!/bin/sh
# End-to-end test: in throwaway Alpine and Ubuntu containers, as root, run
# the root-only unit tests, then keytree sync, then real ssh logins.
# Needs docker and go. Nothing touches the host outside ./dist and a temp dir.
set -eu

cd "$(dirname "$0")/.."
IMAGES=${IMAGES:-"alpine:3 ubuntu:24.04"}

mkdir -p dist
CGO_ENABLED=0 go build -o dist/keytree ./cmd/keytree
CGO_ENABLED=0 go test -c -o dist/authkeys.test ./internal/authkeys

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
ssh-keygen -q -t ed25519 -N '' -C e2e -f "$work/id_e2e"
ssh-keygen -q -t ed25519 -N '' -C intruder -f "$work/id_intruder"
cat >"$work/keytree.yaml" <<EOF
version: 1
users:
  e2e:
    keys:
      - $(cat "$work/id_e2e.pub")
servers:
  "e2e-*":
    root:
      users: [e2e]
    alice:
      users: [e2e]
EOF
cp dist/keytree dist/authkeys.test install.sh "$work/"
chmod 644 "$work"/id_*

cat >"$work/inside.sh" <<'EOF'
#!/bin/sh
set -eu
if command -v apk >/dev/null; then
  apk add --no-cache -q openssh openssh-client >/dev/null
  adduser -D alice
else
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq >/dev/null
  apt-get install -y -qq openssh-server openssh-client >/dev/null
  useradd -m alice
  mkdir -p /run/sshd
fi
# Unlock both accounts for key-only login (no password is set).
sed -i -E 's/^(root|alice):[^:]*:/\1:*:/' /etc/shadow
ssh-keygen -A >/dev/null
/usr/sbin/sshd

echo "--- root-only unit tests"
/e2e/authkeys.test -test.run 'Update|Read' -test.count=1 -test.v >/tmp/unit.log 2>&1 ||
  { cat /tmp/unit.log; exit 1; }
grep -q -- '--- PASS: TestUpdateOwnershipAsRoot' /tmp/unit.log ||
  { cat /tmp/unit.log; echo "root-only ownership test did not run" >&2; exit 1; }
echo "passed, including TestUpdateOwnershipAsRoot"

echo "--- sync"
mkdir -p -m 700 /root/.ssh
echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ breakglass' >/root/.ssh/authorized_keys
/e2e/install.sh file:///e2e/keytree.yaml --binary /e2e/keytree --name e2e-box
grep -q 'keytree sync' /etc/crontabs/root 2>/dev/null || grep -q 'keytree sync' /etc/cron.d/keytree
keytree sync # idempotent, reads /etc/keytree/config.yaml

stat -c '%U %a %n' /home/alice/.ssh /home/alice/.ssh/authorized_keys
[ "$(stat -c %U:%a /home/alice/.ssh)" = alice:700 ]
[ "$(stat -c %U:%a /home/alice/.ssh/authorized_keys)" = alice:600 ]
grep -q breakglass /root/.ssh/authorized_keys

cp /e2e/id_e2e /e2e/id_intruder /tmp/ && chmod 600 /tmp/id_e2e /tmp/id_intruder
opts="-o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"
for u in root alice; do
  ssh $opts -i /tmp/id_e2e "$u@127.0.0.1" true
  echo "login as $u: ok"
  if ssh $opts -i /tmp/id_intruder "$u@127.0.0.1" true 2>/dev/null; then
    echo "intruder key logged in as $u" >&2; exit 1
  fi
done

echo "--- revoke alice"
sed -i '/^    alice:/,$d' /e2e/keytree.yaml
keytree sync
if ssh $opts -i /tmp/id_e2e alice@127.0.0.1 true 2>/dev/null; then
  echo "alice still has access after revoke" >&2; exit 1
fi
echo "alice revoked: ok"

echo "--- uninstall"
/e2e/install.sh --uninstall
! command -v keytree >/dev/null
! grep -qs 'keytree sync' /etc/crontabs/root /etc/cron.d/keytree
[ ! -e /etc/keytree ] && [ ! -e /var/lib/keytree ]
ssh $opts -i /tmp/id_e2e root@127.0.0.1 true # keys stay after uninstall
echo "uninstall: ok"
EOF
chmod +x "$work/inside.sh"

for image in $IMAGES; do
  echo "=== $image"
  cp "$work/keytree.yaml" "$work/keytree.yaml.orig"
  docker run --rm -v "$work:/e2e" "$image" /e2e/inside.sh
  mv "$work/keytree.yaml.orig" "$work/keytree.yaml"
done
echo "=== container image"
docker build -q -t keytree:e2e . >/dev/null
hostroot="$work/hostroot"
mkdir -p "$hostroot/etc" "$hostroot/home/alice"
echo "alice:x:$(id -u):$(id -g)::/home/alice:/bin/sh" >"$hostroot/etc/passwd"
docker run --rm -v "$work:/e2e:ro" -v "$hostroot:/host" keytree:e2e \
  sync --root /host --source file:///e2e/keytree.yaml --name e2e-box
grep -q "$(cut -d' ' -f2 "$work/id_e2e.pub")" "$hostroot/home/alice/.ssh/authorized_keys"
[ "$(stat -c %u "$hostroot/home/alice/.ssh/authorized_keys")" = "$(id -u)" ]
echo "container sync: ok"
docker run --rm -v "$hostroot:/host" alpine:3 rm -rf /host/var # root-owned state

echo "=== e2e passed"
