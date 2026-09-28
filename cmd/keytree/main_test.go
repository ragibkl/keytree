package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/ragibkl/keytree/internal/authkeys"
)

func testKey(t *testing.T) string {
	t.Helper()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	sp, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sp)))
}

// fakeGitHub serves <user>.keys from a map the test can change.
type fakeGitHub struct {
	mu   sync.Mutex
	keys map[string]string
	down map[string]bool
}

func (g *fakeGitHub) set(user, keys string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.keys[user] = keys
}

func (g *fakeGitHub) setDown(user string, down bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.down[user] = down
}

func (g *fakeGitHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	defer g.mu.Unlock()
	user := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/"), ".keys")
	if g.down[user] {
		w.WriteHeader(502)
		return
	}
	k, ok := g.keys[user]
	if !ok {
		w.WriteHeader(404)
		return
	}
	fmt.Fprint(w, k)
}

// host is a fake server filesystem under a temp --root.
type host struct {
	t      *testing.T
	root   string
	source string
	gh     *fakeGitHub
	srv    *httptest.Server
}

func newHost(t *testing.T) *host {
	t.Helper()
	root := t.TempDir()
	h := &host{t: t, root: root, gh: &fakeGitHub{keys: map[string]string{}, down: map[string]bool{}}}
	h.srv = httptest.NewServer(h.gh)
	t.Cleanup(h.srv.Close)

	uid, gid := os.Getuid(), os.Getgid()
	var pw bytes.Buffer
	for _, u := range []string{"root", "anas", "backup"} {
		home := "/home/" + u
		if u == "root" {
			home = "/root"
		}
		fmt.Fprintf(&pw, "%s:x:%d:%d::%s:/bin/sh\n", u, uid, gid, home)
		os.MkdirAll(filepath.Join(root, home), 0o755)
	}
	os.MkdirAll(filepath.Join(root, "etc/keytree"), 0o755)
	os.WriteFile(filepath.Join(root, "etc/passwd"), pw.Bytes(), 0o644)

	h.source = filepath.Join(root, "srv/keytree.yaml")
	os.MkdirAll(filepath.Dir(h.source), 0o755)
	os.WriteFile(filepath.Join(root, "etc/keytree/config.yaml"),
		[]byte("source: file://"+h.source+"\nname: vmbr1-coder\n"), 0o644)
	return h
}

func (h *host) config(yaml string) {
	h.t.Helper()
	if err := os.WriteFile(h.source, []byte(yaml), 0o644); err != nil {
		h.t.Fatal(err)
	}
}

func (h *host) run(args ...string) (int, string) {
	h.t.Helper()
	var out, errb bytes.Buffer
	full := append([]string{args[0], "--root", h.root, "--github-url", h.srv.URL}, args[1:]...)
	code := run(full, &out, &errb)
	return code, out.String() + errb.String()
}

func (h *host) keys(account string) string {
	h.t.Helper()
	home := "/home/" + account
	if account == "root" {
		home = "/root"
	}
	data, err := os.ReadFile(filepath.Join(h.root, home, ".ssh/authorized_keys"))
	if os.IsNotExist(err) {
		return ""
	}
	if err != nil {
		h.t.Fatal(err)
	}
	return string(data)
}

const baseConfig = `version: 1
users:
  ragib: {github: ragibkl}
  anas: {github: anasazmi571}
groups:
  admins: [ragib]
servers:
  "vmbr1-*":
    root:
      groups: [admins]
  vmbr1-coder:
    anas:
      users: [anas]
`

func TestSyncLifecycle(t *testing.T) {
	h := newHost(t)
	ragib1, ragib2, anas1 := testKey(t), testKey(t), testKey(t)
	h.gh.set("ragibkl", ragib1+"\n")
	h.gh.set("anasazmi571", anas1+"\n")
	h.config(baseConfig)

	// First run writes both accounts and leaves hand keys alone.
	os.MkdirAll(filepath.Join(h.root, "root/.ssh"), 0o700)
	os.WriteFile(filepath.Join(h.root, "root/.ssh/authorized_keys"), []byte("ssh-rsa BREAKGLASS\n"), 0o600)
	if code, out := h.run("sync"); code != 0 {
		t.Fatalf("sync: %d\n%s", code, out)
	}
	root := h.keys("root")
	if !strings.HasPrefix(root, "ssh-rsa BREAKGLASS\n") || !strings.Contains(root, ragib1+" keytree:ragib github:ragibkl") {
		t.Fatalf("root keys:\n%s", root)
	}
	if !strings.Contains(h.keys("anas"), anas1) {
		t.Fatalf("anas keys:\n%s", h.keys("anas"))
	}
	if _, err := os.Stat(filepath.Join(h.root, "var/lib/keytree/last-success")); err != nil {
		t.Fatal("no last-success after a clean run")
	}

	// New laptop key on GitHub shows up next run.
	h.gh.set("ragibkl", ragib1+"\n"+ragib2+"\n")
	if code, out := h.run("sync"); code != 0 {
		t.Fatalf("sync: %d\n%s", code, out)
	}
	if !strings.Contains(h.keys("root"), ragib2) {
		t.Fatal("new key not added")
	}

	// GitHub down for ragib: cached keys kept, exit 1.
	h.gh.setDown("ragibkl", true)
	if code, _ := h.run("sync"); code != 1 {
		t.Fatalf("want partial (1), got %d", code)
	}
	if !strings.Contains(h.keys("root"), ragib1) || !strings.Contains(h.keys("root"), ragib2) {
		t.Fatal("keys removed during outage")
	}

	// Outage with the cache wiped too: keys carried over from the file.
	os.RemoveAll(filepath.Join(h.root, "var/lib/keytree/cache"))
	if code, _ := h.run("sync"); code != 1 {
		t.Fatalf("want partial (1), got %d", code)
	}
	if !strings.Contains(h.keys("root"), ragib1) || !strings.Contains(h.keys("root"), ragib2) {
		t.Fatalf("keys removed with no cache:\n%s", h.keys("root"))
	}
	h.gh.setDown("ragibkl", false)

	// Invalid config: nothing changes, exit 2.
	before := h.keys("root")
	h.config(strings.Replace(baseConfig, "groups: [admins]", "groups: [admns]", 1))
	if code, out := h.run("sync"); code != 2 || !strings.Contains(out, "unknown group") {
		t.Fatalf("want config error (2), got %d\n%s", code, out)
	}
	if h.keys("root") != before {
		t.Fatal("invalid config changed keys")
	}
	h.config(baseConfig)

	// Unreachable config: nothing changes, exit 1.
	os.Rename(h.source, h.source+".bak")
	if code, _ := h.run("sync"); code != 1 {
		t.Fatalf("want 1 for missing config, got %d", code)
	}
	os.Rename(h.source+".bak", h.source)
	if h.keys("root") != before {
		t.Fatal("unreachable config changed keys")
	}

	// No servers entry matches: nothing changes, exit 2.
	if code, out := h.run("sync", "--name", "vmbr9-other"); code != 2 || !strings.Contains(out, "no servers entry matches") {
		t.Fatalf("want 2, got %d\n%s", code, out)
	}
	if h.keys("root") != before {
		t.Fatal("unmatched server changed keys")
	}

	// Removing a user from the config removes their keys.
	h.config(strings.Replace(baseConfig, "    anas:\n      users: [anas]\n", "", 1))
	if code, out := h.run("sync"); code != 0 {
		t.Fatalf("sync: %d\n%s", code, out)
	}
	if strings.Contains(h.keys("anas"), anas1) || strings.Contains(h.keys("anas"), authkeys.BeginMarker) {
		t.Fatalf("anas block not removed after the account lost its entry:\n%s", h.keys("anas"))
	}
	if h.keys("root") != before {
		t.Fatal("root changed when only anas was removed")
	}

	// Taking root away on purpose (empty grant) leaves only the hand key.
	h.config(strings.Replace(baseConfig, "      groups: [admins]\n", "      groups: []\n", 1))
	if code, out := h.run("sync"); code != 0 {
		t.Fatalf("sync: %d\n%s", code, out)
	}
	if h.keys("root") != "ssh-rsa BREAKGLASS\n" {
		t.Fatalf("root after revoke:\n%q", h.keys("root"))
	}
}

func TestSyncMissingAccount(t *testing.T) {
	h := newHost(t)
	h.gh.set("ragibkl", testKey(t)+"\n")
	h.gh.set("anasazmi571", testKey(t)+"\n")
	h.config(baseConfig + "    ghost:\n      users: [ragib]\n")
	code, out := h.run("sync")
	if code != 0 || !strings.Contains(out, `account "ghost" does not exist`) {
		t.Fatalf("got %d\n%s", code, out)
	}
}

func TestSyncDryRun(t *testing.T) {
	h := newHost(t)
	h.gh.set("ragibkl", testKey(t)+"\n")
	h.gh.set("anasazmi571", testKey(t)+"\n")
	h.config(baseConfig)
	code, out := h.run("sync", "--dry-run")
	if code != 0 || !strings.Contains(out, "root: would update (1 keys)") {
		t.Fatalf("got %d\n%s", code, out)
	}
	if h.keys("root") != "" {
		t.Fatal("dry run wrote authorized_keys")
	}
	if _, err := os.Stat(filepath.Join(h.root, "var/lib/keytree")); !os.IsNotExist(err) {
		t.Fatal("dry run created state dir")
	}
}

func TestSyncOverridesNeverTouchHost(t *testing.T) {
	// --config and --state-dir work outside --root too.
	h := newHost(t)
	h.gh.set("ragibkl", testKey(t)+"\n")
	h.gh.set("anasazmi571", testKey(t)+"\n")
	h.config(baseConfig)
	cfg := filepath.Join(t.TempDir(), "local.yaml")
	os.WriteFile(cfg, []byte("source: file://"+h.source+"\nname: vmbr1-coder\n"), 0o644)
	state := filepath.Join(t.TempDir(), "state")
	if code, out := h.run("sync", "--config", cfg, "--state-dir", state); code != 0 {
		t.Fatalf("%d\n%s", code, out)
	}
	if _, err := os.Stat(filepath.Join(state, "state.json")); err != nil {
		t.Fatal("state not written to --state-dir")
	}
}

func TestPlan(t *testing.T) {
	h := newHost(t)
	h.config(baseConfig)
	code, out := h.run("plan")
	want := "server vmbr1-coder\n  matched: vmbr1-*, vmbr1-coder\n  anas:\n    anas (github:anasazmi571)\n  root:\n    ragib (github:ragibkl)\n"
	if code != 0 || out != want {
		t.Fatalf("got %d\n%s\nwant\n%s", code, out, want)
	}
	code, out = h.run("plan", "--name", "nas", h.source)
	if code != 2 || !strings.Contains(out, "no servers entry matches") {
		t.Fatalf("got %d\n%s", code, out)
	}
}

func TestCheck(t *testing.T) {
	dir := t.TempDir()
	good, bad := filepath.Join(dir, "good.yaml"), filepath.Join(dir, "bad.yaml")
	os.WriteFile(good, []byte(baseConfig), 0o644)
	os.WriteFile(bad, []byte("version: 1\nusers:\n  a: {}\n"), 0o644)
	var out, errb bytes.Buffer
	if code := run([]string{"check", good}, &out, &errb); code != 0 {
		t.Fatalf("good: %d %s", code, errb.String())
	}
	if code := run([]string{"check", good, bad}, &out, &errb); code != 2 || !strings.Contains(errb.String(), "no key source") {
		t.Fatalf("bad: %d %s", code, errb.String())
	}
}

func TestLock(t *testing.T) {
	h := newHost(t)
	h.gh.set("ragibkl", testKey(t)+"\n")
	h.gh.set("anasazmi571", testKey(t)+"\n")
	h.config(baseConfig)
	state := filepath.Join(h.root, "var/lib/keytree")
	os.MkdirAll(state, 0o700)
	f, _ := os.OpenFile(filepath.Join(state, "lock"), os.O_CREATE|os.O_RDWR, 0o600)
	defer f.Close()
	if err := flockEx(f); err != nil {
		t.Skip("flock:", err)
	}
	if code, out := h.run("sync"); code != 1 || !strings.Contains(out, "another keytree sync is running") {
		t.Fatalf("got %d\n%s", code, out)
	}
}
