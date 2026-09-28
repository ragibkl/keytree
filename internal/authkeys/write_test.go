package authkeys

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

var testLines = []string{"ssh-ed25519 AAAA1 keytree:ragib github:ragibkl"}

// newAccount makes a home directory owned by the current user.
func newAccount(t *testing.T) Account {
	t.Helper()
	home := filepath.Join(t.TempDir(), "home")
	if err := os.Mkdir(home, 0o755); err != nil {
		t.Fatal(err)
	}
	return Account{Name: "tester", UID: os.Getuid(), GID: os.Getgid(), Home: home}
}

func keysPath(a Account) string { return filepath.Join(a.Home, ".ssh", "authorized_keys") }

func mkSSH(t *testing.T, a Account) {
	t.Helper()
	if err := os.Mkdir(filepath.Join(a.Home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
}

func writeFile(t *testing.T, p, content string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func mode(t *testing.T, p string) os.FileMode {
	t.Helper()
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

func noTemps(t *testing.T, a Account) {
	t.Helper()
	entries, _ := os.ReadDir(filepath.Join(a.Home, ".ssh"))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), tmpPref) {
			t.Fatalf("temp file left behind: %s", e.Name())
		}
	}
}

func TestUpdateCreatesSSHDir(t *testing.T) {
	a := newAccount(t)
	changed, err := Update(a, testLines, false)
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	if m := mode(t, filepath.Join(a.Home, ".ssh")); m != 0o700 {
		t.Errorf(".ssh mode %#o", m)
	}
	if m := mode(t, keysPath(a)); m != 0o600 {
		t.Errorf("authorized_keys mode %#o", m)
	}
	if got := readFile(t, keysPath(a)); got != string(Render(testLines)) {
		t.Errorf("content %q", got)
	}
	noTemps(t, a)
}

func TestUpdateNoKeysNoSSHDir(t *testing.T) {
	a := newAccount(t)
	changed, err := Update(a, nil, false)
	if err != nil || changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	if _, err := os.Stat(filepath.Join(a.Home, ".ssh")); !os.IsNotExist(err) {
		t.Fatal(".ssh was created for no keys")
	}
}

func TestUpdateKeepsHandKeysAndFixesMode(t *testing.T) {
	a := newAccount(t)
	mkSSH(t, a)
	hand := "ssh-rsa BREAKGLASS me@laptop\n"
	writeFile(t, keysPath(a), hand, 0o644)

	if _, err := Update(a, testLines, false); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, keysPath(a)); got != hand+string(Render(testLines)) {
		t.Fatalf("content %q", got)
	}
	if m := mode(t, keysPath(a)); m != 0o600 {
		t.Errorf("mode %#o", m)
	}
	if _, err := Update(a, nil, false); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, keysPath(a)); got != hand {
		t.Fatalf("after removal %q", got)
	}
}

func TestUpdateUnchangedNotRewritten(t *testing.T) {
	a := newAccount(t)
	if _, err := Update(a, testLines, false); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(keysPath(a))
	changed, err := Update(a, testLines, false)
	if err != nil || changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	after, _ := os.Stat(keysPath(a))
	if !os.SameFile(before, after) {
		t.Fatal("file was replaced although nothing changed")
	}
}

func TestUpdateDryRun(t *testing.T) {
	a := newAccount(t)
	changed, err := Update(a, testLines, true)
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	if _, err := os.Stat(filepath.Join(a.Home, ".ssh")); !os.IsNotExist(err) {
		t.Fatal("dry run created .ssh")
	}
	mkSSH(t, a)
	writeFile(t, keysPath(a), "ssh-rsa HAND\n", 0o600)
	if changed, err := Update(a, testLines, true); err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	if got := readFile(t, keysPath(a)); got != "ssh-rsa HAND\n" {
		t.Fatalf("dry run wrote %q", got)
	}
}

// Every refusal must leave the target (and everything outside ~/.ssh) as is.
func TestUpdateRefuses(t *testing.T) {
	cases := map[string]func(t *testing.T, a Account, outside string){
		"authorized_keys symlink": func(t *testing.T, a Account, outside string) {
			mkSSH(t, a)
			os.Symlink(outside, keysPath(a))
		},
		"authorized_keys dangling symlink": func(t *testing.T, a Account, outside string) {
			mkSSH(t, a)
			os.Symlink(outside+".missing", keysPath(a))
		},
		".ssh symlink": func(t *testing.T, a Account, outside string) {
			dir := filepath.Dir(outside)
			os.Symlink(dir, filepath.Join(a.Home, ".ssh"))
			os.Rename(outside, filepath.Join(dir, "authorized_keys"))
			os.Symlink(filepath.Join(dir, "authorized_keys"), outside)
		},
		".ssh is a file": func(t *testing.T, a Account, outside string) {
			writeFile(t, filepath.Join(a.Home, ".ssh"), "x", 0o600)
		},
		".ssh world-writable": func(t *testing.T, a Account, outside string) {
			mkSSH(t, a)
			os.Chmod(filepath.Join(a.Home, ".ssh"), 0o777)
		},
		".ssh group-writable": func(t *testing.T, a Account, outside string) {
			mkSSH(t, a)
			os.Chmod(filepath.Join(a.Home, ".ssh"), 0o770)
		},
		"authorized_keys is a directory": func(t *testing.T, a Account, outside string) {
			mkSSH(t, a)
			os.Mkdir(keysPath(a), 0o700)
		},
		"authorized_keys is a fifo": func(t *testing.T, a Account, outside string) {
			mkSSH(t, a)
			if err := syscall.Mkfifo(keysPath(a), 0o600); err != nil {
				t.Skip("mkfifo:", err)
			}
		},
		"authorized_keys hard link": func(t *testing.T, a Account, outside string) {
			mkSSH(t, a)
			if err := os.Link(outside, keysPath(a)); err != nil {
				t.Skip("link:", err)
			}
		},
		"broken markers": func(t *testing.T, a Account, outside string) {
			mkSSH(t, a)
			writeFile(t, keysPath(a), "ssh-rsa A\n"+BeginMarker+"\n", 0o600)
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			a := newAccount(t)
			outside := filepath.Join(t.TempDir(), "shadow")
			writeFile(t, outside, "root:SECRET:1::::::\n", 0o600)
			setup(t, a, outside)
			var before string
			if fi, err := os.Lstat(keysPath(a)); err == nil && fi.Mode().IsRegular() {
				before = readFile(t, keysPath(a))
			}

			if _, err := Update(a, testLines, false); err == nil {
				t.Fatal("expected refusal")
			}
			if got := readFile(t, outside); got != "root:SECRET:1::::::\n" {
				t.Fatalf("file outside ~/.ssh changed: %q", got)
			}
			if fi, err := os.Lstat(keysPath(a)); err == nil && fi.Mode().IsRegular() {
				if got := readFile(t, keysPath(a)); got != before {
					t.Fatalf("authorized_keys changed: %q", got)
				}
			}
		})
	}
}

func TestUpdateTooLarge(t *testing.T) {
	a := newAccount(t)
	mkSSH(t, a)
	writeFile(t, keysPath(a), strings.Repeat("x", MaxFileSize+1), 0o600)
	if _, err := Update(a, testLines, false); err == nil {
		t.Fatal("expected refusal")
	}
}

func TestUpdateMissingHome(t *testing.T) {
	a := newAccount(t)
	a.Home = filepath.Join(a.Home, "nope")
	if _, err := Update(a, testLines, false); err == nil {
		t.Fatal("expected error")
	}
}

// A crash between write and rename leaves the old file intact, and the next
// run cleans up the temp file.
func TestUpdateCrashBeforeRename(t *testing.T) {
	a := newAccount(t)
	if _, err := Update(a, testLines, false); err != nil {
		t.Fatal(err)
	}
	orig := readFile(t, keysPath(a))

	crash := errors.New("simulated crash")
	testHookBeforeRename = func() error { return crash }
	_, err := Update(a, append(testLines, "ssh-ed25519 NEW x"), false)
	testHookBeforeRename = nil
	if !errors.Is(err, crash) {
		t.Fatalf("err = %v", err)
	}
	if got := readFile(t, keysPath(a)); got != orig {
		t.Fatalf("file changed after crash: %q", got)
	}
	noTemps(t, a)

	// A real crash can't clean up after itself; the next run must.
	stale := filepath.Join(a.Home, ".ssh", tmpPref+"deadbeef")
	writeFile(t, stale, "partial", 0o600)
	if _, err := Update(a, append(testLines, "ssh-ed25519 NEW x"), false); err != nil {
		t.Fatal(err)
	}
	noTemps(t, a)
}

func TestRead(t *testing.T) {
	a := newAccount(t)
	if got, err := Read(a); err != nil || got != nil {
		t.Fatalf("no .ssh: %q %v", got, err)
	}
	if _, err := Update(a, testLines, false); err != nil {
		t.Fatal(err)
	}
	got, err := Read(a)
	if err != nil || strings.Join(got, "\n") != strings.Join(testLines, "\n") {
		t.Fatalf("got %q %v", got, err)
	}
}

// Root-only: files are created with the account's owner, and files owned by
// someone else are refused.
func TestUpdateOwnershipAsRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root (run in the e2e container)")
	}
	const uid, gid = 4242, 4242
	a := newAccount(t)
	os.Chown(a.Home, uid, gid)
	a.UID, a.GID = uid, gid

	if _, err := Update(a, testLines, false); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{filepath.Join(a.Home, ".ssh"), keysPath(a)} {
		fi, _ := os.Lstat(p)
		st := fi.Sys().(*syscall.Stat_t)
		if st.Uid != uid || st.Gid != gid {
			t.Errorf("%s owned by %d:%d", p, st.Uid, st.Gid)
		}
	}

	// authorized_keys owned by root inside the user's .ssh: refuse.
	os.Chown(keysPath(a), 0, 0)
	if _, err := Update(a, append(testLines, "ssh-ed25519 NEW x"), false); err == nil {
		t.Fatal("expected refusal for root-owned authorized_keys")
	}
	// .ssh owned by someone else: refuse.
	os.Chown(keysPath(a), uid, gid)
	os.Chown(filepath.Join(a.Home, ".ssh"), 4343, 4343)
	if _, err := Update(a, append(testLines, "ssh-ed25519 NEW x"), false); err == nil {
		t.Fatal("expected refusal for foreign .ssh")
	}
}
