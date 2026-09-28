package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func testKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sp, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sp)))
}

const valid = `
version: 1
users:
  ragib:
    github: ragibkl
  anas:
    github: anasazmi571
    gitlab: anas
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
    root:
      users: [anas]
  nas:
    backup:
      groups: []
`

func TestParseValid(t *testing.T) {
	f, err := Parse([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	if f.Users["anas"].GitLab != "anas" {
		t.Errorf("gitlab not parsed: %+v", f.Users["anas"])
	}
}

func TestParseLiteralKeys(t *testing.T) {
	k := testKey(t)
	src := "version: 1\nusers:\n  bot:\n    keys:\n      - " + k + " bot@nas\n"
	if _, err := Parse([]byte(src)); err != nil {
		t.Fatal(err)
	}
}

func TestParseErrors(t *testing.T) {
	k := testKey(t)
	cases := map[string]struct {
		src  string
		want string
	}{
		"empty":           {"", "file is empty"},
		"no version":      {"users: {}\n", "version is missing"},
		"future version":  {"version: 2\n", "version 2 is not supported"},
		"unknown field":   {"version: 1\ngrops: {}\n", "grops"},
		"unknown nested":  {"version: 1\nusers:\n  a:\n    githbu: a\n", "githbu"},
		"duplicate key":   {"version: 1\nusers:\n  a: {github: a}\n  a: {github: b}\n", "already defined"},
		"no source":       {"version: 1\nusers:\n  a: {}\n", "users.a: no key source"},
		"bad github":      {"version: 1\nusers:\n  a: {github: ../evil}\n", "invalid github username"},
		"bad gitlab":      {"version: 1\nusers:\n  a: {gitlab: a/b}\n", "invalid gitlab username"},
		"bad key":         {"version: 1\nusers:\n  a:\n    keys: [not-a-key]\n", "not a valid SSH public key"},
		"key options":     {"version: 1\nusers:\n  a:\n    keys: ['from=\"10.0.0.1\" " + k + "']\n", "options"},
		"two keys":        {"version: 1\nusers:\n  a:\n    keys: [\"" + k + "\\n" + k + "\"]\n", "single line"},
		"group unknown":   {"version: 1\nusers:\n  a: {github: a}\ngroups:\n  g: [b]\n", `groups.g: unknown user "b"`},
		"server user":     {"version: 1\nusers:\n  a: {github: a}\nservers:\n  h:\n    root:\n      users: [b]\n", `servers.h.root: unknown user "b"`},
		"server group":    {"version: 1\nusers:\n  a: {github: a}\nservers:\n  h:\n    root:\n      groups: [g]\n", `servers.h.root: unknown group "g"`},
		"bad pattern":     {"version: 1\nservers:\n  \"vm[\":\n    root: {}\n", "invalid pattern"},
		"bad account":     {"version: 1\nservers:\n  h:\n    \"-rf\": {}\n", "invalid account name"},
		"unknown grant":   {"version: 1\nservers:\n  h:\n    root:\n      user: [a]\n", "field user not found"},
		"invalid user id": {"version: 1\nusers:\n  \"a b\": {github: a}\n", "invalid name"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(tc.src))
			if err == nil {
				t.Fatalf("expected error containing %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err, tc.want)
			}
		})
	}
}

func TestParseReportsAllProblems(t *testing.T) {
	src := "version: 1\nusers:\n  a: {}\n  b: {github: ../x}\ngroups:\n  g: [c]\n"
	_, err := Parse([]byte(src))
	ve, ok := err.(*ValidationError)
	if !ok {
		t.Fatalf("want *ValidationError, got %T %v", err, err)
	}
	if len(ve.Problems) != 3 {
		t.Fatalf("want 3 problems, got %d: %v", len(ve.Problems), ve.Problems)
	}
}

func TestResolve(t *testing.T) {
	f, err := Parse([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]Access{
		"vmbr1-alpine-k3s": {
			Matched:  []string{"vmbr1-*"},
			Accounts: map[string][]string{"root": {"ragib"}},
		},
		// Every matching entry applies; lists for the same account combine.
		"vmbr1-ubuntu-coder": {
			Matched:  []string{"vmbr1-*", "vmbr1-ubuntu-coder"},
			Accounts: map[string][]string{"root": {"anas", "ragib"}, "anas": {"anas"}},
		},
		// An account with nobody is kept: it means "remove access".
		"nas": {
			Matched:  []string{"nas"},
			Accounts: map[string][]string{"backup": {}},
		},
		"vmbr2-x": {Accounts: map[string][]string{}},
	}
	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			got := f.Resolve(name)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("got %+v\nwant %+v", got, want)
			}
		})
	}
}

func TestParseLocal(t *testing.T) {
	l, err := ParseLocal([]byte("source: https://example.com/keytree.yaml\nname: nas\n"))
	if err != nil {
		t.Fatal(err)
	}
	if l.Name != "nas" {
		t.Fatalf("name = %q", l.Name)
	}
	for src, want := range map[string]string{
		"name: nas\n":                      "source is required",
		"source: ftp://x/y\n":              "must be an https://",
		"source: https://x\nlabels: [a]\n": "labels",
	} {
		if _, err := ParseLocal([]byte(src)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: got %v, want %q", src, err, want)
		}
	}
}
