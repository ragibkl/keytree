// Package config parses and validates keytree's two config files: the shared
// access file (keytree.yaml) and the per-server local config.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"maps"
	"path"
	"regexp"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
	"golang.org/x/crypto/ssh"
)

// Version is the only access-file version this build understands.
const Version = 1

// File is the shared access file (keytree.yaml).
type File struct {
	Version int                         `yaml:"version"`
	Users   map[string]User             `yaml:"users"`
	Groups  map[string][]string         `yaml:"groups"`
	Servers map[string]map[string]Grant `yaml:"servers"`
	// Revoked lists key fingerprints (SHA256:...) that are never written,
	// whatever source they come from.
	Revoked []string `yaml:"revoked"`
}

// IsRevoked reports whether an authorized_keys line holds a revoked key.
func (f *File) IsRevoked(line string) bool {
	if len(f.Revoked) == 0 {
		return false
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return false
	}
	return slices.Contains(f.Revoked, ssh.FingerprintSHA256(pub))
}

// User is a person and where their public keys come from.
type User struct {
	GitHub string   `yaml:"github"`
	GitLab string   `yaml:"gitlab"`
	Keys   []string `yaml:"keys"`
}

// Grant lists who may log in to one local account.
type Grant struct {
	Users  []string `yaml:"users"`
	Groups []string `yaml:"groups"`
}

var (
	nameRE    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	accountRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9._-]*$`)
	revokedRE = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`)
	githubRE  = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$`)
	gitlabRE  = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]*$`)
)

// ValidationError collects every problem found in a file.
type ValidationError struct {
	Problems []string
}

func (e *ValidationError) Error() string {
	return "invalid config:\n  - " + strings.Join(e.Problems, "\n  - ")
}

// Parse decodes and validates an access file. Unknown fields, unknown
// versions and dangling references are all errors.
func Parse(data []byte) (*File, error) {
	var f File
	if err := decodeStrict(data, &f); err != nil {
		return nil, &ValidationError{Problems: []string{err.Error()}}
	}
	if err := f.validate(); err != nil {
		return nil, err
	}
	return &f, nil
}

func decodeStrict(data []byte, out any) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(out); err != nil {
		if errors.Is(err, io.EOF) {
			return errors.New("file is empty")
		}
		return err
	}
	return nil
}

func (f *File) validate() error {
	var p []string
	add := func(format string, args ...any) { p = append(p, fmt.Sprintf(format, args...)) }

	switch f.Version {
	case 0:
		add("version is missing (expected %d)", Version)
	case Version:
	default:
		add("version %d is not supported (expected %d)", f.Version, Version)
	}

	for i, fp := range f.Revoked {
		if !revokedRE.MatchString(fp) {
			add("revoked[%d]: %q is not a key fingerprint (expected SHA256:..., as printed by ssh-keygen -l)", i, fp)
		}
	}

	for _, name := range slices.Sorted(maps.Keys(f.Users)) {
		u := f.Users[name]
		if !nameRE.MatchString(name) {
			add("users: invalid name %q", name)
		}
		if u.GitHub == "" && u.GitLab == "" && len(u.Keys) == 0 {
			add("users.%s: no key source (github, gitlab or keys)", name)
		}
		if u.GitHub != "" && !githubRE.MatchString(u.GitHub) {
			add("users.%s: invalid github username %q", name, u.GitHub)
		}
		if u.GitLab != "" && !gitlabRE.MatchString(u.GitLab) {
			add("users.%s: invalid gitlab username %q", name, u.GitLab)
		}
		for i, k := range u.Keys {
			if err := checkLiteralKey(k); err != nil {
				add("users.%s.keys[%d]: %v", name, i, err)
			}
		}
	}

	for _, name := range slices.Sorted(maps.Keys(f.Groups)) {
		if !nameRE.MatchString(name) {
			add("groups: invalid name %q", name)
		}
		for _, m := range f.Groups[name] {
			if _, ok := f.Users[m]; !ok {
				add("groups.%s: unknown user %q", name, m)
			}
		}
	}

	for _, pattern := range slices.Sorted(maps.Keys(f.Servers)) {
		if pattern == "" {
			add("servers: empty server name")
		} else if _, err := path.Match(pattern, ""); err != nil {
			add("servers: invalid pattern %q", pattern)
		}
		accounts := f.Servers[pattern]
		for _, account := range slices.Sorted(maps.Keys(accounts)) {
			if !accountRE.MatchString(account) {
				add("servers.%s: invalid account name %q", pattern, account)
			}
			g := accounts[account]
			for _, u := range g.Users {
				if _, ok := f.Users[u]; !ok {
					add("servers.%s.%s: unknown user %q", pattern, account, u)
				}
			}
			for _, gr := range g.Groups {
				if _, ok := f.Groups[gr]; !ok {
					add("servers.%s.%s: unknown group %q", pattern, account, gr)
				}
			}
		}
	}

	if len(p) > 0 {
		return &ValidationError{Problems: p}
	}
	return nil
}

// checkLiteralKey accepts exactly one public key with no options.
func checkLiteralKey(line string) error {
	if strings.ContainsAny(line, "\r\n") {
		return errors.New("must be a single line")
	}
	_, _, options, rest, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return errors.New("not a valid SSH public key")
	}
	if len(options) > 0 {
		return errors.New("key options (from=, command=, ...) are not supported")
	}
	if len(bytes.TrimSpace(rest)) > 0 {
		return errors.New("must be a single key")
	}
	return nil
}

// Local is the per-server config (/etc/keytree/config.yaml).
type Local struct {
	Source string `yaml:"source"`
	Name   string `yaml:"name"`
}

// ParseLocal decodes and validates a local config.
func ParseLocal(data []byte) (*Local, error) {
	var l Local
	if err := decodeStrict(data, &l); err != nil {
		return nil, fmt.Errorf("local config: %w", err)
	}
	if l.Source == "" {
		return nil, errors.New("local config: source is required")
	}
	if err := CheckSource(l.Source); err != nil {
		return nil, fmt.Errorf("local config: %w", err)
	}
	return &l, nil
}

// CheckSource accepts https://, http:// and file:// URLs.
func CheckSource(s string) error {
	for _, scheme := range []string{"https://", "http://", "file://"} {
		if strings.HasPrefix(s, scheme) {
			return nil
		}
	}
	return fmt.Errorf("source %q must be an https:// or file:// URL", s)
}
