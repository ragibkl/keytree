// Package passwd reads local accounts straight from an /etc/passwd file, so
// tests can point keytree at a fake one with --root.
package passwd

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Entry is one account.
type Entry struct {
	Name string
	UID  int
	GID  int
	Home string
}

// Load parses a passwd file into a name -> entry map. Malformed lines are
// skipped; the first entry for a name wins, as with getpwnam.
func Load(path string) (map[string]Entry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// Parse parses passwd-format data.
func Parse(data []byte) (map[string]Entry, error) {
	out := map[string]Entry{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, ":")
		if len(f) != 7 {
			continue
		}
		uid, err1 := strconv.Atoi(f[2])
		gid, err2 := strconv.Atoi(f[3])
		if err1 != nil || err2 != nil || f[0] == "" || !strings.HasPrefix(f[5], "/") {
			continue
		}
		if _, dup := out[f[0]]; dup {
			continue
		}
		out[f[0]] = Entry{Name: f[0], UID: uid, GID: gid, Home: f[5]}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read passwd: %w", err)
	}
	return out, nil
}
