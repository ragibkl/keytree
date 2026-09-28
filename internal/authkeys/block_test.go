package authkeys

import (
	"bytes"
	"errors"
	"math/rand/v2"
	"strings"
	"testing"
)

const (
	b = BeginMarker + "\n"
	e = EndMarker + "\n"
)

func TestApply(t *testing.T) {
	keys := []string{"ssh-ed25519 AAAA1 keytree:ragib github:ragibkl", "ssh-ed25519 AAAA2 keytree:anas github:anasazmi571"}
	block := b + keys[0] + "\n" + keys[1] + "\n" + e

	cases := []struct {
		name  string
		in    string
		lines []string
		want  string
	}{
		{"no file", "", keys, block},
		{"no file, no keys", "", nil, ""},
		{"hand keys, no markers", "ssh-rsa HAND\n", keys, "ssh-rsa HAND\n" + block},
		{"missing trailing newline", "ssh-rsa HAND", keys, "ssh-rsa HAND\n" + block},
		{"missing trailing newline, no keys", "ssh-rsa HAND", nil, "ssh-rsa HAND"},
		{"replace block", b + "old\n" + e, keys, block},
		{"block between hand keys",
			"ssh-rsa A\n" + b + "old\n" + e + "ssh-rsa B\n", keys,
			"ssh-rsa A\n" + block + "ssh-rsa B\n"},
		{"remove block", "ssh-rsa A\n" + b + "old\n" + e + "ssh-rsa B\n", nil, "ssh-rsa A\nssh-rsa B\n"},
		{"remove only block", b + "old\n" + e, nil, ""},
		{"empty block", "ssh-rsa A\n" + b + e, keys, "ssh-rsa A\n" + block},
		{"crlf outside kept",
			"ssh-rsa A\r\n" + b + "old\n" + e + "ssh-rsa B\r\n", keys,
			"ssh-rsa A\r\n" + block + "ssh-rsa B\r\n"},
		{"crlf markers recognised",
			"ssh-rsa A\r\n" + BeginMarker + "\r\nold\r\n" + EndMarker + "\r\n", keys,
			"ssh-rsa A\r\n" + block},
		{"end marker without newline", "ssh-rsa A\n" + b + "old\n" + EndMarker, keys, "ssh-rsa A\n" + block},
		{"comments and options kept",
			"# my note\ncommand=\"x\" ssh-rsa A\n\n", keys,
			"# my note\ncommand=\"x\" ssh-rsa A\n\n" + block},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Apply([]byte(tc.in), tc.lines)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.want {
				t.Fatalf("got:\n%q\nwant:\n%q", got, tc.want)
			}
		})
	}
}

func TestApplyBrokenMarkers(t *testing.T) {
	cases := map[string]string{
		"begin without end": "ssh-rsa A\n" + b + "old\n",
		"end without begin": "ssh-rsa A\n" + e,
		"end before begin":  e + b,
		"two blocks":        b + e + b + e,
		"two begins":        b + b + e,
		"two ends":          b + e + e,
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Apply([]byte(in), []string{"ssh-ed25519 X"})
			if !errors.Is(err, ErrMarkers) {
				t.Fatalf("want ErrMarkers, got %v", err)
			}
		})
	}
}

func TestLines(t *testing.T) {
	got, err := Lines([]byte("ssh-rsa A\n" + b + "k1 c\r\n\nk2 c\n" + e))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, "|") != "k1 c|k2 c" {
		t.Fatalf("got %q", got)
	}
	if got, _ := Lines([]byte("ssh-rsa A\n")); got != nil {
		t.Fatalf("no block: got %q", got)
	}
}

// randomContent builds authorized_keys-like content from hand-written lines,
// comments, blank lines and CRLF endings, never containing markers.
func randomContent(r *rand.Rand) []byte {
	pieces := []string{"ssh-rsa AAAA hand", "# comment", "", "  ", "command=\"x\" ssh-ed25519 B", "ssh-ed25519 C\r", "#BEGIN keytree", "# END keytreex"}
	var buf bytes.Buffer
	n := r.IntN(8)
	for i := 0; i < n; i++ {
		buf.WriteString(pieces[r.IntN(len(pieces))])
		buf.WriteByte('\n')
	}
	if n > 0 && r.IntN(4) == 0 {
		buf.Truncate(buf.Len() - 1) // no trailing newline
	}
	return buf.Bytes()
}

func randomLines(r *rand.Rand) []string {
	var lines []string
	for i := r.IntN(5); i > 0; i-- {
		lines = append(lines, "ssh-ed25519 K"+string(rune('a'+r.IntN(26)))+" keytree:u github:u")
	}
	return lines
}

func TestApplyProperties(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	for i := 0; i < 5000; i++ {
		orig := randomContent(r)
		lines := randomLines(r)
		other := randomLines(r)

		once, err := Apply(orig, lines)
		if err != nil {
			t.Fatalf("apply to %q: %v", orig, err)
		}
		// Idempotent.
		twice, err := Apply(once, lines)
		if err != nil || !bytes.Equal(once, twice) {
			t.Fatalf("not idempotent for %q / %q:\n%q\n%q", orig, lines, once, twice)
		}
		// The block holds exactly the requested lines.
		got, _ := Lines(once)
		if strings.Join(got, "\n") != strings.Join(lines, "\n") {
			t.Fatalf("Lines = %q, want %q", got, lines)
		}
		// Replacing the block only touches the block. (Skipped when once has
		// no block and no trailing newline: adding a block then adds one.)
		swapped, err := Apply(once, other)
		if err != nil {
			t.Fatal(err)
		}
		back, _ := Apply(swapped, lines)
		noNewline := len(once) > 0 && once[len(once)-1] != '\n'
		if !noNewline && !bytes.Equal(back, once) {
			t.Fatalf("swap and back changed content:\n%q\n%q", once, back)
		}
		// Removing the block restores the original, except a newline added
		// to a file that had none.
		removed, err := Apply(once, nil)
		if err != nil {
			t.Fatal(err)
		}
		want := orig
		if len(lines) > 0 && len(orig) > 0 && orig[len(orig)-1] != '\n' {
			want = append(append([]byte{}, orig...), '\n')
		}
		if !bytes.Equal(removed, want) {
			t.Fatalf("remove did not restore:\norig %q\ngot  %q", orig, removed)
		}
	}
}
