// Package authkeys edits keytree's managed block inside authorized_keys
// files, and writes those files safely as root.
package authkeys

import (
	"bytes"
	"errors"
	"fmt"
)

const (
	BeginMarker = "# BEGIN keytree (managed, do not edit)"
	EndMarker   = "# END keytree"
)

// ErrMarkers means the file's markers are broken (unmatched or repeated) and
// keytree refuses to guess which lines it owns.
var ErrMarkers = errors.New("broken keytree markers")

type span struct{ start, end int } // byte offsets of the block, end exclusive

// findBlock locates the managed block. ok is false when the file has no
// markers at all.
func findBlock(content []byte) (s span, ok bool, err error) {
	begin, end := -1, -1
	off := 0
	for off < len(content) {
		lineEnd := bytes.IndexByte(content[off:], '\n')
		next := len(content)
		if lineEnd >= 0 {
			next = off + lineEnd + 1
		}
		line := string(bytes.TrimRight(content[off:next], " \t\r\n"))
		switch line {
		case BeginMarker:
			if begin >= 0 {
				return span{}, false, fmt.Errorf("%w: more than one %q", ErrMarkers, BeginMarker)
			}
			begin = off
		case EndMarker:
			if begin < 0 {
				return span{}, false, fmt.Errorf("%w: %q without %q", ErrMarkers, EndMarker, BeginMarker)
			}
			if end >= 0 {
				return span{}, false, fmt.Errorf("%w: more than one %q", ErrMarkers, EndMarker)
			}
			end = next
		}
		off = next
	}
	switch {
	case begin < 0:
		return span{}, false, nil
	case end < 0:
		return span{}, false, fmt.Errorf("%w: %q without %q", ErrMarkers, BeginMarker, EndMarker)
	}
	return span{begin, end}, true, nil
}

// Render builds the managed block for lines. It returns nil for no lines:
// an empty set of keys means no block at all.
func Render(lines []string) []byte {
	if len(lines) == 0 {
		return nil
	}
	var b bytes.Buffer
	b.WriteString(BeginMarker + "\n")
	for _, l := range lines {
		b.WriteString(l)
		b.WriteByte('\n')
	}
	b.WriteString(EndMarker + "\n")
	return b.Bytes()
}

// Apply returns content with its managed block replaced by lines. Everything
// outside the block is kept byte for byte. With no lines the block is
// removed; with no existing block a new one is appended.
func Apply(content []byte, lines []string) ([]byte, error) {
	s, ok, err := findBlock(content)
	if err != nil {
		return nil, err
	}
	block := Render(lines)
	out := make([]byte, 0, len(content)+len(block)+1)
	if ok {
		out = append(out, content[:s.start]...)
		out = append(out, block...)
		out = append(out, content[s.end:]...)
		return out, nil
	}
	out = append(out, content...)
	if block != nil && len(out) > 0 && out[len(out)-1] != '\n' {
		out = append(out, '\n')
	}
	return append(out, block...), nil
}

// Lines returns the lines inside the managed block, or nil if there is none.
func Lines(content []byte) ([]string, error) {
	s, ok, err := findBlock(content)
	if err != nil || !ok {
		return nil, err
	}
	var lines []string
	for _, l := range bytes.Split(content[s.start:s.end], []byte("\n")) {
		t := string(bytes.TrimRight(l, " \t\r"))
		if t == "" || t == BeginMarker || t == EndMarker {
			continue
		}
		lines = append(lines, t)
	}
	return lines, nil
}
