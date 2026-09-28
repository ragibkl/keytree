package passwd

import (
	"reflect"
	"testing"
)

func TestParse(t *testing.T) {
	data := []byte(`# comment
root:x:0:0:root:/root:/bin/sh

ragib:x:1000:1000:Ragib,,,:/home/ragib:/bin/bash
ragib:x:2000:2000::/elsewhere:/bin/sh
broken:x:abc:0::/home/broken:/bin/sh
short:x:1:1
relhome:x:5:5::home/rel:/bin/sh
`)
	got, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]Entry{
		"root":  {Name: "root", UID: 0, GID: 0, Home: "/root"},
		"ragib": {Name: "ragib", UID: 1000, GID: 1000, Home: "/home/ragib"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v", got)
	}
}
