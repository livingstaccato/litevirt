package main

import (
	"io"
	"strings"
	"testing"
)

// I2 of re-review 4: a forced commit of an overlay already in the disk goes
// ahead only with --overwrite-newer-writes or a typed "yes" on a terminal —
// never on a pipe, never on anything but "yes".
//
// Mutation "any answer confirms" — red.
func TestConfirmOverwriteNewer_OnlyATypedYesOnATerminal(t *testing.T) {
	prev := stdinIsTerminal
	defer func() { stdinIsTerminal = prev }()
	stdinIsTerminal = func() bool { return false }
	if confirmOverwriteNewer(strings.NewReader("yes\n"), io.Discard) {
		t.Error("a non-terminal stdin confirmed the overwrite")
	}
	stdinIsTerminal = func() bool { return true }
	for in, want := range map[string]bool{"yes\n": true, "y\n": false, "\n": false, "no\n": false} {
		if got := confirmOverwriteNewer(strings.NewReader(in), io.Discard); got != want {
			t.Errorf("answer %q confirmed = %v, want %v", in, got, want)
		}
	}
}
