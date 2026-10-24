package storage

import (
	"strings"
	"testing"
)

// (re-review rr1 Nit 5) Hardening drops the options that would undo it in
// any case: SUID or Exec never reaches mount(8).
//
// Mutation: match the options case-sensitively in hardenNFSOptions — red.
func TestHardenNFSOptions_DropsCaseVariants(t *testing.T) {
	got := hardenNFSOptions("vers=4.2,SUID,Exec")
	for _, tok := range strings.Split(got, ",") {
		switch tok {
		case "SUID", "Exec":
			t.Errorf("hardenNFSOptions kept %q: %q", tok, got)
		}
	}
}
