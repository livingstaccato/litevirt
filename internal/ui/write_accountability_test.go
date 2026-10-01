package ui

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestNoUIHandlerWritesReplicatedStateInProcess is a source-level guard.
//
// The UI's handlers hold a host-local Corrosion handle for reads. A mutation
// made through it passes through nothing that authorizes it and nothing that
// audits it. The audit half is the worse of the two: `lv audit verify` then
// reports a clean, unbroken, SIGNED chain in which nobody changed the cluster
// firewall or deleted the security-group rules isolating a compromised VM. The
// log reads as proof that nothing happened.
//
// Every UI write now goes through its gRPC twin with the session's bearer, so
// the daemon authorizes and audits it exactly as it does for `lv`. The
// security-group pages, among the last in-process writers, show why that is the
// only safe shape: they re-implemented the check with a different verb than their RPCs
// (a NetworkAdmin could use `lv sg` and not the page), and the in-process
// authorizer they called could not even see the session, so it authorized
// every caller as the bearerless admin (colonelpanik/litevirt#182).
//
// This test exists so a NEW handler cannot quietly start writing in-process —
// the kind of gap that is invisible in review because the write itself looks
// ordinary.
func TestNoUIHandlerWritesReplicatedStateInProcess(t *testing.T) {
	// Any corrosion call that is not a read. An allowlist of read prefixes, not
	// a denylist of write verbs: the denylist this replaced (Insert/Delete/
	// Update/Upsert/Set) never saw CreateResourceMapping, AddMappingDevice or
	// RemoveMappingDevice, and those three sat in the resource-mapping pages
	// with no authorization at all.
	callRe := regexp.MustCompile(`corrosion\.([A-Z][A-Za-z0-9]*)\(`)
	readRe := regexp.MustCompile(`^(List|Get)`)

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(filepath.Clean(name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		for i, line := range strings.Split(string(src), "\n") {
			for _, m := range callRe.FindAllStringSubmatch(line, -1) {
				if readRe.MatchString(m[1]) {
					continue
				}
				t.Errorf("%s:%d: corrosion.%s is not a read, and the UI must not write replicated "+
					"state in-process; call its gRPC twin with s.uiBearerCtx(r) instead, so the daemon "+
					"authorizes and audits it the way it does for the CLI. An in-process write has "+
					"neither, and an unaudited mutation makes the signed audit chain read as proof "+
					"that nothing changed", name, i+1, m[1])
			}
		}
	}
}
