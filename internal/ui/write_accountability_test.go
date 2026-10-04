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

// uiInProcessReads is every in-process Corrosion read a UI handler may make,
// keyed by "file:corrosion.Func", each with the reason it is not an RPC call.
//
// A read belongs here only when NO RPC serves the same data. Where one does,
// the RPC is where the authorization lives — a RequireRole that refuses a scoped
// token, a RequirePerm at a path, a per-caller filter — and a page reading the
// table in-process skips all of it for whatever session it serves.
var uiInProcessReads = map[string]string{
	"handle_security_groups.go:corrosion.ListSecurityGroups": "no RPC lists security groups; `lv sg ls` " +
		"reads this table in-process too. A list RPC would move this page onto it",
	"handle_security_groups.go:corrosion.ListSGRules": "no RPC lists security-group rules; `lv sg rule-ls` " +
		"reads this table in-process too",
	"handle_vms.go:corrosion.ListSecurityGroups": "the Add-NIC modal's security-group names; no RPC lists " +
		"security groups (see handle_security_groups.go)",
}

// TestNoUIHandlerReadsReplicatedStateAroundItsRPC is the read half of the guard
// above. /rbac read role_bindings in-process and showed every binding in the
// cluster to any session, where ListRoleBindings shows a non-admin only their
// own; /resource-mappings, /firewall and the VM hardware modals skipped checks
// their RPCs make. A read through the session's bearer gets the daemon's answer
// for that caller; an in-process read gets the whole table.
func TestNoUIHandlerReadsReplicatedStateAroundItsRPC(t *testing.T) {
	callRe := regexp.MustCompile(`corrosion\.([A-Z][A-Za-z0-9]*)\(`)
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	seen := map[string]bool{}
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
			if strings.HasPrefix(strings.TrimSpace(line), "//") {
				continue
			}
			for _, m := range callRe.FindAllStringSubmatch(line, -1) {
				key := name + ":corrosion." + m[1]
				if _, ok := uiInProcessReads[key]; ok {
					seen[key] = true
					continue
				}
				t.Errorf("%s:%d: corrosion.%s reads replicated state in-process. Call the RPC that serves "+
					"it with s.uiBearerCtx(r), so the daemon applies its authorization and per-caller "+
					"filtering for this session; only a read with no RPC twin may be allowlisted in "+
					"uiInProcessReads, with the reason", name, i+1, m[1])
			}
		}
	}
	for key := range uiInProcessReads {
		if !seen[key] {
			t.Errorf("uiInProcessReads allows %s, which no handler calls any more; remove the entry", key)
		}
	}
}
