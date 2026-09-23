package ui

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestEveryInProcessUIWriteIsAccountable is a source-level guard.
//
// The UI's write handlers reach the replicated DB in-process, so a mutation
// made here passes through nothing that authorizes it and nothing that audits
// it. The audit half is the worse of the two: `lv audit verify` then reports a
// clean, unbroken, SIGNED chain in which nobody changed the cluster firewall or
// deleted the security-group rules isolating a compromised VM. The log reads as
// proof that nothing happened.
//
// Most of these writes now go through their gRPC twins, which authorize and
// audit. Security groups have no twin, so they call s.authorize and
// s.auditUIWrite explicitly. This test exists so a NEW handler cannot quietly
// join the in-process set without doing one or the other — the kind of gap
// that is invisible in review because the write itself looks ordinary.
func TestEveryInProcessUIWriteIsAccountable(t *testing.T) {
	// corrosion mutators. Reads (List*/Get*) are fine in-process.
	writeRe := regexp.MustCompile(`corrosion\.(Insert|Delete|Update|Upsert|Set)[A-Za-z]*\(`)
	funcRe := regexp.MustCompile(`\nfunc \(s \*Server\) (\w+)\(`)

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
		text := string(src)
		locs := funcRe.FindAllStringSubmatchIndex(text, -1)
		for i, loc := range locs {
			end := len(text)
			if i+1 < len(locs) {
				end = locs[i+1][0]
			}
			body := text[loc[0]:end]
			fname := text[loc[2]:loc[3]]
			if fname == "auditUIWrite" || !writeRe.MatchString(body) {
				continue
			}
			if !strings.Contains(body, "s.auditUIWrite(") {
				t.Errorf("%s: %s writes replicated state in-process without calling "+
					"s.auditUIWrite; route it through its gRPC twin (which authorizes and "+
					"audits) or audit it explicitly. An unaudited mutation makes the signed "+
					"audit chain read as proof that nothing changed", name, fname)
			}
			if !strings.Contains(body, "s.authorize(") {
				t.Errorf("%s: %s writes replicated state in-process without calling "+
					"s.authorize; the session gate in front cannot see token scopes or RBAC "+
					"bindings", name, fname)
			}
		}
	}
}
