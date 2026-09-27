package compose

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// aliasBomb is a compose file (about 4.7 KB for k=300) whose aliases expand to
// k³ nodes: k vms, each an alias of a VM with k NICs, each an alias of a NIC
// whose trunk is an alias of a k-item list.
func aliasBomb(k int) string {
	var b strings.Builder
	b.WriteString("name: s\nx-t: &t [")
	for i := 0; i < k; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString("1")
	}
	b.WriteString("]\nx-n: &n {trunk: *t}\nx-v: &v {network: [")
	for i := 0; i < k; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString("*n")
	}
	b.WriteString("]}\nvms: {")
	for i := 0; i < k; i++ {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "v%d: *v", i)
	}
	b.WriteString("}\n")
	return b.String()
}

// The unknown-field check follows aliases, so a few kilobytes of YAML could
// make it walk k³ nodes — 27 million for k=300, seconds of CPU for every
// DeployStack or DiffStack a caller sends. It visits a bounded number of
// nodes, and a file that needs more is refused rather than half-checked.
func TestCheckFields_AliasExpansionIsBounded(t *testing.T) {
	data := aliasBomb(300)
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(data), &doc); err != nil {
		t.Fatal(err)
	}
	v := &validator{ps: problems{idx: indexNodes(&doc)}, origin: map[string]string{}}
	v.checkFileFields(documentRoot(&doc))
	if v.fieldVisits > maxFieldVisits+1 {
		t.Errorf("checkFields visited %d nodes, want at most %d", v.fieldVisits, maxFieldVisits+1)
	}
	if _, ok := findProblem(v.ps.list, "", "too many nodes"); !ok {
		t.Errorf("an over-budget file is not reported; got:\n%s", dumpProblems(v.ps.list))
	}

}

// The decoder's own excessive-aliasing guard refuses the same file before the
// unknown-field check walks any of it: the file is refused for its aliasing
// alone, in about a millisecond, and the walk's budget is never reached.
func TestParse_AliasBombRefusedByTheDecoderFirst(t *testing.T) {
	_, err := ParseBytes([]byte(aliasBomb(300)))
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("ParseBytes(alias bomb) = %v, want a *ValidationError", err)
	}
	if len(ve.Problems) != 1 || !strings.Contains(ve.Problems[0].Message, "excessive aliasing") {
		t.Errorf("problems:\n%s\nwant exactly the decoder's excessive-aliasing refusal (the walk must not run first)", dumpProblems(ve.Problems))
	}
}

// Ordinary anchors are still followed: an unknown field written once under an
// anchor is reported for the VM that uses it.
func TestCheckFields_AnchorsStillChecked(t *testing.T) {
	ps := problemsOf(t, "name: s\nx-base: &b {image: u, cpus: 2}\nvms:\n  a: *b\n")
	if _, ok := findProblem(ps, "vms.a", `unknown field "cpus"`); !ok {
		t.Errorf("unknown field under an alias not reported; got:\n%s", dumpProblems(ps))
	}
}
