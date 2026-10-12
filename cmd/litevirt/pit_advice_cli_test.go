package main

import (
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/pitoverlay"
)

// P-2 of lab 2 run c2: the held-VM advice told the admin to run
// `lv backup restore-from --vm <vm> --disk <d> --in-place`, which fails at
// once ("--timestamp is required"): restore-from also needs --repo and
// --timestamp. Every restore-from the hold texts name is parsed here by the
// real command, and must set every flag its RunE requires.
//
// Mutations "advice without --repo/--timestamp" and "a flag the command does
// not have" — red.
func TestPITHoldAdvice_RestoreFromIsACompleteInvocation(t *testing.T) {
	commitBegan := pitoverlay.Assessment{Verdict: pitoverlay.Unknown, Reason: "x", CommitBegan: true,
		Binding: &pitoverlay.Binding{State: pitoverlay.StateCommitting}}
	below := commitBegan
	below.BelowFeature, below.BelowWhy = true, "below the release"
	_, discardHalf := pitoverlay.Assessment{Verdict: pitoverlay.HalfWritten, CommitBegan: true}.Consequences()
	_, discardBegan := commitBegan.Consequences()
	texts := map[string]string{
		"advice, commit began":           pitoverlay.HoldAdvice("web", "root", commitBegan),
		"advice below the feature":       pitoverlay.HoldAdvice("web", "root", below),
		"discard of a half-written disk": discardHalf,
		"discard after a commit began":   discardBegan,
	}
	// What newBackupRestoreFromCmd's RunE refuses without.
	required := []string{"repo", "vm", "disk", "timestamp"}
	for name, txt := range texts {
		n := 0
		for _, m := range backtickedInvocationRE.FindAllStringSubmatch(txt, -1) {
			args := strings.Fields(m[1])
			if len(args) < 2 || args[0] != "backup" || args[1] != "restore-from" {
				continue
			}
			n++
			root := newRootCmd()
			cmd, rest, err := root.Find(args)
			if err != nil || cmd.Name() != "restore-from" {
				t.Fatalf("%s: `lv %s` does not resolve to restore-from: %v", name, m[1], err)
			}
			if err := cmd.ParseFlags(rest); err != nil {
				t.Errorf("%s: `lv %s`: %v", name, m[1], err)
				continue
			}
			for _, f := range required {
				if fl := cmd.Flags().Lookup(f); fl == nil || !fl.Changed || fl.Value.String() == "" {
					t.Errorf("%s: `lv %s` does not set --%s, which restore-from requires", name, m[1], f)
				}
			}
			if fl := cmd.Flags().Lookup("in-place"); fl == nil || !fl.Changed {
				t.Errorf("%s: `lv %s` is not --in-place", name, m[1])
			}
		}
		if n == 0 {
			t.Errorf("%s names no `lv backup restore-from …` to run: %q", name, txt)
		}
	}
}
