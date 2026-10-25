package corrosion

import (
	"context"
	"errors"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
)

// importVoters: a, b and c are generation 1; d's replica adopts generation 2
// as built by next, through the sealed-majority import unless plain.
func importVoterAt(t *testing.T, next func(a, b, c, d *claimTestVoter) VoterConfigValue, plain bool, from ...string) (d *claimTestVoter, cfg VoterConfigValue) {
	t.Helper()
	ctx := context.Background()
	ca := newClaimTestCA(t)
	a, b, c := newClaimTestVoter(t, ca, "a"), newClaimTestVoter(t, ca, "b"), newClaimTestVoter(t, ca, "c")
	d = newClaimTestVoter(t, ca, "d")
	adoptHandBuilt(t, 1, membersOf(a, b, c), d)
	cfg = next(a, b, c, d)
	cfg.Generation, cfg.CreatedBy, cfg.CreatedAt = 2, "t", "t"
	if err := WriteVoterConfig(ctx, d.c, cfg, ClaimCertificate{}); err != nil {
		t.Fatal(err)
	}
	var err error
	if plain {
		err = RecordVoterAdoption(ctx, d.c, 2)
	} else {
		if len(from) == 0 {
			from = []string{"a", "b"}
		}
		_, err = d.c.ImportClaimsAndAdoptAutomation(ctx, 2, from, nil)
	}
	if err != nil {
		t.Fatal(err)
	}
	return d, cfg
}

// A new voter may import automation authority only at an ordinary
// generation of at least three members that it adopted, as a member under
// its own incarnation, through the sealed old majority's claim import, and
// whose predecessor is itself an automation electorate. Everything else is a
// standing refusal, and the grant refuses it too.
func TestAutomationImportEligibilityRules(t *testing.T) {
	ctx := context.Background()
	add := func(a, b, c, d *claimTestVoter) VoterConfigValue {
		return VoterConfigValue{Members: membersOf(a, b, c, d), Change: VoterChangeAdd("d")}
	}
	for _, tc := range []struct {
		name  string
		next  func(a, b, c, d *claimTestVoter) VoterConfigValue
		plain bool
		ok    bool
		from  []string
	}{
		{"ordinary add", add, false, true, nil},
		{"adopted without the sealed-majority import", add, true, false, nil},
		{"imported from a minority of the old generation", add, false, false, []string{"a"}},
		{"imported from voters outside the old generation", add, false, false, []string{"d", "x"}},
		{"imported from one voter named twice", add, false, false, []string{"a", "a"}},
		{"imported from the whole old generation", add, false, true, []string{"a", "b", "c"}},
		{"forced", func(a, b, c, d *claimTestVoter) VoterConfigValue {
			return VoterConfigValue{Members: membersOf(a, b, d), Change: "force:x"}
		}, false, false, nil},
		{"reset", func(a, b, c, d *claimTestVoter) VoterConfigValue {
			return VoterConfigValue{Members: membersOf(a, b, c, d), Change: VoterChangeReset}
		}, false, false, nil},
		{"two voters", func(a, b, c, d *claimTestVoter) VoterConfigValue {
			return VoterConfigValue{Members: membersOf(a, d), Change: VoterChangeAdd("d")}
		}, false, false, nil},
		{"other incarnation", func(a, b, c, d *claimTestVoter) VoterConfigValue {
			ms := membersOf(a, b, c, d)
			for i := range ms {
				if ms[i].Name == "d" {
					ms[i].Incarnation = "someone-else"
				}
			}
			return VoterConfigValue{Members: ms, Change: VoterChangeAdd("d")}
		}, false, false, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, _ := importVoterAt(t, tc.next, tc.plain, tc.from...)
			var plan AutomationImportPlan
			err := d.c.ExecuteLocal(ctx, func(tx *LocalTx) error {
				var err error
				plan, err = automationImportEligibleTx(ctx, tx, "d", 2)
				return err
			})
			if tc.ok {
				if err != nil || plan.Generation != 2 || plan.Previous == nil || len(plan.Previous.Members) != 3 {
					t.Fatalf("plan %+v: %v", plan, err)
				}
				// Eligible, but this replica holds no automation state: a
				// cluster that never used automation has nothing to import,
				// and the daemon's pass stops at this local read.
				if _, err := d.c.AutomationImportPlan(ctx); !errors.Is(err, ErrAutomationImportIneligible) {
					t.Fatalf("plan without automation state: %v, want ErrAutomationImportIneligible", err)
				}
				return
			}
			if !errors.Is(err, ErrAutomationImportIneligible) {
				t.Fatalf("plan: %v, want ErrAutomationImportIneligible", err)
			}
			grant := capabilities.GrantForTest(t, capabilities.FeatureAutomationState)
			if err := d.c.AutomationGrantImportedAuthority(ctx, grant, 2, nil); !errors.Is(err, ErrAutomationImportIneligible) {
				t.Fatalf("grant: %v, want ErrAutomationImportIneligible", err)
			}
		})
	}
}

// The writers refuse without the automation_state grant.
func TestAutomationImportWritersTakeTheGrant(t *testing.T) {
	ctx := context.Background()
	d, _ := importVoterAt(t, func(a, b, c, d *claimTestVoter) VoterConfigValue {
		return VoterConfigValue{Members: membersOf(a, b, c, d), Change: VoterChangeAdd("d")}
	}, false)
	other := capabilities.GrantForTest(t, capabilities.FeatureAutomationStream)
	if err := d.c.AutomationGrantImportedAuthority(ctx, other, 2, nil); !errors.Is(err, capabilities.ErrNoFeatureGrant) {
		t.Fatalf("grant writer: %v, want ErrNoFeatureGrant", err)
	}
	if err := d.c.AutomationBeginImport(ctx, capabilities.FeatureGrant{}, AutomationRecord{}, nil, 2); !errors.Is(err, capabilities.ErrNoFeatureGrant) {
		t.Fatalf("begin writer: %v, want ErrNoFeatureGrant", err)
	}
}

// The target is the maximum attested head among qualifying sources, and they
// must be a majority of the WHOLE previous generation: members of it and of
// the current one under the same incarnation, adopted at the import
// generation, holding authority there, with a nonempty head. The importer
// never counts itself.
func TestAutomationImportTargetNeedsOldMajority(t *testing.T) {
	m := func(n, inc string) VoterMember { return VoterMember{Name: n, Incarnation: inc} }
	prev := &VoterConfig{VoterConfigValue: VoterConfigValue{Generation: 1, Members: []VoterMember{m("a", "1"), m("b", "1"), m("c", "1"), m("e", "1"), m("f", "1")}}}
	cur := &VoterConfig{VoterConfigValue: VoterConfigValue{Generation: 2, Members: []VoterMember{m("a", "1"), m("b", "1"), m("c", "1"), m("d", "1"), m("e", "1"), m("f", "1")}}}
	plan := AutomationImportPlan{Self: "d", Generation: 2, Previous: prev, Current: cur}
	src := func(n string, seq uint64) AutomationImportSource {
		return AutomationImportSource{Voter: n, Incarnation: "1", Adopted: 2, Authority: true, Head: AutomationPrefix{ClusterUID: "u", Sequence: seq, Digest: "h" + string(rune('0'+seq))}}
	}
	good := []AutomationImportSource{src("a", 3), src("b", 5), src("c", 4)}
	target, sources, err := plan.Target(good)
	if err != nil || target.Sequence != 5 || len(sources) != 3 {
		t.Fatalf("three of five: %+v %v %v", target, sources, err)
	}
	for name, mutate := range map[string]func(*AutomationImportSource){
		"no authority":        func(s *AutomationImportSource) { s.Authority = false },
		"other generation":    func(s *AutomationImportSource) { s.Adopted = 3 },
		"other incarnation":   func(s *AutomationImportSource) { s.Incarnation = "2" },
		"empty head":          func(s *AutomationImportSource) { s.Head = AutomationPrefix{} },
		"not an old member":   func(s *AutomationImportSource) { s.Voter = "d" },
		"duplicate of a peer": func(s *AutomationImportSource) { s.Voter = "a" },
	} {
		bad := append([]AutomationImportSource(nil), good...)
		mutate(&bad[2])
		if _, _, err := plan.Target(bad); err == nil {
			t.Fatalf("%s: two qualifying sources of five accepted", name)
		}
	}
	split := append([]AutomationImportSource(nil), good...)
	split[1].Head.ClusterUID = "v"
	if _, _, err := plan.Target(split); err == nil {
		t.Fatal("sources disagreeing on the automation cluster accepted")
	}
}

// A tip is verified only against an ordinary automation electorate no later
// than the import generation: not a forced one, not a reset, not one of two.
func TestAutomationImportCertConfigRules(t *testing.T) {
	ctx := context.Background()
	ca := newClaimTestCA(t)
	a, b, c := newClaimTestVoter(t, ca, "a"), newClaimTestVoter(t, ca, "b"), newClaimTestVoter(t, ca, "c")
	d := newClaimTestVoter(t, ca, "d")
	for _, v := range []VoterConfigValue{
		{Generation: 1, Members: membersOf(a, b, c), Change: VoterChangeGenesis},
		{Generation: 2, Members: membersOf(a, b, c), Change: "force:x"},
		{Generation: 3, Members: membersOf(a, b, c), Change: VoterChangeReset},
		{Generation: 4, Members: membersOf(a, b), Change: "rm:c"},
		{Generation: 5, Members: membersOf(a, b, c), Change: VoterChangeAdd("c")},
	} {
		v.CreatedBy, v.CreatedAt = "t", "t"
		if err := WriteVoterConfig(ctx, d.c, v, ClaimCertificate{}); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		certGen, gen int64
		ok           bool
		why          string
	}{
		{1, 5, true, "ordinary genesis"},
		{5, 5, true, "the import generation itself"},
		{2, 5, false, "forced"},
		{3, 5, false, "reset"},
		{4, 5, false, "two voters"},
		{5, 4, false, "later than the import generation"},
		{0, 5, false, "no generation"},
	} {
		err := d.c.ExecuteLocal(ctx, func(tx *LocalTx) error {
			_, err := automationImportCertConfigTx(ctx, tx, tc.certGen, tc.gen)
			return err
		})
		if (err == nil) != tc.ok {
			t.Fatalf("%s (certified at %d, import at %d): %v, want ok=%v", tc.why, tc.certGen, tc.gen, err, tc.ok)
		}
	}
}
