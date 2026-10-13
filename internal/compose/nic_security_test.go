package compose

import (
	"errors"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// nicSpec is a one-NIC spec: the desired side when built from a file, the
// stored side once the live NIC security is overlaid on it.
func nicSpec(att *pb.NetworkAttachment) *pb.VMSpec {
	s := baseSpec()
	att.Name = "lan"
	s.Network = []*pb.NetworkAttachment{att}
	return s
}

func metaFields(p ChangePlan) map[string]Delta {
	out := map[string]Delta{}
	for _, d := range p.MetadataChanges {
		out[d.Field] = d
	}
	return out
}

func weakens(p ChangePlan) string { return strings.Join(p.Weakens(), "\n") }

// N2: a security-group binding the file declares is compared with the live
// binding, so an `sg bind` made outside the file is drift. Any rebind may
// widen access (rules are first-match across the bound groups; under
// default-deny binding a group opens what it accepts), so it is a weakening.
func TestClassify_DeclaredSecurityGroupsDriftIsALiveChange(t *testing.T) {
	desired := nicSpec(&pb.NetworkAttachment{SecurityGroups: []string{"web"}})
	live := nicSpec(&pb.NetworkAttachment{}) // `lv sg bind --sg ""` emptied it
	p := Classify(desired, live, StoredDisksFromSpec(live))
	if p.Max() != ActionLive {
		t.Fatalf("Max()=%v, want Live (a rebind needs no restart)", p.Max())
	}
	d, ok := metaFields(p)[NICSecurityGroupsFieldPrefix+"0"]
	if !ok || d.Old != "[]" || d.New != "[web]" {
		t.Fatalf("delta = %+v (ok=%v), want []→[web]", d, ok)
	}
	if w := weakens(p); !strings.Contains(w, "binds web") {
		t.Errorf("weakens = %q, want the newly bound group named (it can reopen access)", w)
	}
}

// A NIC whose file names no security groups does not own its binding.
func TestClassify_UndeclaredSecurityGroupsAreNotTouched(t *testing.T) {
	desired := nicSpec(&pb.NetworkAttachment{})
	live := nicSpec(&pb.NetworkAttachment{SecurityGroups: []string{"isolate"}})
	if p := Classify(desired, live, StoredDisksFromSpec(live)); p.Max() != ActionNoChange {
		t.Fatalf("an undeclared binding was planned over: %+v", p)
	}
}

func TestClassify_UnbindingAndReorderingAreWeakenings(t *testing.T) {
	desired := nicSpec(&pb.NetworkAttachment{SecurityGroups: []string{"web"}})
	live := nicSpec(&pb.NetworkAttachment{SecurityGroups: []string{"web", "isolate"}})
	p := Classify(desired, live, StoredDisksFromSpec(live))
	if w := weakens(p); !strings.Contains(w, "unbinds isolate, bound now") {
		t.Errorf("weakens = %q, want the unbound group named", w)
	}
	desired = nicSpec(&pb.NetworkAttachment{SecurityGroups: []string{"isolate", "web"}})
	p = Classify(desired, live, StoredDisksFromSpec(live))
	if w := weakens(p); !strings.Contains(w, "reorders") {
		t.Errorf("weakens = %q, want a reorder named", w)
	}
}

// The F4 lab case: the file declares guard on with an allowed address and
// VLAN tags; `nic-guard set --mode on` dropped both. Restoring them relaxes
// the live guard.
func TestClassify_DeclaredGuardDriftThatRelaxes(t *testing.T) {
	desired := nicSpec(&pb.NetworkAttachment{SpoofGuard: "on", AllowedAddresses: []string{"10.246.0.250"}, AllowVlanTags: true})
	live := nicSpec(&pb.NetworkAttachment{SpoofGuard: "on"})
	p := Classify(desired, live, StoredDisksFromSpec(live))
	if p.Max() != ActionLive {
		t.Fatalf("Max()=%v, want Live", p.Max())
	}
	if _, ok := metaFields(p)[NICGuardFieldPrefix+"0"]; !ok {
		t.Fatalf("no guard drift recorded: %+v", p.MetadataChanges)
	}
	if w := weakens(p); !strings.Contains(w, "10.246.0.250") || !strings.Contains(w, "vlan") {
		t.Fatalf("weakens = %q, want the added address and VLAN tags named", w)
	}
}

func TestClassify_UndeclaredGuardIsNotTouched(t *testing.T) {
	desired := nicSpec(&pb.NetworkAttachment{})
	live := nicSpec(&pb.NetworkAttachment{SpoofGuard: "off", AllowDhcpServer: true})
	if p := Classify(desired, live, StoredDisksFromSpec(live)); p.Max() != ActionNoChange {
		t.Fatalf("an undeclared guard was planned over: %+v", p)
	}
}

// Naming any guard setting declares the whole guard, on unless it says off.
// Turning a guard switched off at runtime back on tightens.
func TestClassify_DeclaredGuardBackOnTightens(t *testing.T) {
	desired := nicSpec(&pb.NetworkAttachment{AllowDhcpServer: true})
	live := nicSpec(&pb.NetworkAttachment{SpoofGuard: "off", AllowDhcpServer: true})
	p := Classify(desired, live, StoredDisksFromSpec(live))
	d, ok := metaFields(p)[NICGuardFieldPrefix+"0"]
	if !ok || !strings.Contains(d.New, "mode=on") || !strings.Contains(d.Old, "mode=off") {
		t.Fatalf("delta = %+v (ok=%v), want mode off→on", d, ok)
	}
	if w := weakens(p); w != "" {
		t.Errorf("turning a guard on weakens nothing, got %q", w)
	}
}

func TestClassify_DeclaredGuardOffOverALiveGuardWeakens(t *testing.T) {
	desired := nicSpec(&pb.NetworkAttachment{SpoofGuard: "off"})
	live := nicSpec(&pb.NetworkAttachment{SpoofGuard: "on"})
	if w := weakens(Classify(desired, live, StoredDisksFromSpec(live))); !strings.Contains(w, "turns the guard off") {
		t.Fatalf("weakens = %q, want the guard turned off named", w)
	}
}

func TestClassify_DeclaredGuardOnAnUnguardedNIC(t *testing.T) {
	desired := nicSpec(&pb.NetworkAttachment{SpoofGuard: "on"})
	live := nicSpec(&pb.NetworkAttachment{})
	p := Classify(desired, live, StoredDisksFromSpec(live))
	d, ok := metaFields(p)[NICGuardFieldPrefix+"0"]
	if !ok || d.Old != "unset" {
		t.Fatalf("delta = %+v (ok=%v), want unset→on", d, ok)
	}
	if w := weakens(p); w != "" {
		t.Errorf("guarding an unguarded NIC weakens nothing, got %q", w)
	}
}

func TestClassify_GuardAddressesCompareCanonically(t *testing.T) {
	desired := nicSpec(&pb.NetworkAttachment{SpoofGuard: "ON", AllowedAddresses: []string{" 10.0.0.9 ", "10.0.1.0/24", "10.0.0.9", "10.0.2.7/16"}})
	live := nicSpec(&pb.NetworkAttachment{SpoofGuard: "on", AllowedAddresses: []string{"10.0.0.9", "10.0.0.0/16", "10.0.1.0/24"}})
	if p := Classify(desired, live, StoredDisksFromSpec(live)); p.Max() != ActionNoChange {
		t.Fatalf("an equivalent guard read as drift: %s", p.Reasons())
	}
}

// An address the live guard already allows through a prefix is no
// relaxation (review M3).
func TestClassify_AnAddressInsideALivePrefixIsNoRelaxation(t *testing.T) {
	desired := nicSpec(&pb.NetworkAttachment{SpoofGuard: "on", AllowedAddresses: []string{"10.0.0.5", "10.0.0.128/25"}})
	live := nicSpec(&pb.NetworkAttachment{SpoofGuard: "on", AllowedAddresses: []string{"10.0.0.0/24"}})
	p := Classify(desired, live, StoredDisksFromSpec(live))
	if _, ok := metaFields(p)[NICGuardFieldPrefix+"0"]; !ok {
		t.Fatal("a different allowed list is still drift")
	}
	if w := weakens(p); w != "" {
		t.Errorf("weakens = %q; both addresses are inside the live 10.0.0.0/24", w)
	}
}

// A NIC whose network changed does not stop the comparison of the NICs after
// it (review M4).
func TestClassify_LaterNICsAreComparedAfterANetworkChange(t *testing.T) {
	desired := baseSpec()
	desired.Network = []*pb.NetworkAttachment{{Name: "other"}, {Name: "lan", SecurityGroups: []string{"web"}}}
	live := baseSpec()
	live.Network = []*pb.NetworkAttachment{{Name: "lan"}, {Name: "lan"}}
	if _, ok := metaFields(Classify(desired, live, StoredDisksFromSpec(live)))[NICSecurityGroupsFieldPrefix+"1"]; !ok {
		t.Error("drift on nic 1 was hidden by a network change on nic 0")
	}
}

func TestOverlayLiveNICSecurity(t *testing.T) {
	stored := &pb.VMSpec{Network: []*pb.NetworkAttachment{
		{Name: "lan", Mac: "52:54:00:00:00:01", SecurityGroups: []string{"web"}, SpoofGuard: "on", AllowVlanTags: true},
		{Name: "core", SecurityGroups: []string{"db"}, SpoofGuard: "off"},
		{Name: "gone", SecurityGroups: []string{"x"}, SpoofGuard: "on"},
	}}
	live := []LiveNIC{
		{Network: "core", MAC: "52:54:00:00:00:02", Ordinal: 1},
		{Network: "lan", MAC: "52:54:00:00:00:01", Ordinal: 0, SecurityGroups: []string{"isolate"},
			Guard: &LiveGuard{Mode: "on", Allowed: []string{"10.0.0.250"}}},
	}
	got := OverlayLiveNICSecurity(stored, live)
	if n := got.Network[0]; len(n.SecurityGroups) != 1 || n.SecurityGroups[0] != "isolate" || n.SpoofGuard != "on" ||
		n.AllowVlanTags || len(n.AllowedAddresses) != 1 {
		t.Errorf("nic 0 = %v, want the live binding and guard", n)
	}
	if n := got.Network[1]; len(n.SecurityGroups) != 0 || n.SpoofGuard != "" {
		t.Errorf("nic 1 = %v, want no groups and no guard (unguarded)", n)
	}
	if n := got.Network[2]; n.SecurityGroups[0] != "x" || n.SpoofGuard != "on" {
		t.Errorf("nic 2 (no live NIC) = %v, want the stored values left as they are", n)
	}
	if stored.Network[0].SecurityGroups[0] != "web" {
		t.Error("the overlay changed the spec it was given")
	}
}

// gated classifies desired against live and applies the gate.
func gated(desired, live *pb.VMSpec, liveNICs []LiveNIC, g NICSecurityGate) (ChangePlan, string) {
	p := Classify(desired, live, StoredDisksFromSpec(live))
	w := ApplyNICSecurityGate("vm", &p, desired, live, liveNICs, g)
	return p, strings.Join(w, "\n")
}

// R1: a restore that may weaken protection is withheld without the opt-in,
// and the plan says what and how to apply it; with it, it is applied and
// still named.
func TestGate_AWeakeningRestoreNeedsAllowWeaken(t *testing.T) {
	desired := nicSpec(&pb.NetworkAttachment{SecurityGroups: []string{"web"}, SpoofGuard: "on", AllowedAddresses: []string{"10.0.0.250"}})
	live := nicSpec(&pb.NetworkAttachment{SecurityGroups: []string{"isolate"}, SpoofGuard: "on"})
	p, w := gated(desired, live, nil, NICSecurityGate{})
	if p.Max() != ActionNoChange {
		t.Errorf("withheld restores still planned: %+v", p.MetadataChanges)
	}
	for _, want := range []string{"security groups not restored", "unbinds isolate", "guard not restored", "10.0.0.250", "--allow-weaken"} {
		if !strings.Contains(w, want) {
			t.Errorf("warnings %q lack %q", w, want)
		}
	}
	p, w = gated(desired, live, nil, NICSecurityGate{AllowWeaken: true})
	if f := metaFields(p); len(f) != 2 {
		t.Errorf("with --allow-weaken the restores are applied, got %+v", p.MetadataChanges)
	}
	if !strings.Contains(w, "applied with --allow-weaken") || !strings.Contains(w, "isolate") {
		t.Errorf("warnings %q do not name the applied weakening", w)
	}
}

// A guard restore to a plain "on" is applied without the opt-in and without
// guard authority (as at create); a declared guard that is off needs it.
func TestGate_ATighteningGuardRestoreProceeds(t *testing.T) {
	desired := nicSpec(&pb.NetworkAttachment{SpoofGuard: "on"})
	live := nicSpec(&pb.NetworkAttachment{SpoofGuard: "off"})
	noAuthority := func(string) error { return errors.New("needs network.update on /") }
	p, w := gated(desired, live, nil, NICSecurityGate{CheckGuardAuthority: noAuthority})
	if _, ok := metaFields(p)[NICGuardFieldPrefix+"0"]; !ok || w != "" {
		t.Errorf("a tightening restore was withheld: %+v %q", p.MetadataChanges, w)
	}
	desired = nicSpec(&pb.NetworkAttachment{SpoofGuard: "off"})
	live = nicSpec(&pb.NetworkAttachment{SpoofGuard: "on"})
	p, w = gated(desired, live, nil, NICSecurityGate{AllowWeaken: true, CheckGuardAuthority: noAuthority})
	if len(p.MetadataChanges) != 0 || !strings.Contains(w, "needs network.update") {
		t.Errorf("a weakening the caller may not make was not withheld: %+v %q", p.MetadataChanges, w)
	}
}

// I3/I4b: what the deploy cannot make is withheld at plan time, with why.
func TestGate_WithholdsWhatTheDeployCannotMake(t *testing.T) {
	desired := nicSpec(&pb.NetworkAttachment{SecurityGroups: []string{"web"}, SpoofGuard: "on"})
	live := nicSpec(&pb.NetworkAttachment{})
	p, w := gated(desired, live, nil, NICSecurityGate{AllowWeaken: true,
		GuardsUnwritable: "the cluster upgrade must finish",
		CheckBind:        func(string) error { return errors.New("rebinding needs network.update on vm") }})
	if len(p.MetadataChanges) != 0 {
		t.Errorf("withheld restores still planned: %+v", p.MetadataChanges)
	}
	if !strings.Contains(w, "the cluster upgrade must finish") || !strings.Contains(w, "rebinding needs network.update") {
		t.Errorf("warnings %q do not say why", w)
	}
}

// I4a: a binding is written per network, so a NIC sharing its network with
// one the file does not declare the same groups for cannot be restored alone.
func TestGate_ABindingSharedWithAnotherNICIsWithheld(t *testing.T) {
	two := func(a, b []string) *pb.VMSpec {
		s := baseSpec()
		s.Network = []*pb.NetworkAttachment{{Name: "lan", Mac: "52:54:00:00:00:01", SecurityGroups: a},
			{Name: "lan", Mac: "52:54:00:00:00:02", SecurityGroups: b}}
		return s
	}
	liveNICs := []LiveNIC{{Network: "lan", MAC: "52:54:00:00:00:01"}, {Network: "lan", MAC: "52:54:00:00:00:02", Ordinal: 1}}
	p, w := gated(two([]string{"web"}, nil), two([]string{"isolate"}, []string{"isolate"}), liveNICs, NICSecurityGate{AllowWeaken: true})
	if len(p.MetadataChanges) != 0 || !strings.Contains(w, "written per network") {
		t.Errorf("a per-network rebind reaching an undeclared NIC was planned: %+v %q", p.MetadataChanges, w)
	}
	// A hot-attached NIC on the network, which the spec does not describe.
	one := nicSpec(&pb.NetworkAttachment{Mac: "52:54:00:00:00:01", SecurityGroups: []string{"web"}})
	liveOne := nicSpec(&pb.NetworkAttachment{Mac: "52:54:00:00:00:01", SecurityGroups: []string{"isolate"}})
	if _, w := gated(one, liveOne, liveNICs, NICSecurityGate{AllowWeaken: true}); !strings.Contains(w, "written per network") {
		t.Errorf("a hot-attached sibling was not seen: %q", w)
	}
	p, _ = gated(two([]string{"web"}, []string{"web"}), two([]string{"isolate"}, []string{"isolate"}), liveNICs, NICSecurityGate{AllowWeaken: true})
	if len(p.MetadataChanges) != 2 {
		t.Errorf("both NICs declared alike is one binding and is applied: %+v", p.MetadataChanges)
	}
}

// A recreate makes the NICs from the file, as it always has: nothing is
// gated, and what it changes is a warning.
func TestGate_ARecreateIsNotGatedButWarns(t *testing.T) {
	desired := nicSpec(&pb.NetworkAttachment{SecurityGroups: []string{"web"}})
	desired.Image = "other"
	live := nicSpec(&pb.NetworkAttachment{SecurityGroups: []string{"isolate"}})
	p, w := gated(desired, live, nil, NICSecurityGate{})
	if p.Max() != ActionRecreate || !strings.Contains(w, "the recreate applies") || !strings.Contains(w, "isolate") {
		t.Errorf("plan %v warnings %q", p.Max(), w)
	}
}

// I5: a recreate keeps the live binding of a NIC whose file declares none.
func TestCarryUndeclaredSecurityGroups(t *testing.T) {
	desired := baseSpec()
	desired.Network = []*pb.NetworkAttachment{{Name: "lan"}, {Name: "core", SecurityGroups: []string{"db"}}, {Name: "new"}}
	stored := baseSpec()
	stored.Network = []*pb.NetworkAttachment{{Name: "lan", SecurityGroups: []string{"isolate"}},
		{Name: "core", SecurityGroups: []string{"x"}}, {Name: "old", SecurityGroups: []string{"y"}}}
	notes := CarryUndeclaredSecurityGroups(desired, stored)
	if g := desired.Network[0].SecurityGroups; len(g) != 1 || g[0] != "isolate" {
		t.Errorf("undeclared nic 0 = %v, want isolate carried", g)
	}
	if g := desired.Network[1].SecurityGroups; g[0] != "db" {
		t.Errorf("declared nic 1 = %v, want the file's", g)
	}
	if len(desired.Network[2].SecurityGroups) != 0 {
		t.Error("a NIC whose network changed carried a binding")
	}
	if len(notes) != 2 || !strings.Contains(notes[0], "isolate") || !strings.Contains(notes[1], "drops the security groups [y]") {
		t.Errorf("notes = %v, want the carry and the dropped binding named", notes)
	}
}

// Build applies the safe gate by default: a runtime unbind on a declared NIC
// is withheld and reported, and the VM is otherwise unchanged.
func TestBuild_AWeakeningRestoreIsWithheldAndReported(t *testing.T) {
	def := createdDef()
	def.Network = []NetworkAttachment{{Name: "lan", SecurityGroups: []string{"web"}}}
	stored := storedAsCreated()
	stored.Network[0].SecurityGroups = []string{"isolate"}
	plan := buildWithStored(t, def, stored)
	if len(plan.Ops) != 1 || plan.Ops[0].Kind != OpNoChange {
		t.Fatalf("ops = %+v, want no change", plan.Ops)
	}
	if w := plan.Ops[0].Warning; !strings.Contains(w, "isolate") || !strings.Contains(w, "--allow-weaken") {
		t.Errorf("warning %q does not name the withheld unbind and the opt-in", w)
	}
}

// Round 2, N1: guard authority is asked for every declared guard weaker than
// the default (off, or any allowance), whatever the live guard: one that
// tightens a wider live guard, or is put on a NIC with no record, still needs
// it, because the executor writes it under the same rule.
func TestGate_GuardAuthorityIsAskedForEveryGuardWeakerThanTheDefault(t *testing.T) {
	noAuthority := func(string) error { return errors.New("needs network.update on /") }
	for _, c := range []struct {
		name           string
		declared, live *pb.NetworkAttachment
		withheld       bool
	}{
		{"allowance over no record", &pb.NetworkAttachment{SpoofGuard: "on", AllowedAddresses: []string{"10.0.0.5"}}, &pb.NetworkAttachment{}, true},
		{"narrower than a wider live prefix", &pb.NetworkAttachment{SpoofGuard: "on", AllowedAddresses: []string{"10.0.0.5"}},
			&pb.NetworkAttachment{SpoofGuard: "on", AllowedAddresses: []string{"10.0.0.0/24"}}, true},
		{"off over no record", &pb.NetworkAttachment{SpoofGuard: "off"}, &pb.NetworkAttachment{}, true},
		{"plain on over no record", &pb.NetworkAttachment{SpoofGuard: "on"}, &pb.NetworkAttachment{}, false},
	} {
		p, w := gated(nicSpec(c.declared), nicSpec(c.live), nil, NICSecurityGate{CheckGuardAuthority: noAuthority})
		if got := len(p.MetadataChanges) == 0; got != c.withheld {
			t.Errorf("%s: withheld = %v (%q), want %v", c.name, got, w, c.withheld)
		}
		if c.withheld && !strings.Contains(w, "needs network.update") {
			t.Errorf("%s: warnings %q do not name the permission", c.name, w)
		}
		if DeclaredGuardNeedsAuthority(nicSpec(c.declared).Network[0]) != c.withheld {
			t.Errorf("%s: DeclaredGuardNeedsAuthority disagrees", c.name)
		}
	}
}

// Round 2, M3: the carry matches a NIC by its network and its place among the
// NICs on that network, so a NIC inserted before it does not lose its
// binding; a binding whose NIC the file no longer has is named.
func TestCarryUndeclaredSecurityGroups_SurvivesAnInsertedNIC(t *testing.T) {
	desired := baseSpec()
	desired.Network = []*pb.NetworkAttachment{{Name: "new"}, {Name: "lan"}, {Name: "lan"}}
	stored := baseSpec()
	stored.Network = []*pb.NetworkAttachment{{Name: "lan", SecurityGroups: []string{"isolate"}}, {Name: "lan"},
		{Name: "gone", SecurityGroups: []string{"quarantine"}}}
	notes := strings.Join(CarryUndeclaredSecurityGroups(desired, stored), "\n")
	if g := desired.Network[1].SecurityGroups; len(g) != 1 || g[0] != "isolate" {
		t.Errorf("the first lan NIC (now position 1) = %v, want isolate carried", g)
	}
	if len(desired.Network[0].SecurityGroups) != 0 || len(desired.Network[2].SecurityGroups) != 0 {
		t.Errorf("a binding was carried onto the wrong NIC: %v", desired.Network)
	}
	if !strings.Contains(notes, "drops the security groups [quarantine]") {
		t.Errorf("notes %q do not name the dropped binding", notes)
	}
}

// Round 3, N2: a guard declared on a NIC whose network cannot enforce one
// (direct, SR-IOV) is no drift: create wrote no record, so there is nothing
// to restore. The plan says it is not enforced, and does not count it as a
// withheld restore.
func TestGate_AGuardOnAnUnenforcedNetworkIsNoDrift(t *testing.T) {
	desired := nicSpec(&pb.NetworkAttachment{SpoofGuard: "on"})
	live := nicSpec(&pb.NetworkAttachment{})
	unenforced := func(n string) string { return GuardUnenforcedOn("direct", n) }
	p, w := gated(desired, live, nil, NICSecurityGate{GuardUnenforced: unenforced})
	if p.Max() != ActionNoChange {
		t.Errorf("a guard on a direct NIC planned %+v", p.MetadataChanges)
	}
	if !strings.Contains(w, "declares a guard that is not enforced") || strings.Contains(w, "not restored") {
		t.Errorf("warnings %q, want the not-enforced note and no withheld restore", w)
	}
	if GuardUnenforcedOn("sriov", "x") == "" || GuardUnenforcedOn("", "direct:eth0") == "" || GuardUnenforcedOn("bridge", "lan") != "" {
		t.Error("GuardUnenforcedOn misjudges a network type")
	}
}

// A declared guard create would refuse (a bad mode, an address that does not
// parse) is withheld with why, not planned for the executor to refuse.
func TestGate_AnInvalidDeclaredGuardIsWithheld(t *testing.T) {
	for _, att := range []*pb.NetworkAttachment{{SpoofGuard: "enabled"}, {AllowedAddresses: []string{"not-an-ip"}}} {
		p, w := gated(nicSpec(att), nicSpec(&pb.NetworkAttachment{}), nil, NICSecurityGate{AllowWeaken: true})
		if len(p.MetadataChanges) != 0 || !strings.Contains(w, "the file's guard is invalid") {
			t.Errorf("%v: plan %+v warnings %q", att, p.MetadataChanges, w)
		}
	}
}

// A create's spec loses a guard its network cannot enforce, and the plan
// says so; other NICs keep theirs.
func TestStripUnenforcedGuards(t *testing.T) {
	spec := baseSpec()
	spec.Network = []*pb.NetworkAttachment{{Name: "wan", SpoofGuard: "on", AllowedAddresses: []string{"10.0.0.5"}}, {Name: "lan", SpoofGuard: "on"}}
	notes := StripUnenforcedGuards(spec, func(n string) string {
		if n == "wan" {
			return GuardUnenforcedOn("direct", n)
		}
		return ""
	})
	if spec.Network[0].SpoofGuard != "" || len(spec.Network[0].AllowedAddresses) != 0 || spec.Network[1].SpoofGuard != "on" {
		t.Errorf("network = %v", spec.Network)
	}
	if len(notes) != 1 || !strings.Contains(notes[0], "nic 0 (wan) declares a guard that is not enforced") {
		t.Errorf("notes = %v", notes)
	}
}

// Round 3, m1: a NIC removed on the same network makes the pairing
// ambiguous: nothing is carried there (the remaining NIC must not gain the
// removed one's groups), and each binding is named as dropped.
func TestCarry_ARemovedNICOnTheSameNetworkCarriesNothing(t *testing.T) {
	desired := baseSpec()
	desired.Network = []*pb.NetworkAttachment{{Name: "lan"}}
	stored := baseSpec()
	stored.Network = []*pb.NetworkAttachment{{Name: "lan", Mac: "52:54:00:00:00:01", SecurityGroups: []string{"web"}},
		{Name: "lan", Mac: "52:54:00:00:00:02"}}
	notes := strings.Join(CarryUndeclaredSecurityGroups(desired, stored), "\n")
	if len(desired.Network[0].SecurityGroups) != 0 {
		t.Errorf("the remaining NIC took %v", desired.Network[0].SecurityGroups)
	}
	if !strings.Contains(notes, "drops the security groups [web]") || !strings.Contains(notes, "changes how many NICs are on lan") {
		t.Errorf("notes %q", notes)
	}
	// Inserted on the same network: the same.
	desired.Network = []*pb.NetworkAttachment{{Name: "lan"}, {Name: "lan"}, {Name: "lan"}}
	CarryUndeclaredSecurityGroups(desired, stored)
	for i, n := range desired.Network {
		if len(n.SecurityGroups) != 0 {
			t.Errorf("nic %d took %v from an ambiguous pairing", i, n.SecurityGroups)
		}
	}
}

// A NIC the file names by MAC takes the binding of the NIC with that MAC,
// wherever it now sits.
func TestCarry_MatchesByMAC(t *testing.T) {
	desired := baseSpec()
	desired.Network = []*pb.NetworkAttachment{{Name: "lan", Mac: "52:54:00:00:00:02"}, {Name: "lan", Mac: "52:54:00:00:00:01"}}
	stored := baseSpec()
	stored.Network = []*pb.NetworkAttachment{{Name: "lan", Mac: "52:54:00:00:00:01", SecurityGroups: []string{"isolate"}},
		{Name: "lan", Mac: "52:54:00:00:00:02"}}
	CarryUndeclaredSecurityGroups(desired, stored)
	if len(desired.Network[0].SecurityGroups) != 0 || len(desired.Network[1].SecurityGroups) != 1 || desired.Network[1].SecurityGroups[0] != "isolate" {
		t.Errorf("network = %v, want isolate on the NIC with MAC :01", desired.Network)
	}
}
