package compose

import (
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

// N2: a security-group binding the file declares is compared with the live
// binding, so an `sg bind` made outside the file is drift that `up` restores.
func TestClassify_DeclaredSecurityGroupsDriftIsALiveChange(t *testing.T) {
	desired := nicSpec(&pb.NetworkAttachment{SecurityGroups: []string{"web"}})
	live := nicSpec(&pb.NetworkAttachment{}) // `lv sg bind --sg ""` emptied it
	p := Classify(desired, live, StoredDisksFromSpec(live))
	if p.Max() != ActionLive {
		t.Fatalf("Max()=%v, want Live (a rebind needs no restart)", p.Max())
	}
	d, ok := metaFields(p)[NICSecurityGroupsFieldPrefix+"0"]
	if !ok {
		t.Fatalf("no security-group drift recorded: %+v", p.MetadataChanges)
	}
	if d.Old != "[]" || d.New != "[web]" {
		t.Errorf("delta = %+v, want []→[web]", d)
	}
	if len(p.Weakens) != 0 {
		t.Errorf("binding a group removes nothing, got weakens %v", p.Weakens)
	}
}

// A NIC whose file names no security groups does not own its binding: a
// group an operator bound at runtime (an isolation group in an incident) is
// neither reported nor removed.
func TestClassify_UndeclaredSecurityGroupsAreNotTouched(t *testing.T) {
	desired := nicSpec(&pb.NetworkAttachment{})
	live := nicSpec(&pb.NetworkAttachment{SecurityGroups: []string{"isolate"}})
	if p := Classify(desired, live, StoredDisksFromSpec(live)); p.Max() != ActionNoChange {
		t.Fatalf("an undeclared binding was planned over: %+v", p)
	}
}

// Restoring the file's binding can unbind a group bound outside it. The plan
// says so in words, not just as a list change.
func TestClassify_UnbindingARuntimeGroupIsExplicit(t *testing.T) {
	desired := nicSpec(&pb.NetworkAttachment{SecurityGroups: []string{"web"}})
	live := nicSpec(&pb.NetworkAttachment{SecurityGroups: []string{"web", "isolate"}})
	p := Classify(desired, live, StoredDisksFromSpec(live))
	if _, ok := metaFields(p)[NICSecurityGroupsFieldPrefix+"0"]; !ok {
		t.Fatalf("no drift recorded: %+v", p.MetadataChanges)
	}
	if len(p.Weakens) != 1 || !strings.Contains(p.Weakens[0], "isolate") {
		t.Fatalf("weakens = %v, want one naming the unbound group isolate", p.Weakens)
	}
	if !strings.Contains(p.Reasons(), "isolate") {
		t.Errorf("reasons do not name the unbound group: %s", p.Reasons())
	}
}

// The F4 lab case: the file declares guard on with an allowed address and
// VLAN tags; `nic-guard set --mode on` dropped both. That is drift, and the
// restore relaxes the live guard, which the plan says.
func TestClassify_DeclaredGuardDriftRestoresAndSaysItRelaxes(t *testing.T) {
	desired := nicSpec(&pb.NetworkAttachment{SpoofGuard: "on", AllowedAddresses: []string{"10.246.0.250"}, AllowVlanTags: true})
	live := nicSpec(&pb.NetworkAttachment{SpoofGuard: "on"})
	p := Classify(desired, live, StoredDisksFromSpec(live))
	if p.Max() != ActionLive {
		t.Fatalf("Max()=%v, want Live", p.Max())
	}
	if _, ok := metaFields(p)[NICGuardFieldPrefix+"0"]; !ok {
		t.Fatalf("no guard drift recorded: %+v", p.MetadataChanges)
	}
	if len(p.Weakens) != 1 || !strings.Contains(p.Weakens[0], "10.246.0.250") || !strings.Contains(p.Weakens[0], "vlan") {
		t.Fatalf("weakens = %v, want the added address and VLAN tags named", p.Weakens)
	}
}

// A guard the file does not mention is the operator's: turning it off at
// runtime is not drift compose reverts.
func TestClassify_UndeclaredGuardIsNotTouched(t *testing.T) {
	desired := nicSpec(&pb.NetworkAttachment{})
	live := nicSpec(&pb.NetworkAttachment{SpoofGuard: "off", AllowDhcpServer: true})
	if p := Classify(desired, live, StoredDisksFromSpec(live)); p.Max() != ActionNoChange {
		t.Fatalf("an undeclared guard was planned over: %+v", p)
	}
}

// Naming any guard setting declares the whole guard: mode on unless the file
// says off. Turning a guard switched off at runtime back on removes nothing.
func TestClassify_DeclaredGuardBackOnIsNotAWeakening(t *testing.T) {
	desired := nicSpec(&pb.NetworkAttachment{AllowDhcpServer: true}) // mode defaults to on
	live := nicSpec(&pb.NetworkAttachment{SpoofGuard: "off", AllowDhcpServer: true})
	p := Classify(desired, live, StoredDisksFromSpec(live))
	d, ok := metaFields(p)[NICGuardFieldPrefix+"0"]
	if !ok {
		t.Fatalf("no guard drift recorded: %+v", p.MetadataChanges)
	}
	if !strings.Contains(d.New, "mode=on") || !strings.Contains(d.Old, "mode=off") {
		t.Errorf("delta = %+v, want mode off→on", d)
	}
	if len(p.Weakens) != 0 {
		t.Errorf("turning a guard on weakens nothing, got %v", p.Weakens)
	}
}

// Turning a live guard off because the file says off is a weakening.
func TestClassify_DeclaredGuardOffOverALiveGuardIsAWeakening(t *testing.T) {
	desired := nicSpec(&pb.NetworkAttachment{SpoofGuard: "off"})
	live := nicSpec(&pb.NetworkAttachment{SpoofGuard: "on"})
	p := Classify(desired, live, StoredDisksFromSpec(live))
	if len(p.Weakens) != 1 || !strings.Contains(p.Weakens[0], "off") {
		t.Fatalf("weakens = %v, want the guard turned off named", p.Weakens)
	}
}

// A NIC with no guard record (unguarded, stored "") and a file that declares
// one: the guard is put on.
func TestClassify_DeclaredGuardOnAnUnguardedNIC(t *testing.T) {
	desired := nicSpec(&pb.NetworkAttachment{SpoofGuard: "on"})
	live := nicSpec(&pb.NetworkAttachment{})
	p := Classify(desired, live, StoredDisksFromSpec(live))
	d, ok := metaFields(p)[NICGuardFieldPrefix+"0"]
	if !ok || d.Old != "unset" {
		t.Fatalf("delta = %+v (ok=%v), want unset→on", d, ok)
	}
	if len(p.Weakens) != 0 {
		t.Errorf("guarding an unguarded NIC weakens nothing, got %v", p.Weakens)
	}
}

// The comparison is on the canonical address list the record stores, so an
// unchanged file re-applied to the guard it created is no change.
func TestClassify_GuardAddressesCompareCanonically(t *testing.T) {
	desired := nicSpec(&pb.NetworkAttachment{SpoofGuard: "ON", AllowedAddresses: []string{" 10.0.0.9 ", "10.0.1.0/24", "10.0.0.9", "10.0.2.7/16"}})
	live := nicSpec(&pb.NetworkAttachment{SpoofGuard: "on", AllowedAddresses: []string{"10.0.0.9", "10.0.0.0/16", "10.0.1.0/24"}})
	if p := Classify(desired, live, StoredDisksFromSpec(live)); p.Max() != ActionNoChange {
		t.Fatalf("an equivalent guard read as drift: %s", p.Reasons())
	}
}

// OverlayLiveNICSecurity puts what the firewall enforces in place of the
// create-time values: by MAC, else (a spec with no MAC) by position and
// network. No guard record is an unguarded NIC.
func TestOverlayLiveNICSecurity(t *testing.T) {
	stored := &pb.VMSpec{Network: []*pb.NetworkAttachment{
		{Name: "lan", Mac: "52:54:00:00:00:01", SecurityGroups: []string{"web"}, SpoofGuard: "on", AllowVlanTags: true},
		{Name: "core", SecurityGroups: []string{"db"}, SpoofGuard: "off"},
		{Name: "gone", SecurityGroups: []string{"x"}, SpoofGuard: "on"},
	}}
	live := []LiveNIC{
		{Network: "core", MAC: "52:54:00:00:00:02", Ordinal: 1}, // no record, no groups
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

// Build carries the weakening into the op's warning, which `lv compose diff`
// and the deploy plan print.
func TestBuild_ARuntimeGroupUnbindIsAWarning(t *testing.T) {
	def := createdDef()
	def.Network = []NetworkAttachment{{Name: "lan", SecurityGroups: []string{"web"}}}
	stored := storedAsCreated()
	stored.Network[0].SecurityGroups = []string{"web", "isolate"}
	plan := buildWithStored(t, def, stored)
	if len(plan.Ops) != 1 || plan.Ops[0].Kind != OpUpdate {
		t.Fatalf("ops = %+v, want one update", plan.Ops)
	}
	if !strings.Contains(plan.Ops[0].Warning, "isolate") {
		t.Errorf("warning %q does not name the group the update unbinds", plan.Ops[0].Warning)
	}
}
