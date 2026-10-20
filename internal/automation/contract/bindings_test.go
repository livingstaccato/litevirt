package contract

import (
	"encoding/json"
	"strings"
	"testing"
)

func createBindingCommand() Command {
	return Command{Kind: "admit_create", ClusterUID: "cluster", ProjectUID: "project", PrincipalID: "principal", OwnerID: "owner", ManagementKey: "machine", RequestID: "create-request", Session: 1, SessionID: "session", Body: []byte(`{"version":1,"desired":{"name":"machine","cpu":2,"memory_mib":1024}}`)}
}

func TestAutomationBindingCreateSchema(t *testing.T) {
	c := createBindingCommand()
	if err := ValidateSupportedCommand(c); err != nil {
		t.Fatalf("strict create intent not supported: %v", err)
	}
	for _, body := range []string{
		`{"version":1,"desired":{"name":"machine","cpu":0,"memory_mib":1024}}`,
		`{"version":1,"desired":{"name":"machine","cpu":2,"memory_mib":0}}`,
		`{"version":1,"desired":{"name":"machine","cpu":2,"memory_mib":1024,"bootstrap":{"user_data":"secret"}}}`,
		`{"version":1,"desired":{"Name":"machine","cpu":2,"memory_mib":1024}}`,
		`{"version":1,"desired":{"name":"machine","cpu":2,"memory_mib":1024,"max_cpu":null}}`,
		`{"version":1,"desired":{"name":"../machine","cpu":2,"memory_mib":1024}}`,
		`{"version":1,"desired":{"name":"machine","cpu":2,"memory_mib":1024,"image":{"selector":{"scope":{"cluster_uid":"cluster","global":true,"project_uid":"project"},"name":"image"}}}}`,
	} {
		c.Body = []byte(body)
		if err := ValidateSupportedCommand(c); Code(err) != CodeValidation {
			t.Errorf("invalid binding intent accepted or misclassified: %s: %v", body, err)
		}
	}
	c = createBindingCommand()
	c.ManagementKey = strings.Repeat("x", MaxStringBytes+1)
	if err := ValidateSupportedCommand(c); Code(err) != CodeValidation {
		t.Fatal("oversized binding key accepted", err)
	}
}

func TestAutomationBindingCannotInheritControlAssignment(t *testing.T) {
	d := Decision{Sequence: 2, ParentDigest: strings.Repeat("a", 64), Command: createBindingCommand(), Assignment: []byte(`{"version":1,"cluster_uid":"cluster","operation_id":"create-operation","recorded_at":"2026-10-18T00:00:00Z"}`)}
	if err := ValidateSupportedDecision(d); Code(err) != CodeValidation {
		t.Fatalf("create inherited generic control assignment: %v", err)
	}
	if r, err := Reduce(Projection{Head: Prefix{ClusterUID: "cluster", Sequence: 1, Digest: d.ParentDigest}}, d); err == nil {
		t.Fatalf("missing binding assignment produced generic success: %+v", r)
	}
}

func createBindingDecision() Decision {
	return Decision{Sequence: 7, ParentDigest: strings.Repeat("a", 64), Command: createBindingCommand(), Assignment: []byte(`{"version":1,"cluster_uid":"cluster","operation_id":"create-operation","recorded_at":"2026-10-18T00:00:00Z","binding":{"resource_uid":"resource-uid","binding_generation":1,"name_generation":1,"revision":"rev:opaque-alpha","domain_uuid":"domain-uuid","incarnation":"runtime-incarnation","admitted_generation":1,"configuration":{"name":"machine","cpu":2,"memory_mib":1024,"max_cpu":2,"memory_hotplug_max_mib":1024,"placement":{"policy":"balanced"},"requested_state":"running"}}}`)}
}
func TestAutomationBindingAssignmentSchema(t *testing.T) {
	d := createBindingDecision()
	if err := ValidateSupportedDecision(d); err != nil {
		t.Fatal("valid prepared binding refused", err)
	}
	for _, change := range []struct{ from, to string }{
		{`"binding_generation":1`, `"binding_generation":2`},
		{`"name_generation":1`, `"name_generation":0`},
		{`"admitted_generation":1`, `"admitted_generation":0`},
		{`"domain_uuid":"domain-uuid"`, `"domain_uuid":""`},
		{`"cpu":2`, `"cpu":3`},
		{`"max_cpu":2,`, ``},
		{`"configuration":{`, `"configuration":{"effective_seed":"secret",`},
	} {
		bad := d
		bad.Assignment = []byte(strings.Replace(string(d.Assignment), change.from, change.to, 1))
		if err := ValidateSupportedDecision(bad); Code(err) != CodeValidation {
			t.Fatalf("bad prepared binding accepted: %s: %v", bad.Assignment, err)
		}
	}
}

func createBindingProjection() Projection {
	return Projection{Target: &TargetProjection{}, Head: Prefix{ClusterUID: "cluster", Sequence: 6}, Binding: &BindingProjection{
		Project:   &IdentityRecord{ClusterUID: "cluster", Kind: "project", UID: "project", Alias: "acme", Witness: "project-lifetime", Generation: 1},
		Principal: &IdentityRecord{ClusterUID: "cluster", Kind: "principal", UID: "principal", Alias: "alice", Witness: "principal-lifetime", Generation: 1},
		Owner:     &OwnerRecord{ClusterUID: "cluster", ProjectUID: "project", OwnerID: "owner", FounderPrincipalUID: "principal", SessionPrincipalUID: "principal", SessionID: "session", Activation: 1},
	}}
}
func noBindingEffects(r Reduction) bool {
	return r.ResourcePrevious == nil && r.IdentityEffect == nil && r.ResourceEffect == nil && r.NameEffect == nil && len(r.BindingEffects) == 0 && r.AdmissionEffect == nil
}
func TestAutomationBindingCreateAtomicFacts(t *testing.T) {
	d := createBindingDecision()
	p := createBindingProjection()
	r, err := Reduce(p, d)
	if err != nil || r.Receipt.Code != "" || r.Receipt.State != "accepted" || r.Receipt.ResourceUID != "resource-uid" || r.Receipt.Generation != 1 || r.Receipt.ResourceRevision != "rev:opaque-alpha" || r.IdentityEffect == nil || r.ResourceEffect == nil || r.NameEffect == nil || len(r.BindingEffects) != 1 || r.AdmissionEffect == nil {
		t.Fatalf("create did not produce complete atomic admission: %+v %v", r, err)
	}
	if r.ResourceEffect.UID == r.ResourceEffect.DomainUUID || r.ResourceEffect.DomainUUID != "domain-uuid" || r.ResourceEffect.Incarnation != "runtime-incarnation" || r.ResourceEffect.LastOperationID != r.Receipt.OperationID || r.NameEffect.ResourceUID != r.ResourceEffect.UID || r.NameEffect.Disposition != "reserved" || r.BindingEffects[0].ResourceUID != r.ResourceEffect.UID || r.AdmissionEffect.PrincipalUID != "principal" || r.AdmissionEffect.BindingGeneration != 1 {
		t.Fatalf("admitted identity counters/operation drift: %+v", r)
	}
	p.Existing = &Request{Identity: r.Identity, Receipt: r.Receipt}
	p.Operation = &r.Receipt
	d.Command.Session = 2
	d.Command.SessionID = "successor-session"
	d.Assignment = []byte(strings.Replace(string(d.Assignment), `"resource_uid":"resource-uid"`, `"resource_uid":"candidate-uid"`, 1))
	retry, err := Reduce(p, d)
	if err != nil || retry.Receipt != r.Receipt || !noBindingEffects(retry) {
		t.Fatalf("successor retry rebound original admission: %+v %v", retry, err)
	}
}
func TestAutomationNameGlobalConflictHasNoEffects(t *testing.T) {
	p := createBindingProjection()
	p.Binding.Name = &NameRecord{ClusterUID: "cluster", Name: "machine", ResourceUID: "other-project-resource", Generation: 4, Disposition: "reserved"}
	r, err := Reduce(p, createBindingDecision())
	if err != nil || r.Receipt.Code != CodeOwnershipConflict || !noBindingEffects(r) {
		t.Fatalf("global name conflict allocated effects: %+v %v", r, err)
	}
}
func TestAutomationBindingStaleSessionHasNoEffects(t *testing.T) {
	p := createBindingProjection()
	p.Binding.Owner.Activation = 2
	p.Binding.Owner.SessionID = "successor"
	r, err := Reduce(p, createBindingDecision())
	if err != nil || r.Receipt.Code != CodeOwnershipConflict || !noBindingEffects(r) {
		t.Fatalf("stale session allocated a binding: %+v %v", r, err)
	}
}

func TestAutomationBindingRevisionIsOpaque(t *testing.T) {
	d := createBindingDecision()
	d.Assignment = []byte(strings.Replace(string(d.Assignment), `"revision":"rev:opaque-alpha"`, `"revision":"another:opaque-token"`, 1))
	if err := ValidateSupportedDecision(d); err != nil {
		t.Fatal("opaque resource revision rejected", err)
	}
}

func TestAutomationBindingLegacyRevisionCannotAuthorize(t *testing.T) {
	d := createBindingDecision()
	d.Command.ExpectedRevision = 1
	if _, err := Reduce(createBindingProjection(), d); Code(err) != CodeValidation {
		t.Fatal("legacy numeric revision accepted for business command", err)
	}
	d = createBindingDecision()
	d.Assignment = []byte(strings.Replace(string(d.Assignment), `"revision":"rev:opaque-alpha"`, `"revision":1`, 1))
	if err := ValidateSupportedDecision(d); Code(err) != CodeValidation {
		t.Fatal("numeric resource revision accepted", err)
	}
}
func TestAutomationReceiptOldEncodingPreserved(t *testing.T) {
	encoded, err := json.Marshal(Receipt{RequestID: "request", OperationID: "operation", ResourceUID: "cluster", Sequence: 1, State: "succeeded"})
	const old = `{"RequestID":"request","OperationID":"operation","ResourceUID":"cluster","Code":"","Sequence":1,"Generation":0,"Revision":0,"State":"succeeded"}`
	if err != nil || string(encoded) != old {
		t.Fatalf("old control receipt changed: %s %v", encoded, err)
	}
}

func bindingPinnedFixture(t *testing.T) (Projection, Decision) {
	t.Helper()
	p := createBindingProjection()
	d := createBindingDecision()
	body, err := DecodeCreateBindingBody(d.Command)
	if err != nil {
		t.Fatal(err)
	}
	a, err := DecodeAssignment(d)
	if err != nil {
		t.Fatal(err)
	}
	project := ReferenceScope{ClusterUID: "cluster", ProjectUID: "project"}
	global := ReferenceScope{ClusterUID: "cluster", Global: true}
	body.Desired.Image = &ReferenceInput{Selector: &ScopedSelector{Scope: project, Name: "base-image"}}
	body.Desired.NICs = []NICIntent{{Key: "net0", Network: ReferenceInput{Selector: &ScopedSelector{Scope: project, Name: "blue"}}}}
	affinity := []ResourceReference{{ClusterUID: "cluster", ProjectUID: "project", Kind: "vm", UID: "peer-uid"}}
	body.Desired.Placement = &PlacementIntent{Host: &HostInput{Name: "worker"}, Affinity: affinity}
	image := &ReferenceInput{Pinned: &PinnedReference{Scope: project, UID: "image-uid", Name: "base-image", ContentDigest: strings.Repeat("a", 64)}}
	a.Binding.Configuration.Image = image
	a.Binding.Configuration.Disks = []DiskIntent{{Key: "root", SizeBytes: 4096, Pool: &ReferenceInput{Pinned: &PinnedReference{Scope: global, UID: "pool-uid", Name: "shared"}}, Image: image, Bus: "virtio"}}
	mac := "02:00:00:00:00:01"
	a.Binding.Configuration.NICs = []NICIntent{{Key: "net0", Network: ReferenceInput{Pinned: &PinnedReference{Scope: project, UID: "network-uid", Name: "blue"}}, Model: "virtio", MAC: &mac}}
	a.Binding.Configuration.Placement = &PlacementIntent{Policy: "balanced", Host: &HostInput{Pinned: &HostReference{ClusterUID: "cluster", UID: "host-uid", Name: "worker"}}, Affinity: affinity}
	for _, entry := range []struct{ kind, uid, scope, alias string }{{"image", "image-uid", "project", "base-image"}, {"pool", "pool-uid", "", "shared"}, {"network", "network-uid", "project", "blue"}, {"host", "host-uid", "", "worker"}, {"vm", "peer-uid", "project", "peer"}} {
		p.Binding.Dependencies = append(p.Binding.Dependencies, &IdentityRecord{ClusterUID: "cluster", ProjectUID: entry.scope, Kind: entry.kind, UID: entry.uid, Alias: entry.alias, Witness: "positive-" + entry.uid, Generation: 1})
	}
	d.Command.Body, _ = json.Marshal(body)
	d.Assignment, _ = json.Marshal(a)
	return p, d
}
func TestAutomationBindingPinnedDependencies(t *testing.T) {
	p, d := bindingPinnedFixture(t)
	r, err := Reduce(p, d)
	if err != nil || r.Receipt.Code != "" || r.AdmissionEffect == nil || r.AdmissionEffect.PinnedConfiguration.Image.Pinned.UID != "image-uid" || len(r.AdmissionEffect.PinnedConfiguration.Disks) != 1 {
		t.Fatal("valid resolved dependency configuration not admitted", r.Receipt, err)
	}
	for _, mode := range []string{"retired", "wrong-uid", "wrong-kind", "wrong-project", "wrong-cluster", "zero-generation", "missing"} {
		t.Run(mode, func(t *testing.T) {
			p, d := bindingPinnedFixture(t)
			want := CodeUnavailable
			switch mode {
			case "retired":
				p.Binding.Dependencies[0].Retired = true
				want = CodeRetired
			case "wrong-uid":
				p.Binding.Dependencies[0].UID = "replacement-same-name"
			case "wrong-kind":
				p.Binding.Dependencies[0].Kind = "pool"
			case "wrong-project":
				p.Binding.Dependencies[0].ProjectUID = "other"
			case "wrong-cluster":
				p.Binding.Dependencies[0].ClusterUID = "other"
			case "zero-generation":
				p.Binding.Dependencies[0].Generation = 0
			case "missing":
				p.Binding.Dependencies = p.Binding.Dependencies[1:]
			}
			r, err := Reduce(p, d)
			code := r.Receipt.Code
			if err != nil {
				code = Code(err)
			}
			if code != want || !noBindingEffects(r) {
				t.Fatal("wrong dependency lifetime admitted", mode, r.Receipt, err)
			}
		})
	}
	p, d = bindingPinnedFixture(t)
	a, _ := DecodeAssignment(d)
	a.Binding.Configuration.Image.Pinned.Name = "other-selector-name"
	d.Assignment, _ = json.Marshal(a)
	if _, err := Reduce(p, d); Code(err) != CodeValidation {
		t.Fatal("selector preparation changed requested name", err)
	}
}
func bindingReusableFixture(t *testing.T) (Projection, Decision) {
	t.Helper()
	p := createBindingProjection()
	d := createBindingDecision()
	d.Command.Generation = 3
	a, _ := DecodeAssignment(d)
	a.Binding.BindingGeneration = 4
	a.Binding.NameGeneration = 5
	d.Assignment, _ = json.Marshal(a)
	p.Binding.Last = &BindingRecord{ClusterUID: "cluster", ProjectUID: "project", OwnerID: "owner", ManagementKey: "machine", ResourceUID: "old-resource", OperationID: "old-create", Generation: 3, Revision: "old-revision", Retired: true}
	p.Binding.Name = &NameRecord{ClusterUID: "cluster", Name: "machine", ResourceUID: "old-resource", Generation: 4, Disposition: "reusable", RetirementOperationID: "cleanup-operation"}
	p.Binding.Resource = &ResourceRecord{ClusterUID: "cluster", ProjectUID: "project", UID: "old-resource", Name: "machine", DomainUUID: "old-domain", Incarnation: "old-incarnation", Revision: "old-revision", Retired: true}
	p.Binding.NameIdentity = &IdentityRecord{ClusterUID: "cluster", ProjectUID: "project", Kind: "vm", UID: "old-resource", Alias: "machine", Witness: "old-incarnation", Generation: 4, Retired: true}
	return p, d
}
func TestAutomationBindingReusableNameRequiresExactRetirement(t *testing.T) {
	p, d := bindingReusableFixture(t)
	r, err := Reduce(p, d)
	if err != nil || r.Receipt.Code != "" || r.NameEffect == nil || r.NameEffect.Generation != 5 || r.Receipt.Generation != 4 {
		t.Fatal("ordered name/binding reuse failed", r.Receipt, err)
	}
	for _, mode := range []string{"missing-cleanup", "resource-live", "identity-live", "identity-generation", "name-generation", "same-incarnation", "name-live", "binding-generation"} {
		t.Run(mode, func(t *testing.T) {
			p, d := bindingReusableFixture(t)
			want := CodeUnavailable
			switch mode {
			case "missing-cleanup":
				p.Binding.Name.RetirementOperationID = ""
			case "resource-live":
				p.Binding.Resource.Retired = false
			case "identity-live":
				p.Binding.NameIdentity.Retired = false
			case "identity-generation":
				p.Binding.NameIdentity.Generation = 3
			case "name-generation":
				a, _ := DecodeAssignment(d)
				a.Binding.NameGeneration = 6
				d.Assignment, _ = json.Marshal(a)
				want = CodeRevisionConflict
			case "same-incarnation":
				p.Binding.Resource.Incarnation = "runtime-incarnation"
				want = CodeValidation
			case "name-live":
				p.Binding.Name.Disposition = "live"
				want = CodeOwnershipConflict
			case "binding-generation":
				p.Binding.Last.Generation = 4
				want = CodeRevisionConflict
			}
			r, err := Reduce(p, d)
			code := r.Receipt.Code
			if err != nil {
				code = Code(err)
			}
			if code != want || !noBindingEffects(r) {
				t.Fatal("unproven name reuse admitted", mode, r.Receipt, err)
			}
		})
	}
}
