package contract

import (
	"bytes"
	"encoding/json"
	"math"
	"strings"
	"testing"
)

// Retained consumer facts only: these fixtures are not native issuer permits.
func targetContractFixture(t *testing.T, kind string) (Decision, Projection) {
	t.Helper()
	key := TargetKey{Kind: "vm_name", Name: "machine"}
	expected := TargetPredecessor{Kind: "none"}
	snapshot := OrdinarySnapshot{CreatedAt: "old-lifetime", HostName: "node", IdentityHash: strings.Repeat("a", 64)}
	config := VMIntent{Name: "machine", CPU: 2, MemoryMiB: 1024}
	c := Command{Kind: kind, ClusterUID: "cluster", ProjectUID: "project", PrincipalID: "principal", RequestID: "request"}
	if kind == LegacyRebuildCommand {
		c.Body, _ = json.Marshal(LegacyRebuildBody{Version: 1, Name: "machine", ProjectName: "acme", Snapshot: snapshot, Expected: expected, Keys: []TargetKey{key}})
	} else {
		c.Body, _ = json.Marshal(OrdinaryCreateBody{Version: 1, Desired: config, Expected: expected, Keys: []TargetKey{key}})
	}
	frontier, err := TargetJournalDigest("", "idle", []TargetJournalStep{})
	if err != nil {
		t.Fatal(err)
	}
	prep := TargetPreparation{Key: key, Expected: expected, EvidenceID: "evidence", Host: TargetHostFact{Host: "node", AdmittedAt: "2026-10-20T00:00:00Z", AdmissionSerial: "serial"}, DomainUUID: "11111111-1111-4111-8111-111111111111", JournalState: "idle", JournalSteps: []TargetJournalStep{}, JournalFrontierDigest: frontier, OwnerPreparationID: "owner-preparation", EffectScopeDigest: strings.Repeat("b", 64)}
	if kind == LegacyRebuildCommand {
		prep.Snapshot = &snapshot
	}
	maxCPU := uint32(2)
	maxMemory := uint64(1024)
	resolved := config
	resolved.MaxCPU = &maxCPU
	resolved.MemoryHotplugMaxMiB = &maxMemory
	resolved.Placement = &PlacementIntent{Policy: "balanced"}
	resolved.RequestedState = "running"
	target := &TargetAssignment{Version: 1, AttemptID: "attempt", ParentSequence: 6, ParentDigest: strings.Repeat("c", 64), MembershipGeneration: 1, ConfigDigest: strings.Repeat("d", 64), Project: TargetProjectFact{Name: "acme", Kind: "project", Lifetime: "project-lifetime", CertifiedUID: "project"}, Permission: PermissionFacts{Purpose: "legacy_rebuild", PrincipalUID: "principal", ClusterUID: "cluster", ProjectUID: "project", ProjectName: "acme", ResourceName: "machine", Verb: "vm.rebuild", EvidenceID: "permission", CoverageDigest: strings.Repeat("e", 64), FenceSequence: 6}, Preparations: []TargetPreparation{prep}, Configuration: resolved}
	if kind == OrdinaryCreateCommand {
		target.Permission.Purpose = "ordinary_create"
		target.Permission.Verb = "vm.create"
		target.Allocation = &OrdinaryAllocation{ResourceUID: "allocated", DomainUUID: prep.DomainUUID, Incarnation: "incarnation", NameGeneration: 1, Revision: "revision"}
	}
	assignment, _ := json.Marshal(Assignment{Version: 1, ClusterUID: "cluster", OperationID: "operation", RecordedAt: "2026-10-20T00:00:00Z", Target: target})
	d := Decision{Sequence: 7, ParentDigest: target.ParentDigest, Command: c, Assignment: assignment}
	p := Projection{Head: Prefix{ClusterUID: "cluster", Sequence: 6, Digest: d.ParentDigest}, Target: &TargetProjection{Keys: []TargetKeyProjection{{Key: key}}, Project: &IdentityRecord{ClusterUID: "cluster", Kind: "project", UID: "project", Alias: "acme", Witness: "project-lifetime", Generation: 1}, Principal: &IdentityRecord{ClusterUID: "cluster", Kind: "principal", UID: "principal", Witness: "principal-lifetime", Generation: 1}}}
	return d, p
}
func changeTargetAssignment(t *testing.T, d Decision, f func(*TargetAssignment)) Decision {
	t.Helper()
	var a Assignment
	if err := json.Unmarshal(d.Assignment, &a); err != nil {
		t.Fatal(err)
	}
	f(a.Target)
	d.Assignment, _ = json.Marshal(a)
	return d
}

func TestLegacyTargetDecodeExactFields(t *testing.T) {
	for _, kind := range []string{LegacyRebuildCommand, OrdinaryCreateCommand} {
		t.Run(kind, func(t *testing.T) {
			d, _ := targetContractFixture(t, kind)
			if err := ValidateSupportedDecision(d); err != nil {
				t.Fatal("valid retained packet refused", err)
			}
			for _, change := range []struct{ name, from, to string }{{"case", "\"version\":1", "\"Version\":1"}, {"null", "\"version\":1", "\"version\":null"}, {"fraction", "\"version\":1", "\"version\":1.5"}, {"duplicate", "\"version\":1", "\"version\":1,\"version\":1"}, {"unknown", "\"version\":1", "\"version\":1,\"future\":0"}} {
				t.Run(change.name, func(t *testing.T) {
					bad := d
					bad.Command.Body = []byte(strings.Replace(string(d.Command.Body), change.from, change.to, 1))
					if Code(ValidateSupportedDecision(bad)) != CodeValidation {
						t.Fatal("nonexact body accepted")
					}
				})
			}
			for _, change := range []struct {
				name string
				fn   func(*TargetAssignment)
			}{{"host-negative", func(a *TargetAssignment) { a.Preparations[0].Host.Incarnation = -1 }}, {"parent", func(a *TargetAssignment) { a.ParentSequence++ }}, {"project", func(a *TargetAssignment) { a.Project.CertifiedUID = "foreign" }}, {"secret", func(a *TargetAssignment) { a.PayloadID = "secret" }}, {"journal", func(a *TargetAssignment) { a.Preparations[0].JournalFrontierDigest = strings.Repeat("f", 64) }}, {"host-time", func(a *TargetAssignment) { a.Preparations[0].Host.AdmittedAt = "not-time" }}, {"membership-overflow", func(a *TargetAssignment) { a.MembershipGeneration = math.MaxUint64 }}} {
				t.Run(change.name, func(t *testing.T) {
					if Code(ValidateSupportedDecision(changeTargetAssignment(t, d, change.fn))) != CodeValidation {
						t.Fatal("confused assignment accepted")
					}
				})
			}
		})
	}
}
func TestLegacyTargetRequestScope(t *testing.T) {
	d, p := targetContractFixture(t, LegacyRebuildCommand)
	r, err := Reduce(p, d)
	if err != nil || r.Receipt.State != "accepted" {
		t.Fatal(r, err)
	}
	other := d
	other.Command.PrincipalID = "other"
	if Scope(d) == Scope(other) {
		t.Fatal("ordinary principals shared request scope")
	}
	p.Existing = &Request{Identity: r.Identity, Receipt: r.Receipt}
	p.Target = nil
	retry, err := Reduce(p, d)
	if err != nil || retry.Receipt != r.Receipt || retry.TargetEffect != nil || len(retry.TargetReservations) != 0 {
		t.Fatal("exact retry reacquired keys", err)
	}
	changed := d
	changed.Command.Body = bytes.ReplaceAll(d.Command.Body, []byte("old-lifetime"), []byte("replacement-lifetime"))
	changed = changeTargetAssignment(t, changed, func(a *TargetAssignment) { a.Preparations[0].Snapshot.CreatedAt = "replacement-lifetime" })
	conflict, err := Reduce(p, changed)
	if err != nil || conflict.Receipt.Code != CodeIdempotencyConflict {
		t.Fatal("changed snapshot reused receipt", err)
	}
}
func TestLegacyTargetOrdinaryPredecessors(t *testing.T) {
	d, p := targetContractFixture(t, LegacyRebuildCommand)
	r, err := Reduce(p, d)
	if err != nil || r.Receipt.State != "accepted" || r.IdentityEffect != nil || r.ResourceEffect != nil || r.OwnerEffect != nil || r.TargetEffect == nil || len(r.TargetReservations) != 1 {
		t.Fatal("no-binding L invented identity or failed reservation", r, err)
	}
	p.Target = nil
	if _, err := Reduce(p, d); Code(err) != CodeUnavailable {
		t.Fatal("nil target projection became absence", err)
	}
	d, p = targetContractFixture(t, LegacyRebuildCommand)
	var b LegacyRebuildBody
	_ = json.Unmarshal(d.Command.Body, &b)
	b.Expected = TargetPredecessor{Kind: "unowned", ResourceUID: "existing", NameGeneration: 2, Incarnation: "old-incarnation", Revision: "old-revision"}
	d.Command.Body, _ = json.Marshal(b)
	d = changeTargetAssignment(t, d, func(a *TargetAssignment) {
		a.Preparations[0].Expected = b.Expected
		a.Permission.ResourceUID = b.Expected.ResourceUID
	})
	p.Target.Keys[0].Name = &NameRecord{ClusterUID: "cluster", Name: "machine", ResourceUID: "existing", Generation: 2, Disposition: "live"}
	p.Target.Keys[0].Identity = &IdentityRecord{ClusterUID: "cluster", ProjectUID: "project", Kind: "vm", UID: "existing", Alias: "machine", Witness: "old-incarnation", Generation: 2}
	p.Target.Keys[0].Resource = &ResourceRecord{ClusterUID: "cluster", ProjectUID: "project", UID: "existing", Name: "machine", DomainUUID: "11111111-1111-4111-8111-111111111111", Incarnation: "old-incarnation", Revision: "old-revision"}
	r, err = Reduce(p, d)
	if err != nil || r.Receipt.ResourceUID != "existing" || r.ResourceEffect != nil || r.NameEffect != nil {
		t.Fatal("unowned L changed resource", r, err)
	}
	p.Target.Keys[0].Resource.OwnerID = "managed"
	r, err = Reduce(p, d)
	if err != nil || r.Receipt.Code != CodeOwnershipConflict || r.TargetEffect != nil {
		t.Fatal("managed target admitted", r, err)
	}
}
func TestLegacyTargetOrdering(t *testing.T) {
	d, p := targetContractFixture(t, LegacyRebuildCommand)
	p.Target.Keys[0].Reservation = &TargetReservation{ClusterUID: "cluster", Key: `["vm_name","machine"]`, OperationID: "winner", Sequence: 5}
	r, err := Reduce(p, d)
	if err != nil || r.Receipt.Code != CodeOwnershipConflict || r.TargetEffect != nil {
		t.Fatal("TARGET_RESERVATION: competing L crossed an occupied target", r, err)
	}
	p.Target.Keys[0].Reservation.Key = `["vm_name","other"]`
	if _, err := Reduce(p, d); Code(err) != CodeUnavailable {
		t.Fatal("inconsistent reservation accepted", err)
	}
}
func TestOrdinaryCreateIdentity(t *testing.T) {
	d, p := targetContractFixture(t, OrdinaryCreateCommand)
	r, err := Reduce(p, d)
	if err != nil || r.Receipt.State != "accepted" || r.IdentityEffect == nil || r.IdentityEffect.Witness != "incarnation" || r.ResourceEffect == nil || r.ResourceEffect.OwnerID != "" || r.ResourceEffect.BindingGeneration != 0 || len(r.BindingEffects) != 0 || r.OwnerEffect != nil || r.AdmissionEffect != nil || r.NameEffect == nil || r.Receipt.Generation != 0 {
		t.Fatal("ordinary allocation fabricated managed authority or witness", r, err)
	}
	p.Target.AssignedIdentity = &IdentityRecord{UID: "allocated"}
	r, err = Reduce(p, d)
	if err != nil || r.Receipt.Code != CodeValidation || r.IdentityEffect != nil {
		t.Fatal("assigned UID collision accepted", r, err)
	}
}
func TestLegacyTargetEffectIsolation(t *testing.T) {
	d, p := targetContractFixture(t, LegacyRebuildCommand)
	r, err := Reduce(p, d)
	if err != nil || r.TargetEffect == nil {
		t.Fatal(err)
	}
	before := append([]byte(nil), r.TargetEffect.Assignment...)
	d.Assignment[0] = '!'
	d.Command.Body[0] = '!'
	if !bytes.Equal(before, r.TargetEffect.Assignment) || r.TargetEffect.Body[0] == '!' {
		t.Fatal("callback input mutation changed retained effect")
	}
}
func TestLegacyTargetJournalDigestGolden(t *testing.T) {
	got, err := TargetJournalDigest("", "idle", []TargetJournalStep{})
	if err != nil || got != "849d1937b9e2393fba52dbd4fa4e90db4b96fb1f16f995289bd868f6abc3a137" {
		t.Fatal("idle digest encoding drift", got, err)
	}
	got, err = TargetJournalDigest("op", "settled", []TargetJournalStep{{Name: "done", Facts: `{"a":1}`}})
	if err != nil || got != "04b0e0e01acc9616b7f9a8ff73f22a98afdc4d8520cce83ae795685282ff4662" {
		t.Fatal("settled digest encoding drift", got, err)
	}
	if _, err := TargetJournalDigest("op", "settled", []TargetJournalStep{{Name: "b", Facts: `{}`}, {Name: "a", Facts: `{}`}}); err == nil {
		t.Fatal("unsorted settled facts accepted")
	}
}

func targetExistingVMFixture(t *testing.T, kind string) (Decision, Projection) {
	t.Helper()
	if kind == "admit_create" {
		return createBindingDecision(), createBindingProjection()
	}
	if kind == "assign_identity" {
		d := identityDecision(t)
		var body IdentityEnrollment
		_ = json.Unmarshal(d.Command.Body, &body)
		body.Kind = "vm"
		body.Alias = "machine"
		d.Command.ProjectUID = "project"
		d.Command.Body, _ = json.Marshal(body)
		var a Assignment
		_ = json.Unmarshal(d.Assignment, &a)
		a.Identity.Enrollment.Kind = "vm"
		a.Identity.Enrollment.Alias = "machine"
		a.Identity.Enrollment.ProjectUID = "project"
		a.Identity.Enrollment.VM = &VMEnrollmentRuntime{Version: 1, DomainUUID: "original", Incarnation: "runtime", Revision: "revision"}
		d.Assignment, _ = json.Marshal(a)
		return d, Projection{Head: Prefix{ClusterUID: "cluster", Sequence: 1, Digest: d.ParentDigest}, Target: &TargetProjection{}, Identity: &IdentityProjection{Project: &IdentityRecord{ClusterUID: "cluster", Kind: "project", UID: "project", Witness: "project-lifetime", Generation: 1}}}
	}
	d, p := transferDecision(), ownershipProjection(t)
	if kind == "adopt_resource" {
		p.Binding.Resource.OwnerID = ""
		p.Binding.Resource.ManagementKey = ""
		p.Binding.Resource.BindingGeneration = 0
		p.Binding.Resource.OriginalOperationID = ""
		p.Binding.Resource.LastOperationID = "migration-operation"
		p.Binding.OriginalAdmission = nil
		p.Binding.Last = nil
		d.Command.Kind = kind
		d.Command.OwnerID = "target-owner"
		d.Command.ManagementKey = "target-key"
		d.Command.Generation = 0
		d.Command.PrincipalID = "target-principal"
		d.Command.SessionID = "target-session"
		d.Command.Session = 3
		body, _ := DecodeOwnershipBody(transferDecision().Command)
		body.Source = nil
		d.Command.Body, _ = json.Marshal(body)
		a, _ := DecodeAssignment(d)
		a.OperationID = "adopt-operation"
		a.Ownership.Quiescence.LastOperationID = "migration-operation"
		a.Ownership.Permissions = a.Ownership.Permissions[1:]
		for i := range a.Ownership.Permissions {
			a.Ownership.Permissions[i].PrincipalUID = "target-principal"
		}
		d.Assignment, _ = json.Marshal(a)
		p.Binding.Owner = p.Binding.TargetOwner
		p.Binding.Principal = p.Binding.TargetPrincipal
	}
	return d, p
}
func TestLegacyTargetExistingVMOrdering(t *testing.T) {
	for _, kind := range []string{"assign_identity", "admit_create", "adopt_resource", "transfer_owner"} {
		t.Run(kind, func(t *testing.T) {
			d, p := targetExistingVMFixture(t, kind)
			positive, err := Reduce(p, d)
			if err != nil || positive.Receipt.Code != "" || positive.ResourceEffect == nil {
				t.Fatal("ordinary handler positive fixture refused", positive, err)
			}
			key := TargetKey{Kind: "vm_name", Name: "machine"}
			encoded, _ := TargetKeyEncoding(key)
			p.Target = &TargetProjection{Keys: []TargetKeyProjection{{Key: key, Reservation: &TargetReservation{ClusterUID: "cluster", Key: encoded, OperationID: "earlier-L", Sequence: 1}}}}
			r, err := Reduce(p, d)
			if err != nil || r.Receipt.Code != CodeOwnershipConflict || r.IdentityEffect != nil || r.ResourceEffect != nil || r.NameEffect != nil || r.AdmissionEffect != nil || len(r.BindingEffects) != 0 {
				t.Fatal("TARGET_VM_ORDER: VM handler crossed earlier L reservation", r, err)
			}
			p.Target.Keys[0].Key.Name = "other"
			p.Target.Keys[0].Reservation.Key = `["vm_name","other"]`
			r, err = Reduce(p, d)
			if err != nil || r.Receipt.Code != "" || r.ResourceEffect == nil {
				t.Fatal("unrelated name was globally blocked", r, err)
			}
			p.Target = nil
			if _, err := Reduce(p, d); Code(err) != CodeUnavailable {
				t.Fatal("VM handler treated nil target facts as no reservation", err)
			}
		})
	}
}
func TestOrdinaryCreateRetiredPredecessor(t *testing.T) {
	d, p := targetContractFixture(t, OrdinaryCreateCommand)
	var body OrdinaryCreateBody
	_ = json.Unmarshal(d.Command.Body, &body)
	body.Expected = TargetPredecessor{Kind: "retired", ResourceUID: "old", NameGeneration: 4, Incarnation: "old-incarnation", Revision: "old-revision", RetirementOperationID: "retire"}
	d.Command.Body, _ = json.Marshal(body)
	d = changeTargetAssignment(t, d, func(a *TargetAssignment) {
		a.Preparations[0].Expected = body.Expected
		a.Permission.ResourceUID = "old"
		a.Allocation.NameGeneration = 5
	})
	f := &p.Target.Keys[0]
	f.Name = &NameRecord{ClusterUID: "cluster", Name: "machine", ResourceUID: "old", Generation: 4, Disposition: "reusable", RetirementOperationID: "retire"}
	f.Identity = &IdentityRecord{ClusterUID: "cluster", ProjectUID: "project", Kind: "vm", UID: "old", Alias: "machine", Witness: "old-incarnation", Generation: 4, Retired: true}
	f.Resource = &ResourceRecord{ClusterUID: "cluster", ProjectUID: "project", UID: "old", Name: "machine", DomainUUID: "old-domain", Incarnation: "old-incarnation", Revision: "old-revision", Retired: true}
	r, err := Reduce(p, d)
	if err != nil || r.Receipt.Code != "" || r.NameEffect == nil || r.NameEffect.Generation != 5 || r.IdentityEffect.Witness != r.ResourceEffect.Incarnation {
		t.Fatal("exact retired predecessor refused", r, err)
	}
	f.Name.RetirementOperationID = "different"
	if _, err := Reduce(p, d); Code(err) != CodeUnavailable {
		t.Fatal("wrong retirement certificate treated reusable", err)
	}
}
func TestLegacyTargetKeyGrammarAndAtomicity(t *testing.T) {
	d, p := targetContractFixture(t, LegacyRebuildCommand)
	var body LegacyRebuildBody
	_ = json.Unmarshal(d.Command.Body, &body)
	artifact := TargetKey{Kind: "artifact", Artifact: &TargetArtifactKey{OwnerKind: "pool", OwnerUID: "pool-uid", ObjectID: "positive-object"}}
	body.Keys = append([]TargetKey{artifact}, body.Keys...)
	d.Command.Body, _ = json.Marshal(body)
	d = changeTargetAssignment(t, d, func(a *TargetAssignment) {
		extra := a.Preparations[0]
		extra.Key = artifact
		extra.DomainUUID = ""
		extra.Snapshot = nil
		a.Preparations = append([]TargetPreparation{extra}, a.Preparations...)
	})
	p.Target.Keys = append([]TargetKeyProjection{{Key: artifact}}, p.Target.Keys...)
	r, err := Reduce(p, d)
	if err != nil || r.Receipt.Code != "" || len(r.TargetReservations) != 2 {
		t.Fatal("disjoint two-key retained admission refused", r, err)
	}
	encoded, _ := TargetKeyEncoding(artifact)
	p.Target.Keys[0].Reservation = &TargetReservation{ClusterUID: "cluster", Key: encoded, OperationID: "winner", Sequence: 4}
	r, err = Reduce(p, d)
	if err != nil || r.Receipt.Code != CodeOwnershipConflict || len(r.TargetReservations) != 0 || r.TargetEffect != nil {
		t.Fatal("partial acquisition escaped artifact contention", r, err)
	}
	body.Keys[0], body.Keys[1] = body.Keys[1], body.Keys[0]
	bad := d
	bad.Command.Body, _ = json.Marshal(body)
	if Code(ValidateSupportedCommand(bad.Command)) != CodeValidation {
		t.Fatal("noncanonical key order accepted")
	}
	body.Keys = []TargetKey{{Kind: "artifact", Name: "not-empty", Artifact: artifact.Artifact}}
	bad.Command.Body, _ = json.Marshal(body)
	if Code(ValidateSupportedCommand(bad.Command)) != CodeValidation {
		t.Fatal("variant-confused artifact accepted")
	}
}
func TestLegacyTargetHistoricalAssignmentBytes(t *testing.T) {
	a := Assignment{Version: 1, ClusterUID: "cluster", OperationID: "op", RecordedAt: "2026-10-20T00:00:00Z"}
	b, err := json.Marshal(a)
	if err != nil || string(b) != `{"version":1,"cluster_uid":"cluster","operation_id":"op","recorded_at":"2026-10-20T00:00:00Z"}` {
		t.Fatal("appended target changed historical assignment", string(b), err)
	}
}

func TestLegacyTargetScopeDigestGolden(t *testing.T) {
	d, _ := targetContractFixture(t, LegacyRebuildCommand)
	var a Assignment
	if err := json.Unmarshal(d.Assignment, &a); err != nil {
		t.Fatal(err)
	}
	p := a.Target.Preparations[0]
	got := TargetPreparationScopeDigest(p)
	if got != "e07d141611f82aa34596840ce26aebc79237bd5f06f6d416c17122308dd9eb9c" {
		t.Fatal("scope preimage drift", got)
	}
	p.Host.Incarnation++
	if TargetPreparationScopeDigest(p) == got {
		t.Fatal("scope lost host incarnation")
	}
	// External owner evidence is not silently promoted to a permit or verified
	// solely because the contract can compute an encoding digest.
	a.Target.Preparations[0].EffectScopeDigest = strings.Repeat("f", 64)
	d.Assignment, _ = json.Marshal(a)
	if err := ValidateSupportedDecision(d); err != nil {
		t.Fatal("well-shaped retained external evidence was treated as a local permit", err)
	}
}

func TestLegacyTargetRefusesNullAndSecretVariants(t *testing.T) {
	d, _ := targetContractFixture(t, LegacyRebuildCommand)
	for _, change := range []struct{ name, from, to string }{{"epoch-absent", `"owner_epoch":0,`, ``}, {"epoch-null", `"owner_epoch":0`, `"owner_epoch":null`}, {"steps-null", `"journal_steps":[]`, `"journal_steps":null`}, {"wrong-target-case", `"target":{`, `"Target":{`}, {"fractional-epoch", `"owner_epoch":0`, `"owner_epoch":0.5`}, {"overflow-epoch", `"owner_epoch":0`, `"owner_epoch":9223372036854775808`}} {
		t.Run(change.name, func(t *testing.T) {
			bad := d
			bad.Assignment = []byte(strings.Replace(string(d.Assignment), change.from, change.to, 1))
			if Code(ValidateSupportedDecision(bad)) != CodeValidation {
				t.Fatal("ambiguous assignment decoded")
			}
		})
	}
	t.Run("preparation-byte-bound", func(t *testing.T) {
		bad := d
		bad.Assignment = []byte(strings.Replace(string(d.Assignment), `"preparations":[`, `"preparations":[`+strings.Repeat(" ", MaxTargetPreparationBytes), 1))
		if Code(ValidateSupportedDecision(bad)) != CodeValidation {
			t.Fatal("retained raw preparation whitespace bypassed byte bound")
		}
	})
	t.Run("snapshot-null", func(t *testing.T) {
		bad := d
		var a map[string]json.RawMessage
		_ = json.Unmarshal(d.Assignment, &a)
		var target map[string]json.RawMessage
		_ = json.Unmarshal(a["target"], &target)
		var preps []map[string]json.RawMessage
		_ = json.Unmarshal(target["preparations"], &preps)
		preps[0]["snapshot"] = json.RawMessage("null")
		target["preparations"], _ = json.Marshal(preps)
		a["target"], _ = json.Marshal(target)
		bad.Assignment, _ = json.Marshal(a)
		if Code(ValidateSupportedDecision(bad)) != CodeValidation {
			t.Fatal("explicit null snapshot accepted")
		}
	})
	for _, which := range []string{"owner", "session", "ciphertext", "resource"} {
		t.Run(which, func(t *testing.T) {
			bad := d
			switch which {
			case "owner":
				bad.Command.OwnerID = "fake"
			case "session":
				bad.Command.Session = 1
			case "ciphertext":
				bad.Command.Ciphertext = []byte{1}
			case "resource":
				bad.Command.ResourceUID = "pseudo-uid"
			}
			if Code(ValidateSupportedCommand(bad.Command)) != CodeValidation {
				t.Fatal("ordinary command acquired incompatible authority shape")
			}
		})
	}
}
