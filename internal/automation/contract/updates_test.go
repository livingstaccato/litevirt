package contract

import (
	"encoding/json"
	"math"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// Removing the update dispatch must fail this real Reduce assertion.
func updateContractFixture(t *testing.T, prepare ...func(*Projection, *Decision)) (Projection, Decision) {
	p, create := bindingPinnedFixture(t)
	for _, fn := range prepare {
		fn(&p, &create)
	}
	born, err := Reduce(p, create)
	if err != nil || born.Receipt.Code != "" {
		t.Fatal("positive create predecessor", born.Receipt, err)
	}
	p.Head = Prefix{ClusterUID: "cluster", Sequence: 7, Digest: strings.Repeat("b", 64)}
	p.Binding.Resource = born.ResourceEffect
	p.Binding.Last = &born.BindingEffects[0]
	p.Binding.Name = born.NameEffect
	p.Binding.NameIdentity = born.IdentityEffect
	p.Binding.OriginalAdmission = born.AdmissionEffect
	d := Decision{Sequence: 8, ParentDigest: p.Head.Digest, Command: create.Command}
	d.Command.Kind = "admit_update"
	d.Command.ResourceUID = "resource-uid"
	d.Command.Generation = 1
	d.Command.RequestID = "update-request"
	d.Command.Body = []byte(`{"version":1,"resource":{"cluster_uid":"cluster","project_uid":"project","kind":"vm","uid":"resource-uid"},"expected_revision":"rev:opaque-alpha","patch":{"labels":{"values":{}}},"permitted_disruption":"live"}`)
	config := *born.AdmissionEffect.PinnedConfiguration
	config.Labels = map[string]string{}
	ref := map[string]any{"sequence": 7, "digest": p.Head.Digest}
	facts := map[string]any{"version": 1, "resource_uid": "resource-uid", "revision": "rev:opaque-alpha", "incarnation": "runtime-incarnation", "last_operation_id": "create-operation", "runtime_owner_epoch": 1, "fence_sequence": 7, "evidence_id": "fixture-quiescence", "coverage_digest": strings.Repeat("c", 64)}
	applicability := map[string]any{"version": 1, "resource_uid": "resource-uid", "domain_uuid": "domain-uuid", "incarnation": "runtime-incarnation", "previous_revision": "rev:opaque-alpha", "previous_operation": "create-operation", "host_uid": "host-uid", "host_incarnation": "positive-host-uid", "runtime_owner_epoch": 1, "fence_sequence": 7, "evidence_id": "fixture-applicability", "coverage_digest": strings.Repeat("d", 64), "mechanism": "none", "cpu_live_min": 0, "cpu_live_max": 0, "memory_live_min_mib": 0, "memory_live_max_mib": 0, "memory_mode": "none", "cpu_pinned": false, "runtime_state": "running"}
	permission := map[string]any{"purpose": "resource", "principal_uid": "principal", "cluster_uid": "cluster", "project_uid": "project", "project_name": "acme", "owner_id": "owner", "resource_uid": "resource-uid", "resource_name": "machine", "verb": "vm.update", "evidence_id": "fixture-permission", "coverage_digest": strings.Repeat("e", 64), "fence_sequence": 7}
	d.Assignment, _ = json.Marshal(map[string]any{"version": 3, "cluster_uid": "cluster", "operation_id": "update-operation", "recorded_at": "2026-10-23T20:00:00Z", "update": map[string]any{"version": 1, "previous_desired": ref, "previous_operation": ref, "origin": ref, "revision": "rev:opaque-alpha", "admitted_generation": 1, "configuration": config, "payload_id": "", "quiescence": facts, "permissions": []any{permission}, "applicability": applicability}})
	p.Update = &UpdateProjection{PreviousDesired: born.AdmissionEffect, PreviousOperation: born.AdmissionEffect, Origin: born.AdmissionEffect, PreviousDesiredReference: HistoryReference{7, p.Head.Digest}, PreviousOperationReference: HistoryReference{7, p.Head.Digest}, OriginReference: HistoryReference{7, p.Head.Digest}, OriginResource: born.ResourceEffect}
	return p, d
}
func TestAutomationUpdateRequiredReducer(t *testing.T) {
	p, d := updateContractFixture(t)

	r, err := Reduce(p, d)
	if err != nil || r.Receipt.Code != "" || r.Receipt.State != "accepted" || r.AdmissionEffect == nil || r.AdmissionEffect.Method != "admit_update" {
		t.Fatalf("conditional no-op update must be admitted without replacing identity: receipt=%+v err=%v", r.Receipt, err)
	}
	if r.ResourceEffect == nil || r.ResourceEffect.OriginalOperationID != "create-operation" || r.ResourceEffect.Revision != "rev:opaque-alpha" || r.ResourceEffect.UID != "resource-uid" {
		t.Fatalf("update changed immutable birth or no-op revision: %+v", r.ResourceEffect)
	}
}

func updateContractEdit(t *testing.T, d *Decision, edit func(*UpdateBindingBody, *UpdateAssignment)) {
	t.Helper()
	b, e := DecodeUpdateBindingBody(d.Command)
	if e != nil {
		t.Fatal(e)
	}
	a, e := DecodeAssignment(*d)
	if e != nil {
		t.Fatal(e)
	}
	edit(&b, a.Update)
	d.Command.Body, _ = json.Marshal(b)
	d.Assignment, _ = json.Marshal(a)
}
func TestAutomationUpdatePresenceAndStrictSchema(t *testing.T) {
	_, d := updateContractFixture(t)
	for _, patch := range []string{`{}`, `{"labels":{"values":{}}}`, `{"placement":{}}`, `{"cpu":3}`, `{"memory_mib":1536}`} {
		c := d.Command
		c.Body = []byte(strings.Replace(string(c.Body), `{"labels":{"values":{}}}`, patch, 1))
		b, e := DecodeUpdateBindingBody(c)
		if e != nil {
			t.Fatal("valid patch", patch, e)
		}
		if patch == `{}` && (b.Patch.CPU != nil || b.Patch.MemoryMiB != nil || b.Patch.Labels != nil || b.Patch.Placement != nil) {
			t.Fatal("absent patch fields became present")
		}
		if patch == `{"labels":{"values":{}}}` && (b.Patch.Labels == nil || b.Patch.Labels.Values == nil) {
			t.Fatal("explicit label clear lost presence")
		}
	}
	for _, patch := range []string{`null`, `{"cpu":0}`, `{"memory_mib":0}`, `{"cpu":null}`, `{"labels":null}`, `{"labels":{}}`, `{"labels":{"values":null}}`, `{"CPU":3}`, `{"cpu":3,"cpu":4}`, `{"image":{}}`, `{"placement":{"unknown":1}}`, `{"placement":{"policy":"replacement"}}`} {
		c := d.Command
		c.Body = []byte(strings.Replace(string(c.Body), `{"labels":{"values":{}}}`, patch, 1))
		if _, e := DecodeUpdateBindingBody(c); Code(e) != CodeValidation {
			t.Fatal("bad patch accepted", patch, e)
		}
	}
	for _, change := range []struct{ from, to string }{{`"patch":{"labels":{"values":{}}},`, ``}, {`"version":1`, `"Version":1`}, {`"expected_revision":"rev:opaque-alpha"`, `"expected_revision":1`}} {
		c := d.Command
		c.Body = []byte(strings.Replace(string(c.Body), change.from, change.to, 1))
		if e := ValidateSupportedCommand(c); Code(e) != CodeValidation {
			t.Fatal("bad body accepted", string(c.Body), e)
		}
	}
	c := d.Command
	c.Body = append(c.Body, []byte(` {}`)...)
	if e := ValidateSupportedCommand(c); Code(e) != CodeValidation {
		t.Fatal("trailing body accepted")
	}
	c = d.Command
	c.Body = []byte(strings.Repeat(" ", 1<<20) + string(c.Body))
	if e := ValidateSupportedCommand(c); Code(e) != CodeValidation {
		t.Fatal("oversized body accepted")
	}
	for _, v := range []int{1, 2, 4} {
		bad := d
		var raw map[string]any
		json.Unmarshal(bad.Assignment, &raw)
		raw["version"] = v
		bad.Assignment, _ = json.Marshal(raw)
		if e := ValidateSupportedDecision(bad); Code(e) != CodeValidation {
			t.Fatal("update inherited another outer version", v, e)
		}
	}
	old := createBindingDecision()
	old.Assignment = []byte(strings.Replace(string(old.Assignment), `"version":1`, `"version":3`, 1))
	if e := ValidateSupportedDecision(old); Code(e) != CodeValidation {
		t.Fatal("create inherited update version", e)
	}
	old = createBindingDecision()
	old.Assignment = []byte(strings.Replace(string(old.Assignment), `"version":1`, `"update":{},"version":1`, 1))
	if e := ValidateSupportedDecision(old); Code(e) != CodeValidation {
		t.Fatal("old v1 admitted update member", e)
	}
}
func TestAutomationUpdateSupportedFieldsAndDisruption(t *testing.T) {
	for _, tc := range []struct {
		name, mechanism, disruption, mode, state string
		cpu                                      uint32
		memory                                   uint64
		want                                     string
		pin                                      bool
	}{
		{name: "CPU", mechanism: "live_resize", disruption: "live", mode: "none", state: "running", cpu: 3},
		{name: "balloon", mechanism: "live_resize", disruption: "live", mode: "balloon", state: "running", memory: 1537},
		{name: "virtio-even", mechanism: "live_resize", disruption: "live", mode: "virtio_mem", state: "running", memory: 1536},
		{name: "virtio-odd", mechanism: "live_resize", disruption: "live", mode: "virtio_mem", state: "running", memory: 1537, want: CodeValidation},
		{name: "virtio-stopped", mechanism: "live_resize", disruption: "live", mode: "virtio_mem", state: "stopped", memory: 1536, want: CodeValidation},
		{name: "combined", mechanism: "live_resize", disruption: "live", mode: "virtio_mem", state: "running", cpu: 3, memory: 1536},
		{name: "combined-bad-memory", mechanism: "live_resize", disruption: "live", mode: "virtio_mem", state: "running", cpu: 3, memory: 1537, want: CodeValidation},
		{name: "combined-bad-cpu", mechanism: "live_resize", disruption: "live", mode: "balloon", state: "running", cpu: 1, memory: 1536, want: CodeValidation},
		{name: "pinned", mechanism: "live_resize", disruption: "live", mode: "none", state: "running", cpu: 3, pin: true, want: CodeValidation},
		{name: "CPU-ceiling", mechanism: "live_resize", disruption: "live", mode: "none", state: "running", cpu: 5, want: CodeValidation},
		{name: "legacy-overflow", mechanism: "restart", disruption: "restart", mode: "none", state: "running", memory: math.MaxInt32 + 1, want: CodeValidation},
		{name: "none-memory", mechanism: "live_resize", disruption: "live", mode: "none", state: "running", memory: 1536, want: CodeValidation},
		{name: "restart-denied", mechanism: "restart", disruption: "live", mode: "none", state: "running", cpu: 3, want: CodeValidation},
		{name: "restart-permitted", mechanism: "restart", disruption: "restart", mode: "none", state: "stopped", cpu: 3},
		{name: "restart-permission-live", mechanism: "live_resize", disruption: "restart", mode: "balloon", state: "running", cpu: 3},
		{name: "replacement", mechanism: "replacement", disruption: "restart", mode: "none", state: "running", cpu: 3, want: CodeValidation},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, d := updateContractFixture(t)
			maxCPU, maxMemory := uint32(8), uint64(math.MaxInt32+1)
			p.Update.PreviousDesired.PinnedConfiguration.MaxCPU = &maxCPU
			p.Update.PreviousDesired.PinnedConfiguration.MemoryHotplugMaxMiB = &maxMemory
			updateContractEdit(t, &d, func(b *UpdateBindingBody, u *UpdateAssignment) {
				u.Configuration = updateClone(*p.Update.PreviousDesired.PinnedConfiguration)
				b.Patch = VMUpdatePatch{}
				b.PermittedDisruption = tc.disruption
				if tc.cpu != 0 {
					v := tc.cpu
					b.Patch.CPU = &v
					u.Configuration.CPU = v
				}
				if tc.memory != 0 {
					v := tc.memory
					b.Patch.MemoryMiB = &v
					u.Configuration.MemoryMiB = v
				}
				u.Revision = "rev:changed"
				u.Applicability.Mechanism = tc.mechanism
				u.Applicability.MemoryMode = tc.mode
				u.Applicability.RuntimeState = tc.state
				u.Applicability.CPUPinned = tc.pin
				u.Applicability.CPULiveMin = 2
				u.Applicability.CPULiveMax = 4
				u.Applicability.MemoryLiveMinMiB = 1024
				u.Applicability.MemoryLiveMaxMiB = 2048
			})
			r, e := Reduce(p, d)
			code := r.Receipt.Code
			if e != nil {
				code = Code(e)
			}
			if code != tc.want {
				t.Fatal("safe applicability mismatch", tc.name, r.Receipt, e)
			}
			if tc.want != "" && !noBindingEffects(r) {
				t.Fatal("refused applicability emitted effects")
			}
			if tc.want == "" && (r.AdmissionEffect == nil || r.Receipt.State != "accepted") {
				t.Fatal("supported dimensions missing", r, e)
			}
		})
	}
	p, d := updateContractFixture(t)
	updateContractEdit(t, &d, func(b *UpdateBindingBody, u *UpdateAssignment) {
		b.Patch = VMUpdatePatch{Labels: &UpdateLabelSet{Values: map[string]string{"role": "db"}}, Placement: &PlacementIntent{Policy: "pack", RequiredLabels: map[string]string{"zone": "a"}, PreferredLabels: map[string]string{"fast": "yes"}, MaxPerHost: 2}}
		u.Configuration.Labels = map[string]string{"role": "db"}
		u.Configuration.Placement = &PlacementIntent{Policy: "pack", RequiredLabels: map[string]string{"zone": "a"}, PreferredLabels: map[string]string{"fast": "yes"}, MaxPerHost: 2}
		u.Applicability.Mechanism = "metadata"
		u.Revision = "rev:metadata"
	})
	r, e := Reduce(p, d)
	if e != nil || r.Receipt.Code != "" || r.AdmissionEffect == nil || r.AdmissionEffect.PinnedConfiguration.Placement.MaxPerHost != 2 {
		t.Fatal("full metadata policy lost", r, e)
	}
}
func TestAutomationUpdatePreservesIdentityAndPayload(t *testing.T) {
	p, d := updateContractFixture(t)
	p.Update.Origin.PayloadID = "birth-payload"
	p.Update.PreviousDesired.PayloadID = "birth-payload"
	updateContractEdit(t, &d, func(b *UpdateBindingBody, u *UpdateAssignment) { u.PayloadID = "birth-payload" })
	r, e := Reduce(p, d)
	if e != nil || r.AdmissionEffect == nil || r.AdmissionEffect.PayloadID != "birth-payload" || r.ResourcePrevious == nil {
		t.Fatal("payload birth not retained", r, e)
	}
	before, after := *p.Binding.Resource, *r.ResourceEffect
	after.LastOperationID = before.LastOperationID
	after.AppliedSequence = before.AppliedSequence
	if !reflect.DeepEqual(before, after) || r.IdentityEffect != nil || r.NameEffect != nil || r.ExecutorEffect != nil || r.TerminalEffect != nil || r.WrappingEffect != nil || len(r.ArtifactEffects) != 0 || len(r.TargetReservations) != 0 {
		t.Fatal("update replaced identity/artifact facts", r)
	}
	for _, mode := range []string{"name", "disk", "image", "state", "payload", "origin-domain"} {
		p, d := updateContractFixture(t)
		updateContractEdit(t, &d, func(b *UpdateBindingBody, u *UpdateAssignment) {
			switch mode {
			case "name":
				u.Configuration.Name = "replacement"
			case "disk":
				u.Configuration.Disks[0].SizeBytes++
			case "image":
				u.Configuration.Image.Pinned.ContentDigest = strings.Repeat("f", 64)
			case "state":
				u.Configuration.RequestedState = "stopped"
			case "payload":
				u.PayloadID = "new-payload"
			case "origin-domain":
				p.Update.OriginResource = &ResourceRecord{DomainUUID: "replacement"}
			}
		})
		r, e := Reduce(p, d)
		if e == nil && r.Receipt.Code == "" {
			t.Fatal("immutable assignment drift admitted", mode)
		}
	}
}
func TestAutomationUpdateRevisionNoopAndRetry(t *testing.T) {
	p, d := updateContractFixture(t)
	r, e := Reduce(p, d)
	if e != nil || r.Receipt.State != "accepted" {
		t.Fatal(r, e)
	}
	p.Existing = &Request{Identity: r.Identity, Receipt: r.Receipt}
	p.Head.Sequence = 100
	p.Binding = nil
	p.Update = nil
	d.Sequence = 101
	d.Command.Session = 8
	d.Command.SessionID = "handoff"
	retry, e := Reduce(p, d)
	if e != nil || retry.Receipt != r.Receipt || !noBindingEffects(retry) || retry.SaveRequest {
		t.Fatal("exact retry consulted current predecessor", retry, e)
	}
	d.Command.Body = []byte(strings.Replace(string(d.Command.Body), `"labels":{"values":{}}`, ``, 1))
	conflict, e := Reduce(p, d)
	if e != nil || conflict.Receipt.Code != CodeIdempotencyConflict {
		t.Fatal("patch presence did not change request identity", conflict, e)
	}
	p, d = updateContractFixture(t)
	updateContractEdit(t, &d, func(b *UpdateBindingBody, u *UpdateAssignment) {
		b.ExpectedRevision = "rev:stale"
		u.Quiescence.Revision = b.ExpectedRevision
		u.Applicability.PreviousRevision = b.ExpectedRevision
	})
	stale, e := Reduce(p, d)
	if e != nil || stale.Receipt.Code != CodeRevisionConflict || !noBindingEffects(stale) {
		t.Fatal("stale no-op did not conflict", stale, e)
	}
	p, d = updateContractFixture(t)
	updateContractEdit(t, &d, func(b *UpdateBindingBody, u *UpdateAssignment) { u.Revision = "rev:unnecessary" })
	r, e = Reduce(p, d)
	if e == nil && r.Receipt.Code == "" {
		t.Fatal("no-op advanced desired revision")
	}
}
func TestAutomationUpdatePredecessorAndQuiescence(t *testing.T) {
	for _, mode := range []string{"missing", "foreign", "retired", "stale-session", "binding-generation", "origin", "previous", "quiescence", "host", "fence", "dependency", "name", "target"} {
		t.Run(mode, func(t *testing.T) {
			p, d := updateContractFixture(t)
			switch mode {
			case "missing":
				p.Update = nil
			case "foreign":
				p.Update.PreviousDesired.ProjectUID = "foreign"
			case "retired":
				p.Binding.Resource.Retired = true
			case "stale-session":
				p.Binding.Owner.Activation = 2
			case "binding-generation":
				d.Command.Generation = 2
			case "origin":
				p.Update.OriginReference.Sequence = 6
			case "previous":
				p.Update.PreviousOperationReference.Digest = strings.Repeat("f", 64)
			case "quiescence":
				updateContractEdit(t, &d, func(b *UpdateBindingBody, u *UpdateAssignment) { u.Quiescence.LastOperationID = "uncertain-worker" })
			case "host":
				updateContractEdit(t, &d, func(b *UpdateBindingBody, u *UpdateAssignment) { u.Applicability.HostIncarnation = "foreign" })
			case "fence":
				updateContractEdit(t, &d, func(b *UpdateBindingBody, u *UpdateAssignment) { u.Applicability.FenceSequence = 6 })
			case "dependency":
				p.Binding.Dependencies[0].Retired = true
			case "name":
				p.Binding.Name.Disposition = "reusable"
			case "target":
				p.Target = nil
			}
			r, e := Reduce(p, d)
			if e == nil && r.Receipt.Code == "" {
				t.Fatal("bad predecessor admitted", mode)
			}
			if !noBindingEffects(r) {
				t.Fatal("bad predecessor emitted effects", mode, r)
			}
		})
	}
}

func TestAutomationUpdateDecisionEnvelopeVersion(t *testing.T) {
	_, d := updateContractFixture(t)
	raw, e := EncodeDecision(d)
	if e != nil {
		t.Fatal("update v3 envelope must encode", e)
	}
	got, e := DecodeDecision(raw)
	if e != nil || !reflect.DeepEqual(got, d) {
		t.Fatal("update envelope round trip changed certified bytes", e)
	}
	for _, version := range []string{"1", "2", "4"} {
		bad := d
		bad.Assignment = []byte(strings.Replace(string(d.Assignment), `"version":3`, `"version":`+version, 1))
		if _, e := EncodeDecision(bad); e == nil {
			t.Fatal("update envelope inherited another outer version", version)
		}
	}
}

func TestAutomationUpdatePlacementResolvesEnrolledHost(t *testing.T) {
	for _, tamper := range []bool{false, true} {
		t.Run(strconv.FormatBool(tamper), func(t *testing.T) {
			p, d := updateContractFixture(t)
			updateContractEdit(t, &d, func(b *UpdateBindingBody, u *UpdateAssignment) {
				b.Patch = VMUpdatePatch{Placement: &PlacementIntent{Host: &HostInput{Name: "worker"}, Policy: "spread"}}
				u.Configuration.Placement = &PlacementIntent{Host: &HostInput{Pinned: &HostReference{ClusterUID: "cluster", UID: "host-uid", Name: "worker"}}, Policy: "spread"}
				u.Applicability.Mechanism = "metadata"
				u.Revision = "rev:placement"
			})
			if tamper {
				for _, r := range p.Binding.Dependencies {
					if r.UID == "host-uid" {
						r.Alias = "other-enrolled-host"
					}
				}
			}
			r, e := Reduce(p, d)
			if !tamper {
				if e != nil || r.Receipt.Code != "" || r.AdmissionEffect == nil || r.AdmissionEffect.PinnedConfiguration.Placement.Host.Pinned.UID != "host-uid" {
					t.Fatal("resolved enrolled placement host refused", r.Receipt, e)
				}
			} else if e == nil && r.Receipt.Code == "" {
				t.Fatal("host selector resolved against claimed name instead of enrolled host identity")
			}
		})
	}
}

// An ordinary allocation has certified desired/birth facts without a managed
// create admission. This pure consumer fixture does not release its reservation
// or implement the missing native adoption/enrollment producer.
func TestAutomationUpdateOrdinaryOriginDesiredConfiguration(t *testing.T) {
	p, d := updateContractFixture(t)
	originDecision, originProjection := targetContractFixture(t, OrdinaryCreateCommand)
	originConfig := updateClone(*p.Update.Origin.PinnedConfiguration)
	originDecision.Command.Body, _ = json.Marshal(OrdinaryCreateBody{Version: 1, Desired: originConfig, Expected: TargetPredecessor{Kind: "none"}, Keys: []TargetKey{{Kind: "vm_name", Name: "machine"}}})
	a, _ := DecodeAssignment(originDecision)
	a.Target.Configuration = originConfig
	a.Target.Allocation = &OrdinaryAllocation{ResourceUID: "resource-uid", DomainUUID: "11111111-1111-4111-8111-111111111111", Incarnation: "runtime-incarnation", NameGeneration: 1, Revision: "rev:ordinary"}
	originDecision.Assignment, _ = json.Marshal(a)
	originProjection.Target.Dependencies = p.Binding.Dependencies
	original, e := Reduce(originProjection, originDecision)
	if e != nil || original.Receipt.Code != "" || original.TargetEffect == nil {
		t.Fatal("positive ordinary allocation prerequisite", original.Receipt, e)
	}
	original.TargetEffect.DecisionDigest = strings.Repeat("b", 64)
	birth := *original.ResourceEffect
	current := *p.Binding.Resource
	current.OriginalOperationID = a.OperationID
	current.LastOperationID = "ownership-op"
	current.AppliedSequence = 8
	current.Revision = "rev:adopted"
	current.DomainUUID = birth.DomainUUID
	p.Binding.Resource = &current
	p.Binding.Last.OperationID = "ownership-op"
	p.Binding.Last.Revision = current.Revision
	p.Binding.OriginalAdmission = nil
	p.Binding.OriginalTarget = original.TargetEffect
	origin := &AdmissionRecord{ClusterUID: "cluster", ProjectUID: "project", ResourceUID: "resource-uid", OperationID: a.OperationID, RequestID: originDecision.Command.RequestID, PrincipalUID: "principal", Method: OrdinaryCreateCommand, AdmittedGeneration: 1, Sequence: 7, PinnedConfiguration: &originConfig}
	predecessor := &AdmissionRecord{ClusterUID: "cluster", ProjectUID: "project", ResourceUID: "resource-uid", OperationID: "ownership-op", RequestID: "adopt-request", PrincipalUID: "principal", OwnerID: "owner", ManagementKey: "machine", Method: "adopt_resource", BindingGeneration: 1, AdmittedGeneration: 1, Sequence: 8}
	p.Head = Prefix{ClusterUID: "cluster", Sequence: 8, Digest: strings.Repeat("c", 64)}
	d.Sequence = 9
	d.ParentDigest = p.Head.Digest
	p.Update = &UpdateProjection{Origin: origin, PreviousDesired: origin, PreviousOperation: predecessor, OriginResource: &birth, OriginReference: HistoryReference{7, strings.Repeat("b", 64)}, PreviousDesiredReference: HistoryReference{7, strings.Repeat("b", 64)}, PreviousOperationReference: HistoryReference{8, p.Head.Digest}}
	updateContractEdit(t, &d, func(b *UpdateBindingBody, u *UpdateAssignment) {
		b.ExpectedRevision = current.Revision
		u.Revision = current.Revision
		u.Origin = p.Update.OriginReference
		u.PreviousDesired = p.Update.PreviousDesiredReference
		u.PreviousOperation = p.Update.PreviousOperationReference
		u.Quiescence.Revision = current.Revision
		u.Quiescence.LastOperationID = current.LastOperationID
		u.Quiescence.FenceSequence = 8
		u.Applicability.DomainUUID = current.DomainUUID
		u.Applicability.PreviousRevision = current.Revision
		u.Applicability.PreviousOperation = current.LastOperationID
		u.Applicability.FenceSequence = 8
		u.Permissions[0].FenceSequence = 8
	})
	r, e := Reduce(p, d)
	if e != nil || r.Receipt.Code != "" || r.AdmissionEffect == nil || r.ResourceEffect.OriginalOperationID != a.OperationID {
		t.Fatal("complete certified ordinary desired origin unavailable or rewritten as managed create", r.Receipt, e)
	}
	p.Update.Origin.PinnedConfiguration = nil
	if r, e = Reduce(p, d); e == nil && r.Receipt.Code == "" {
		t.Fatal("missing ordinary desired producer facts became fabricated create")
	}
}

func updatePopulatedPlacementFixture(t *testing.T) (Projection, Decision) {
	t.Helper()
	return updateContractFixture(t, func(p *Projection, d *Decision) {
		body, e := DecodeCreateBindingBody(d.Command)
		if e != nil {
			t.Fatal(e)
		}
		a, e := DecodeAssignment(*d)
		if e != nil {
			t.Fatal(e)
		}
		maxCPU, maxMemory := uint32(4), uint64(2048)
		body.Desired.MaxCPU = &maxCPU
		body.Desired.MemoryHotplugMaxMiB = &maxMemory
		a.Binding.Configuration.MaxCPU = &maxCPU
		a.Binding.Configuration.MemoryHotplugMaxMiB = &maxMemory
		affinity := []ResourceReference{{ClusterUID: "cluster", ProjectUID: "project", Kind: "vm", UID: "peer-uid"}}
		anti := []ResourceReference{{ClusterUID: "cluster", ProjectUID: "project", Kind: "vm", UID: "anti-peer-uid"}}
		body.Desired.Labels = map[string]string{"base": "keep"}
		a.Binding.Configuration.Labels = map[string]string{"base": "keep"}
		body.Desired.Placement = &PlacementIntent{Policy: "spread", Host: &HostInput{Name: "worker"}, RequiredLabels: map[string]string{"zone": "a"}, PreferredLabels: map[string]string{"fast": "yes"}, Affinity: affinity, AntiAffinity: anti, MaxPerHost: 2}
		a.Binding.Configuration.Placement = &PlacementIntent{Policy: "spread", Host: &HostInput{Pinned: &HostReference{ClusterUID: "cluster", UID: "host-uid", Name: "worker"}}, RequiredLabels: map[string]string{"zone": "a"}, PreferredLabels: map[string]string{"fast": "yes"}, Affinity: affinity, AntiAffinity: anti, MaxPerHost: 2}
		for _, entry := range []struct{ kind, uid, alias, project string }{{"vm", "anti-peer-uid", "anti-peer", "project"}, {"vm", "new-peer-uid", "new-peer", "project"}, {"host", "host-2", "worker-2", ""}} {
			p.Binding.Dependencies = append(p.Binding.Dependencies, &IdentityRecord{ClusterUID: "cluster", ProjectUID: entry.project, Kind: entry.kind, UID: entry.uid, Alias: entry.alias, Witness: "positive-" + entry.uid, Generation: 1})
		}
		d.Command.Body, _ = json.Marshal(body)
		d.Assignment, _ = json.Marshal(a)
	})
}
func updateReplacementPlacement() (PlacementIntent, PlacementIntent) {
	requested := PlacementIntent{Policy: "pack", Host: &HostInput{Name: "worker-2"}, RequiredLabels: map[string]string{"zone": "b"}, PreferredLabels: map[string]string{"fast": "no"}, Affinity: []ResourceReference{{ClusterUID: "cluster", ProjectUID: "project", Kind: "vm", UID: "new-peer-uid"}}, AntiAffinity: []ResourceReference{{ClusterUID: "cluster", ProjectUID: "project", Kind: "vm", UID: "peer-uid"}}, MaxPerHost: 3}
	resolved := requested
	resolved.Host = &HostInput{Pinned: &HostReference{ClusterUID: "cluster", UID: "host-2", Name: "worker-2"}}
	return requested, resolved
}
func TestAutomationUpdatePopulatedPlacementPresenceAndMixedResize(t *testing.T) {
	for _, mode := range []string{"absent", "clear", "replace", "mixed"} {
		t.Run(mode, func(t *testing.T) {
			p, d := updatePopulatedPlacementFixture(t)
			old := updateClone(*p.Update.PreviousDesired.PinnedConfiguration)
			before := *p.Binding.Resource
			want := updateClone(old)
			requested, resolved := updateReplacementPlacement()
			updateContractEdit(t, &d, func(b *UpdateBindingBody, u *UpdateAssignment) {
				b.Patch = VMUpdatePatch{}
				u.Configuration = updateClone(old)
				u.Revision = "rev:placement:" + mode
				u.Applicability.Mechanism = "metadata"
				switch mode {
				case "absent":
					b.Patch.Labels = &UpdateLabelSet{Values: map[string]string{"base": "keep", "other": "new"}}
					want.Labels = map[string]string{"base": "keep", "other": "new"}
				case "clear":
					b.Patch.Placement = &PlacementIntent{}
					want.Placement = &PlacementIntent{Policy: "balanced"}
				case "replace":
					b.Patch.Placement = &requested
					want.Placement = &resolved
				case "mixed":
					cpu, memory := uint32(3), uint64(1536)
					b.Patch = VMUpdatePatch{CPU: &cpu, MemoryMiB: &memory, Labels: &UpdateLabelSet{Values: map[string]string{"role": "db"}}, Placement: &requested}
					want.CPU = 3
					want.MemoryMiB = 1536
					want.Labels = map[string]string{"role": "db"}
					want.Placement = &resolved
					u.Applicability.Mechanism = "live_resize"
					u.Applicability.CPULiveMin = 2
					u.Applicability.CPULiveMax = 4
					u.Applicability.MemoryLiveMinMiB = 1024
					u.Applicability.MemoryLiveMaxMiB = 2048
					u.Applicability.MemoryMode = "virtio_mem"
				}
				u.Configuration = updateClone(want)
			})
			r, e := Reduce(p, d)
			if e != nil || r.Receipt.Code != "" || r.AdmissionEffect == nil || r.AdmissionEffect.PinnedConfiguration == nil {
				t.Fatalf("populated placement/mixed resize not admitted: mode=%s receipt=%+v err=%v", mode, r.Receipt, e)
			}
			if !reflect.DeepEqual(*r.AdmissionEffect.PinnedConfiguration, want) {
				t.Fatal("placement presence or resize lost exact full configuration", mode, r.AdmissionEffect.PinnedConfiguration, want)
			}
			if !reflect.DeepEqual(*p.Update.PreviousDesired.PinnedConfiguration, old) {
				t.Fatal("patch mutated authenticated old placement/config", mode)
			}
			preserved := *r.ResourceEffect
			preserved.Revision = before.Revision
			preserved.LastOperationID = before.LastOperationID
			preserved.AppliedSequence = before.AppliedSequence
			if preserved != before || r.ResourceEffect.OriginalOperationID != "create-operation" || r.IdentityEffect != nil || r.NameEffect != nil || r.WrappingEffect != nil || r.ExecutorEffect != nil || r.TerminalEffect != nil || len(r.ArtifactEffects) != 0 || len(r.TargetReservations) != 0 {
				t.Fatal("placement or mixed resize changed birth/runtime/artifact identity", mode)
			}
			if mode == "clear" {
				v := r.AdmissionEffect.PinnedConfiguration.Placement
				if v.Policy != "balanced" || v.Host != nil || len(v.RequiredLabels) != 0 || len(v.PreferredLabels) != 0 || len(v.Affinity) != 0 || len(v.AntiAffinity) != 0 || v.MaxPerHost != 0 {
					t.Fatal("placement clear retained populated constraints", v)
				}
			}
		})
	}
}
func TestAutomationUpdatePlacementAffinityDependencyScope(t *testing.T) {
	for _, mode := range []string{"affinity-scope", "affinity-retired", "anti-scope", "anti-retired"} {
		t.Run(mode, func(t *testing.T) {
			p, d := updatePopulatedPlacementFixture(t)
			requested, resolved := updateReplacementPlacement()
			updateContractEdit(t, &d, func(b *UpdateBindingBody, u *UpdateAssignment) {
				b.Patch = VMUpdatePatch{Placement: &requested}
				u.Configuration = updateClone(*p.Update.PreviousDesired.PinnedConfiguration)
				u.Configuration.Placement = &resolved
				u.Applicability.Mechanism = "metadata"
				u.Revision = "rev:affinity"
			})
			positive, e := Reduce(p, d)
			if e != nil || positive.Receipt.Code != "" || positive.AdmissionEffect == nil {
				t.Fatal("positive enrolled affinity/anti-affinity replacement", positive.Receipt, e)
			}
			uid := "new-peer-uid"
			if strings.HasPrefix(mode, "anti") {
				uid = "peer-uid"
			}
			want := CodeUnavailable
			for _, dep := range p.Binding.Dependencies {
				if dep.UID == uid {
					if strings.HasSuffix(mode, "retired") {
						dep.Retired = true
						want = CodeRetired
					} else {
						dep.ProjectUID = "other-project"
					}
				}
			}
			r, e := Reduce(p, d)
			code := r.Receipt.Code
			if e != nil {
				code = Code(e)
			}
			if code != want || !noBindingEffects(r) {
				t.Fatal("placement borrowed foreign/retired affinity dependency", mode, r.Receipt, e)
			}
		})
	}
}
