package fleet

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/automation"
	"github.com/litevirt/litevirt/internal/automation/contract"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Returning a certified absence for an enrolled UID loses actual projection
// facts. These expected scalars come from the retained fixture, not Observe.
func TestAutomationObserveCertifiedResource(t *testing.T) {
	for _, tc := range []struct {
		name          string
		through       uint64
		uid           string
		want          automation.View
		lastOperation string
		original      string
		reconstruct   bool
	}{
		{name: "created", through: 7, uid: "resource-uid", want: automation.View{ResourceUID: "resource-uid", Name: "machine", DomainUUID: "domain-uuid", ResourceRevision: "rev:opaque-alpha", Generation: 1}, lastOperation: "create-op", original: "create-op"},
		{name: "transferred", through: 10, uid: "resource-uid", want: automation.View{ResourceUID: "resource-uid", Name: "machine", DomainUUID: "domain-uuid", ResourceRevision: "new-opaque-resource-uid", Generation: 1}, lastOperation: "transfer_owner-op", original: "create-op"},
		{name: "migrated_unowned", through: 11, uid: "legacy-uid", want: automation.View{ResourceUID: "legacy-uid", Name: "legacy-machine", DomainUUID: "legacy-domain", ResourceRevision: "legacy-revision"}, lastOperation: "migration-op"},
		{name: "reconstructed", through: 11, uid: "legacy-uid", want: automation.View{ResourceUID: "legacy-uid", Name: "legacy-machine", DomainUUID: "legacy-domain", ResourceRevision: "legacy-revision"}, lastOperation: "migration-op", reconstruct: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := NewAutomationFixture(t, 3)
			observeRetainedHistoryFixture(t, f, tc.through)
			db := f.cluster.Nodes[0].DB
			before := f.Head(t, 0)
			tc.want.ClusterUID = before.ClusterUID
			// Independently establish the exact scalar facts before invoking the
			// method under test. Do not seed an unchecked resource row.
			rows, err := db.Query(f.Context(), `SELECT cluster_uid,uid,name,domain_uuid,revision,binding_generation,retired,last_operation_id,original_operation_id,applied_sequence FROM local_automation_resources WHERE stage='' AND uid=?`, tc.uid)
			if err != nil || len(rows) != 1 {
				t.Fatalf("retained fixture resource missing: %+v %v", rows, err)
			}
			r := rows[0]
			if r.String("cluster_uid") != before.ClusterUID || r.String("uid") != tc.uid || r.String("name") != tc.want.Name || r.String("domain_uuid") != tc.want.DomainUUID || r.String("revision") != tc.want.ResourceRevision || r.Int64("binding_generation") != int64(tc.want.Generation) || r.Int64("retired") != 0 || r.String("last_operation_id") != tc.lastOperation || r.String("original_operation_id") != tc.original || r.Int64("applied_sequence") != int64(tc.through) {
				t.Fatalf("retained fixture scalar facts differ from hand-checked history: %+v", r)
			}
			if tc.reconstruct {
				// Retain the original signed history and anchors. The real Engine
				// recovery must reconstruct the resource and semantic frontier.
				for _, table := range []string{"local_automation_resources", "local_automation_names", "local_automation_bindings", "local_automation_admissions", "local_automation_identities", "local_automation_aliases", "local_automation_owners", "local_automation_semantic_heads", "local_automation_prefix"} {
					if err := localExec(f.Context(), db, "DELETE FROM "+table); err != nil {
						t.Fatal(err)
					}
				}
			}
			got, err := f.Engine(0).Observe(f.Context(), tc.uid, tc.through+1)
			after := f.Head(t, 0)
			if after.ClusterUID != before.ClusterUID || after.Sequence <= tc.through {
				t.Fatalf("Observe did not complete a fresh certified barrier: before=%+v after=%+v err=%v", before, after, err)
			}
			barrier, found, readErr := db.AutomationRecord(f.Context(), after.Sequence)
			if readErr != nil || !found {
				t.Fatalf("Observe barrier record missing: %v", readErr)
			}
			decision, readErr := contract.DecodeDecision(barrier.Value.Automation.Envelope)
			if readErr != nil || decision.Command.Kind != "read_barrier" {
				t.Fatalf("Observe frontier is not the actual read barrier: %+v %v", decision, readErr)
			}
			if err != nil {
				t.Fatalf("certified enrolled resource %q reported error after successful barrier (false absence=%v): %v", tc.uid, automation.IsAbsent(err), err)
			}
			tc.want.AppliedSequence = after.Sequence
			if got != tc.want {
				t.Fatalf("Observe = %+v; want exact retained resource facts %+v", got, tc.want)
			}
		})
	}
}

func TestAutomationObserveRequiresCertifiedFrontier(t *testing.T) {
	f := NewAutomationFixture(t, 3)
	observeRetainedHistoryFixture(t, f, 11)
	before := f.Head(t, 0)
	if _, err := f.Engine(0).Observe(f.Context(), "never-enrolled", before.Sequence+129); automation.Code(err) != automation.CodeUnavailable {
		t.Fatalf("unmet minimum became absence: %v", err)
	}
	if after := f.Head(t, 0); after != before {
		t.Fatalf("impossible minimum consumed a decision: %+v want %+v", after, before)
	}
	if _, err := f.Engine(0).Observe(f.Context(), "never-enrolled", 0); !automation.IsAbsent(err) {
		t.Fatalf("complete certified projection did not establish genuine absence: %v", err)
	}
	f.Isolate(0)
	ctx, cancel := context.WithTimeout(f.Context(), 2*time.Second)
	defer cancel()
	if _, err := f.Engine(0).Observe(ctx, "resource-uid", 0); automation.Code(err) != automation.CodeUnavailable {
		t.Fatalf("unavailable barrier returned resource/absence: %v", err)
	}
	f.Heal(0)
	if view, err := f.Engine(0).Observe(f.Context(), "resource-uid", 0); err != nil || view.ResourceUID != "resource-uid" || view.ResourceRevision != "new-opaque-resource-uid" {
		t.Fatalf("healed certified resource = %+v %v", view, err)
	}
	if err := localExec(f.Context(), f.cluster.Nodes[0].DB, `DELETE FROM local_automation_authority`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Engine(0).Observe(f.Context(), "never-enrolled", 0); automation.Code(err) != automation.CodeUnavailable {
		t.Fatalf("unavailable membership became absence: %v", err)
	}
}

// This is the literal twelve-decision historical fixture already exercised by
// corrosion.automationTypedHistoryFixtureWithDecision, adapted only to the real
// fleet's genesis cluster UID and signer/electorate. Each fixed record is signed
// and verified before the production AutomationApply/contract.Reduce path.
// It supplies no fresh business ClaimAccept permit, provider, or reducer result.
func observeRetainedHistoryFixture(t *testing.T, f *AutomationFixture, through uint64) {
	t.Helper()
	head := f.Head(t, 0)
	cluster, parent := head.ClusterUID, head.Digest
	appendDecision := func(d contract.Decision) {
		t.Helper()
		if d.Sequence > through {
			return
		}
		d.ParentDigest = parent
		envelope, err := contract.EncodeDecision(d)
		if err != nil {
			t.Fatal(err)
		}
		value := corrosion.ClaimValue{Automation: &corrosion.AutomationClaimValue{Envelope: envelope}}
		key, err := corrosion.AutomationClaimKey(d.Sequence)
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := corrosion.AdoptedVoterConfig(f.Context(), f.cluster.Nodes[0].DB)
		if err != nil {
			t.Fatal(err)
		}
		ballot := corrosion.Ballot{Round: 2, Coordinator: f.cluster.Nodes[0].Name, Nonce: []byte("observe-retained-fixture")}
		record := corrosion.AutomationRecord{Value: value, Certificate: corrosion.ClaimCertificate{Key: key, Ballot: ballot, ConfigGeneration: cfg.Generation, ValueDigest: value.MustDigest()}}
		for _, n := range f.cluster.Nodes {
			signer, err := corrosion.LoadClaimSigner(n.PKIDir, n.Name)
			if err != nil {
				t.Fatal(err)
			}
			incarnation, err := n.DB.VoterIncarnation(f.Context())
			if err != nil {
				t.Fatal(err)
			}
			signed, err := signer.Sign(key, cfg.Generation, ballot, value.MustDigest(), incarnation)
			if err != nil {
				t.Fatal(err)
			}
			record.Certificate.Accepts = append(record.Certificate.Accepts, signed)
		}
		for _, n := range f.cluster.Nodes {
			verifier, err := corrosion.LoadClaimVerifier(n.PKIDir)
			if err != nil {
				t.Fatal(err)
			}
			if err := verifier.Verify(record.Certificate, corrosion.CertExpectation{Key: key, ValueDigest: value.MustDigest(), ConfigGeneration: cfg.Generation, Electorate: cfg.Members, Quorum: corrosion.MajorityOf(len(cfg.Members))}); err != nil {
				t.Fatal(err)
			}
			if receipt, err := n.DB.AutomationApply(f.Context(), record, verifier, contract.Reduce); err != nil || receipt.Code != "" || receipt.Sequence != d.Sequence {
				t.Fatalf("retained certified fixture sequence %d: %+v %v", d.Sequence, receipt, err)
			}
		}
		parent = value.MustDigest()
	}
	for i, kind := range []string{"project", "principal"} {
		body := contract.IdentityEnrollment{Version: 1, Kind: kind, Alias: kind + "-alias", Witness: kind + "-source-lifetime", EvidenceID: "closed-cutover"}
		bodyJSON, _ := json.Marshal(body)
		assignment := contract.Assignment{Version: 1, ClusterUID: cluster, OperationID: kind + "-op", RecordedAt: "2026-10-17T00:00:00Z", Identity: &contract.IdentityAssignment{UID: kind + "-uid", Generation: 1, Enrollment: &contract.IdentityEnrollmentFacts{Version: 1, EvidenceID: body.EvidenceID, ClusterUID: cluster, Kind: kind, Alias: body.Alias, Witness: body.Witness, CoverageDigest: strings.Repeat("b", 64), FenceSequence: 1}}}
		assignmentJSON, _ := json.Marshal(assignment)
		appendDecision(contract.Decision{Sequence: uint64(i + 2), Command: contract.Command{Kind: "assign_identity", ClusterUID: cluster, PrincipalID: "host", RequestID: kind + "-request", Body: bodyJSON}, Assignment: assignmentJSON})
	}
	for i, kind := range []string{"ensure_owner", "acquire_session", "handoff_session"} {
		command := contract.Command{Kind: kind, ClusterUID: cluster, ProjectUID: "project-uid", PrincipalID: "principal-uid", OwnerID: "owner", RequestID: kind + "-request", Body: []byte(`{"version":1}`)}
		assignment := contract.Assignment{Version: 1, ClusterUID: cluster, OperationID: kind + "-op", RecordedAt: "2026-10-17T00:00:00Z"}
		if i > 0 {
			assignment.Owner = &contract.OwnerAssignment{SessionID: fmt.Sprintf("session-%d", i)}
		}
		if i == 2 {
			command.Session = 1
			command.SessionID = "session-1"
			command.Body = []byte(`{"version":1,"next_principal_uid":"principal-uid"}`)
		}
		assignmentJSON, _ := json.Marshal(assignment)
		appendDecision(contract.Decision{Sequence: uint64(i + 4), Command: command, Assignment: assignmentJSON})
	}
	maxCPU, maxMemory := uint32(2), uint64(1024)
	desired := contract.VMIntent{Name: "machine", CPU: 2, MemoryMiB: 1024}
	prepared := desired
	prepared.MaxCPU = &maxCPU
	prepared.MemoryHotplugMaxMiB = &maxMemory
	prepared.RequestedState = "running"
	prepared.Placement = &contract.PlacementIntent{Policy: "balanced"}
	bodyJSON, _ := json.Marshal(contract.CreateBindingBody{Version: 1, Desired: desired})
	assignmentJSON, _ := json.Marshal(contract.Assignment{Version: 1, ClusterUID: cluster, OperationID: "create-op", RecordedAt: "2026-10-17T00:00:00Z", Binding: &contract.BindingAssignment{PayloadID: "payload-reference", ResourceUID: "resource-uid", BindingGeneration: 1, NameGeneration: 1, Revision: "rev:opaque-alpha", DomainUUID: "domain-uuid", Incarnation: "incarnation", AdmittedGeneration: 1, Configuration: prepared}})
	appendDecision(contract.Decision{Sequence: 7, Command: contract.Command{Kind: "admit_create", ClusterUID: cluster, ProjectUID: "project-uid", PrincipalID: "principal-uid", OwnerID: "owner", ManagementKey: "key", SessionID: "session-2", Session: 2, RequestID: "create-request", Body: bodyJSON, Ciphertext: []byte("retained-encrypted-payload"), SecretIntentTag: []byte("equality-tag"), SecretKeyEpoch: "key-epoch"}, Assignment: assignmentJSON})
	for offset, kind := range []string{"ensure_owner", "acquire_session"} {
		assigned := contract.Assignment{Version: 1, ClusterUID: cluster, OperationID: kind + "-target-op", RecordedAt: "2026-10-17T00:00:00Z"}
		if offset == 1 {
			assigned.Owner = &contract.OwnerAssignment{SessionID: "target-session"}
		}
		encoded, _ := json.Marshal(assigned)
		appendDecision(contract.Decision{Sequence: uint64(8 + offset), Command: contract.Command{Kind: kind, ClusterUID: cluster, ProjectUID: "project-uid", PrincipalID: "principal-uid", OwnerID: "target-owner", RequestID: kind + "-target-request", Body: []byte(`{"version":1}`)}, Assignment: encoded})
	}
	ownership := func(seq uint64, kind, uid, name, revision, incarnation, lastOperation, key string, source *contract.BindingReference) {
		body := contract.OwnershipBody{Version: 1, Resource: contract.ResourceReference{ClusterUID: cluster, ProjectUID: "project-uid", Kind: "vm", UID: uid}, ExpectedRevision: revision, Source: source, Target: contract.BindingKey{ClusterUID: cluster, ProjectUID: "project-uid", OwnerID: "target-owner", ManagementKey: key}}
		command := contract.Command{Kind: kind, ClusterUID: cluster, ProjectUID: "project-uid", PrincipalID: "principal-uid", OwnerID: "target-owner", ManagementKey: key, ResourceUID: uid, Session: 1, SessionID: "target-session", RequestID: kind + "-request"}
		if source != nil {
			command.OwnerID = source.Key.OwnerID
			command.ManagementKey = source.Key.ManagementKey
			command.Generation = source.Generation
			command.Session = 2
			command.SessionID = "session-2"
		}
		command.Body, _ = json.Marshal(body)
		assignment := contract.Assignment{Version: 1, ClusterUID: cluster, OperationID: kind + "-op", RecordedAt: "2026-10-17T00:00:00Z", Ownership: &contract.OwnershipAssignment{Version: 1, TargetSession: contract.RecordedOwnerSession{ID: "target-session", Activation: 1, PrincipalUID: "principal-uid"}, TargetGeneration: 1, Revision: "new-opaque-" + uid, AdmittedGeneration: 1, Quiescence: contract.QuiescenceFacts{Version: 1, ResourceUID: uid, Revision: revision, Incarnation: incarnation, LastOperationID: lastOperation, FenceSequence: seq - 1, EvidenceID: "quiescence-reference", CoverageDigest: strings.Repeat("d", 64)}}}
		for _, purpose := range []string{"source_owner", "target_owner", "resource"} {
			if purpose == "source_owner" && source == nil {
				continue
			}
			permission := contract.PermissionFacts{Purpose: purpose, PrincipalUID: command.PrincipalID, ClusterUID: command.ClusterUID, ProjectUID: command.ProjectUID, ProjectName: "project-alias", Verb: "vm.update", EvidenceID: "permission-reference", CoverageDigest: strings.Repeat("e", 64), FenceSequence: seq - 1}
			switch purpose {
			case "source_owner":
				permission.OwnerID = source.Key.OwnerID
			case "target_owner":
				permission.OwnerID = "target-owner"
			case "resource":
				permission.ResourceUID = uid
				permission.ResourceName = name
			}
			assignment.Ownership.Permissions = append(assignment.Ownership.Permissions, permission)
		}
		encoded, _ := json.Marshal(assignment)
		appendDecision(contract.Decision{Sequence: seq, Command: command, Assignment: encoded})
	}
	ownership(10, "transfer_owner", "resource-uid", "machine", "rev:opaque-alpha", "incarnation", "create-op", "target-key", &contract.BindingReference{Key: contract.BindingKey{ClusterUID: cluster, ProjectUID: "project-uid", OwnerID: "owner", ManagementKey: "key"}, Generation: 1})
	migration := contract.IdentityEnrollment{Version: 1, Kind: "vm", Alias: "legacy-machine", Witness: "positive-legacy-witness", EvidenceID: "closed-cutover"}
	encodedBody, _ := json.Marshal(migration)
	migrationAssignment := contract.Assignment{Version: 1, ClusterUID: cluster, OperationID: "migration-op", RecordedAt: "2026-10-17T00:00:00Z", Identity: &contract.IdentityAssignment{UID: "legacy-uid", Generation: 1, Enrollment: &contract.IdentityEnrollmentFacts{Version: 1, EvidenceID: migration.EvidenceID, ClusterUID: cluster, ProjectUID: "project-uid", Kind: "vm", Alias: migration.Alias, Witness: migration.Witness, CoverageDigest: strings.Repeat("f", 64), FenceSequence: 1, VM: &contract.VMEnrollmentRuntime{Version: 1, DomainUUID: "legacy-domain", Incarnation: "legacy-incarnation", Revision: "legacy-revision"}}}}
	encodedAssignment, _ := json.Marshal(migrationAssignment)
	appendDecision(contract.Decision{Sequence: 11, Command: contract.Command{Kind: "assign_identity", ClusterUID: cluster, ProjectUID: "project-uid", PrincipalID: "host", RequestID: "migration-request", Body: encodedBody}, Assignment: encodedAssignment})
	ownership(12, "adopt_resource", "legacy-uid", "legacy-machine", "legacy-revision", "legacy-incarnation", "migration-op", "legacy-key", nil)
}
