package corrosion

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/automation/contract"
)

// UNBOUND/UNFORMATTED/UNCOMPILED/UNRUN external proposal. Bind to root's actual
// reviewed B753 composition before adoption. These are certified-history replay
// fixtures; neither the test signers nor the FULL result issue a native permit.
// Missing FULL preparation must fail at the positive apply below before any
// execution-table SQL is reached. No schema version or grant is hand-inserted.
func TestAutomationExecutionFULLFirstGrantAfterAdmissionGap(t *testing.T) {
	dir := t.TempDir()
	c, grant, admission, config := automationExecutionCertifiedFirstGrantFixture(t, dir)
	before := sharedActiveRows(t, c)
	beforeTyped := automationTypedSnapshot(t, c)
	t.Log("certified-history setup complete: admission=10 gap=11 first-grant=12 host/image/pool/network=enrolled native-issuance=false")
	first, err := applySharedAutomation(t, c, grant, contract.Reduce, automationFreshAnchor)
	if err != nil {
		// Failure must leave the existing certified state untouched as well as
		// identify the missing execution preparation, rather than a setup error.
		if !reflect.DeepEqual(before, sharedActiveRows(t, c)) || !reflect.DeepEqual(beforeTyped, automationTypedSnapshot(t, c)) {
			t.Fatal("failed FULL first grant changed certified predecessor state")
		}
		t.Fatalf("FULL first grant after valid certified admission gap must apply: code=%q err=%v", contract.Code(err), err)
	}
	if first.Code != "" || first.State != "accepted" || first.Sequence != 12 ||
		first.OperationID != "claim-op" || first.ResourceUID != "resource-uid" ||
		first.Generation != 1 || first.ResourceRevision != "rev:opaque-alpha" {
		t.Fatalf("FULL first grant returned incomplete accepted receipt: %+v", first)
	}

	// New execution-table queries are deliberately dominated by successful FULL
	// application. The preimplementation witness is never a missing-table error.
	want := automationExecutionFirstGrantWant(t, grant, admission, config)
	beforeReopen := automationExecutionFirstGrantSnapshot(t, c, grant, first, want)
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewLocalClient(dir, "a")
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	reopened.SetVoterConfigGate(func() bool { return true })
	if after := automationExecutionFirstGrantSnapshot(t, reopened, grant, first, want); !reflect.DeepEqual(beforeReopen, after) {
		t.Fatal("cold reopen changed committed FULL execution/history/request/cursors")
	}
	// Exact certified-history retry must retain the first receipt and byte rows.
	retry, err := applySharedAutomation(t, reopened, grant, contract.Reduce, automationFreshAnchor)
	if err != nil || retry != first {
		t.Fatalf("cold exact grant retry changed receipt: %+v %v", retry, err)
	}
	if after := automationExecutionFirstGrantSnapshot(t, reopened, grant, first, want); !reflect.DeepEqual(beforeReopen, after) {
		t.Fatal("cold exact grant retry changed committed execution state")
	}
}

// Reuse existing file-backed InitSchema, signed initialization and verified
// project/principal history. Its returned seq4 target proposal is NOT applied;
// the signing closure accepts the actual decisions below. No target grant,
// production genesis, admission permit or runtime issuance is fabricated here.
func automationExecutionCertifiedFirstGrantFixture(t *testing.T, dir string) (*Client, AutomationRecord, AutomationRecord, contract.VMIntent) {
	t.Helper()
	c, grant, admission, config, _ := automationExecutionCertifiedFirstGrantSigningFixture(t, dir)
	return c, grant, admission, config
}

// Retain the real fixture signer for additive storage/replay decisions.
func automationExecutionCertifiedFirstGrantSigningFixture(t *testing.T, dir string) (*Client, AutomationRecord, AutomationRecord, contract.VMIntent, func(contract.Decision) AutomationRecord) {
	t.Helper()
	c, _, signed, _ := targetCertifiedFixtureAt(t, contract.OrdinaryCreateCommand, dir)
	return automationExecutionCertifiedFirstGrantOn(t, c, signed)
}

// Continue the same certified semantics on an existing initialized client and
// its existing electorate's signer. Existing a/b/c entry points retain behavior.
func automationExecutionCertifiedFirstGrantOn(t *testing.T, c *Client, signed func(contract.Decision) AutomationRecord) (*Client, AutomationRecord, AutomationRecord, contract.VMIntent, func(contract.Decision) AutomationRecord) {
	t.Helper()
	ctx := context.Background()
	head, err := c.AutomationHead(ctx)
	if err != nil || head.Sequence != 3 || head.ClusterUID != "established-cluster" {
		t.Fatalf("execution prerequisite: certified project/principal history: %+v %v", head, err)
	}
	appendDecision := func(command contract.Command, assignment contract.Assignment) AutomationRecord {
		t.Helper()
		d := contract.Decision{Sequence: head.Sequence + 1, ParentDigest: head.Digest, Command: command, Assignment: automationExecutionJSON(t, assignment)}
		r := signed(d)
		receipt, err := applySharedAutomation(t, c, r, contract.Reduce, automationFreshAnchor)
		if err != nil || receipt.Code != "" {
			t.Fatalf("execution prerequisite: certified %s seq%d did not apply: %+v %v", command.Kind, d.Sequence, receipt, err)
		}
		head = contract.Prefix{ClusterUID: "established-cluster", Sequence: d.Sequence, Digest: r.Value.MustDigest()}
		return r
	}
	assignment := func(operation string) contract.Assignment {
		return contract.Assignment{Version: 1, ClusterUID: "established-cluster", OperationID: operation, RecordedAt: "2026-10-21T00:00:00Z"}
	}
	for _, dependency := range []struct{ kind, uid, project, alias string }{
		{"host", "host-uid", "", "worker"},
		{"pool", "pool-uid", "", "shared"},
		{"image", "image-uid", "project-uid", "base-image"},
		{"network", "network-uid", "project-uid", "blue"},
	} {
		body := contract.IdentityEnrollment{Version: 1, Kind: dependency.kind, Alias: dependency.alias, Witness: "positive-" + dependency.uid, EvidenceID: "retained-cutover"}
		a := assignment(dependency.kind + "-op")
		a.Identity = &contract.IdentityAssignment{UID: dependency.uid, Generation: 1, Enrollment: &contract.IdentityEnrollmentFacts{Version: 1, EvidenceID: body.EvidenceID, ClusterUID: "established-cluster", ProjectUID: dependency.project, Kind: body.Kind, Alias: body.Alias, Witness: body.Witness, CoverageDigest: strings.Repeat("b", 64), FenceSequence: 3}}
		appendDecision(contract.Command{Kind: "assign_identity", ClusterUID: "established-cluster", ProjectUID: dependency.project, PrincipalID: "host", RequestID: dependency.kind + "-request", Body: automationExecutionJSON(t, body)}, a)
	}
	for _, kind := range []string{"ensure_owner", "acquire_session"} {
		a := assignment(kind + "-op")
		if kind == "acquire_session" {
			a.Owner = &contract.OwnerAssignment{SessionID: "session"}
		}
		appendDecision(contract.Command{Kind: kind, ClusterUID: "established-cluster", ProjectUID: "project-uid", PrincipalID: "principal-uid", OwnerID: "owner", RequestID: kind + "-request", Body: []byte(`{"version":1}`)}, a)
	}
	project := contract.ReferenceScope{ClusterUID: "established-cluster", ProjectUID: "project-uid"}
	global := contract.ReferenceScope{ClusterUID: "established-cluster", Global: true}
	image := &contract.ReferenceInput{Pinned: &contract.PinnedReference{Scope: project, UID: "image-uid", Name: "base-image", ContentDigest: strings.Repeat("a", 64)}}
	mac := "02:00:00:00:00:01"
	maxCPU, maxMemory := uint32(2), uint64(1024)
	config := contract.VMIntent{Name: "machine", CPU: 2, MemoryMiB: 1024, MaxCPU: &maxCPU, MemoryHotplugMaxMiB: &maxMemory, RequestedState: "running", Image: image,
		Disks:     []contract.DiskIntent{{Key: "root", SizeBytes: 4096, Pool: &contract.ReferenceInput{Pinned: &contract.PinnedReference{Scope: global, UID: "pool-uid", Name: "shared"}}, Image: image, Bus: "virtio"}},
		NICs:      []contract.NICIntent{{Key: "net0", Network: contract.ReferenceInput{Pinned: &contract.PinnedReference{Scope: project, UID: "network-uid", Name: "blue"}}, Model: "virtio", MAC: &mac}},
		Placement: &contract.PlacementIntent{Policy: "balanced", Host: &contract.HostInput{Pinned: &contract.HostReference{ClusterUID: "established-cluster", UID: "host-uid", Name: "worker"}}}}
	a := assignment("create-op")
	a.Binding = &contract.BindingAssignment{ResourceUID: "resource-uid", BindingGeneration: 1, NameGeneration: 1, Revision: "rev:opaque-alpha", DomainUUID: "domain-uuid", Incarnation: "runtime-incarnation", AdmittedGeneration: 1, Configuration: config}
	admission := appendDecision(contract.Command{Kind: "admit_create", ClusterUID: "established-cluster", ProjectUID: "project-uid", PrincipalID: "principal-uid", OwnerID: "owner", ManagementKey: "key", Session: 1, SessionID: "session", RequestID: "create-request", Body: automationExecutionJSON(t, contract.CreateBindingBody{Version: 1, Desired: config})}, a)
	// Observe the admitted original and every enrolled dependency through actual
	// current-stage storage readers, before constructing the execution command.
	if err := c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		original, err := automationAdmissionRecordTx(ctx, tx, "", "create-op")
		if err != nil {
			return err
		}
		if original == nil || original.Sequence != 10 || original.Method != "admit_create" || original.ResourceUID != "resource-uid" || original.AdmittedGeneration != 1 || !reflect.DeepEqual(original.PinnedConfiguration, &config) {
			return fmt.Errorf("original pinned admission missing: %+v", original)
		}
		resource, err := automationResourceRecordTx(ctx, tx, "", "resource-uid")
		if err != nil {
			return err
		}
		if resource == nil || resource.OriginalOperationID != "create-op" || resource.LastOperationID != "create-op" || resource.AppliedSequence != 10 || resource.Retired || resource.Revision != "rev:opaque-alpha" {
			return fmt.Errorf("original managed resource missing: %+v", resource)
		}
		for _, dep := range []struct{ kind, uid, project string }{{"host", "host-uid", ""}, {"pool", "pool-uid", ""}, {"image", "image-uid", "project-uid"}, {"network", "network-uid", "project-uid"}} {
			v, err := automationIdentityRecordTx(ctx, tx, "", dep.uid)
			if err != nil {
				return err
			}
			if v == nil || v.ClusterUID != "established-cluster" || v.ProjectUID != dep.project || v.Kind != dep.kind || v.Witness != "positive-"+dep.uid || v.Generation != 1 || v.Retired {
				return fmt.Errorf("certified dependency missing: %s %+v", dep.uid, v)
			}
		}
		return nil
	}); err != nil {
		t.Fatal("execution prerequisite: observed certified admission/dependencies", err)
	}
	appendDecision(contract.Command{Kind: "read_barrier", ClusterUID: "established-cluster", PrincipalID: "host", RequestID: "unrelated-gap-request", Body: []byte(`{"version":1}`)}, assignment("unrelated-gap-op"))
	observed, err := c.AutomationHead(ctx)
	if err != nil || observed != head || head.Sequence != 11 || head.Digest == admission.Value.MustDigest() {
		t.Fatalf("execution prerequisite: no distinct applied certified admission gap: %+v %v", observed, err)
	}
	for _, operation := range []struct {
		id, state string
		sequence  uint64
	}{{"create-op", "accepted", 10}, {"unrelated-gap-op", "succeeded", 11}} {
		receipt, found, err := c.AutomationOperation(ctx, operation.id)
		if err != nil || !found || receipt.Code != "" || receipt.Sequence != operation.sequence || receipt.State != operation.state {
			t.Fatalf("execution prerequisite: original admission/barrier receipt missing: %s %+v %v", operation.id, receipt, err)
		}
	}
	body := contract.ExecutionBody{Version: 1, OperationID: "create-op", Admission: contract.HistoryReference{Sequence: 10, Digest: admission.Value.MustDigest()}, ResourceRevision: "rev:opaque-alpha", DomainUUID: "domain-uuid", Incarnation: "runtime-incarnation", HostUID: "host-uid", HostIncarnation: "positive-host-uid"}
	a = assignment("claim-op")
	a.Execution = &contract.ExecutionAssignment{Version: 1, ExecutorGeneration: 1}
	d := contract.Decision{Sequence: 12, ParentDigest: head.Digest, Command: contract.Command{Kind: "claim_executor", ClusterUID: "established-cluster", ProjectUID: "project-uid", PrincipalID: "principal-uid", OwnerID: "owner", ManagementKey: "key", ResourceUID: "resource-uid", Generation: 1, Session: 1, SessionID: "session", RequestID: "claim-request", Body: automationExecutionJSON(t, body)}, Assignment: automationExecutionJSON(t, a)}
	if err := contract.ValidateSupportedDecision(d); err != nil {
		t.Fatal("execution prerequisite: strict claim decision invalid", err)
	}
	return c, signed(d), admission, config, signed
}

func automationExecutionJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func automationExecutionFirstGrantWant(t *testing.T, grant, admission AutomationRecord, config contract.VMIntent) contract.ExecutorGrant {
	t.Helper()
	d, err := automationDecision(grant.Value)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := contract.EncodeDecision(d)
	if err != nil {
		t.Fatal(err)
	}
	decisionDigest := sha256.Sum256(envelope)
	configurationDigest := sha256.Sum256(automationExecutionJSON(t, config))
	if hex.EncodeToString(decisionDigest[:]) == grant.Value.MustDigest() {
		t.Fatal("fixture did not distinguish decision and ClaimValue digest namespaces")
	}
	return contract.ExecutorGrant{Generation: 1, Reference: contract.HistoryReference{Sequence: 12, Digest: hex.EncodeToString(decisionDigest[:])},
		Target:       contract.ExecutionTarget{ClusterUID: "established-cluster", ProjectUID: "project-uid", ResourceUID: "resource-uid", OwnerID: "owner", ManagementKey: "key", BindingGeneration: 1, OperationID: "create-op", Admission: contract.HistoryReference{Sequence: 10, Digest: admission.Value.MustDigest()}, ResourceRevision: "rev:opaque-alpha", DomainUUID: "domain-uuid", Incarnation: "runtime-incarnation", HostUID: "host-uid", HostIncarnation: "positive-host-uid", ConfigurationDigest: hex.EncodeToString(configurationDigest[:])},
		Requirements: []contract.ArtifactRequirement{{Key: "root", Kind: "disk"}, {Key: "domain", Kind: "domain"}}}
}

// One FULL read transaction observes derived rows and their certified owners.
// This helper must only be called AFTER a successful first-grant FULL apply.
func automationExecutionFirstGrantSnapshot(t *testing.T, c *Client, grant AutomationRecord, receipt contract.Receipt, want contract.ExecutorGrant) map[string][]Row {
	t.Helper()
	ctx := context.Background()
	out := map[string][]Row{}
	err := c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		for _, table := range []string{"local_automation_executors", "local_automation_execution_progress", "local_automation_execution_artifacts", "local_automation_execution_terminals"} {
			rows, err := tx.Query(ctx, "SELECT * FROM "+table+" ORDER BY stage,cluster_uid,operation_id")
			if err != nil {
				return err
			}
			out[table] = rows
			if table != "local_automation_executors" && len(rows) != 0 {
				return fmt.Errorf("first grant invented progress/artifact/terminal: %s %+v", table, rows)
			}
		}
		rows := out["local_automation_executors"]
		if len(rows) != 1 {
			return fmt.Errorf("FULL first grant durable executor count=%d, want 1", len(rows))
		}
		r := rows[0]
		if r.String("stage") != "" || r.String("cluster_uid") != "established-cluster" || r.String("operation_id") != "create-op" || r.String("resource_uid") != "resource-uid" || r.Int64("executor_generation") != 1 || r.Int64("grant_sequence") != 12 || r.String("grant_digest") != want.Reference.Digest || r.Int64("admission_sequence") != 10 || r.String("admission_digest") != want.Target.Admission.Digest {
			return fmt.Errorf("durable executor scalar identity differs: %+v", r)
		}
		var stored contract.ExecutorGrant
		if err := json.Unmarshal([]byte(r.String("grant_json")), &stored); err != nil {
			return err
		}
		if !reflect.DeepEqual(stored, want) || r.String("grant_json") != string(automationExecutionJSON(t, want)) {
			return fmt.Errorf("durable grant target/requirements/encoding differ: %+v", stored)
		}
		head, err := automationHeadTx(ctx, tx)
		if err != nil {
			return err
		}
		semantic, err := automationSemanticHeadTx(ctx, tx, "")
		if err != nil {
			return err
		}
		if head != (contract.Prefix{ClusterUID: "established-cluster", Sequence: 12, Digest: grant.Value.MustDigest()}) || semantic != head {
			return fmt.Errorf("grant history/semantic cursors differ: %+v %+v", head, semantic)
		}
		d, err := automationDecision(grant.Value)
		if err != nil {
			return err
		}
		body, err := contract.DecodeExecutionBody(d.Command)
		if err != nil {
			return err
		}
		body.Grant = &contract.ExecutorReference{Generation: 1, Decision: want.Reference}
		body.State = "running"
		probe := d
		probe.Sequence, probe.ParentDigest = 13, head.Digest
		probe.Command.Kind, probe.Command.RequestID = "record_progress", "unapplied-projection-probe"
		probe.Command.Body = automationExecutionJSON(t, body)
		probe.Assignment = automationExecutionJSON(t, contract.Assignment{Version: 1, ClusterUID: "established-cluster", OperationID: "unapplied-projection-op", RecordedAt: "2026-10-21T00:00:01Z"})
		projection, err := automationProjectionTx(ctx, tx, head, probe, nil)
		if err != nil {
			return err
		}
		if projection.Head != head || projection.Execution == nil || projection.Execution.Admission != want.Target.Admission || projection.Execution.Grant == nil || !reflect.DeepEqual(*projection.Execution.Grant, want) || projection.Execution.Progress != nil || projection.Execution.Terminal != nil || len(projection.Execution.Artifacts) != 0 || len(projection.Execution.Exclusions) != 0 {
			return fmt.Errorf("current-stage execution projection differs from original grant: %+v", projection.Execution)
		}
		if projection.Binding == nil || projection.Binding.OriginalAdmission == nil || projection.Binding.OriginalAdmission.OperationID != "create-op" || projection.Binding.Resource == nil || projection.Binding.Resource.OriginalOperationID != "create-op" {
			return fmt.Errorf("current-stage execution projection lost original binding")
		}
		request, err := automationRequestTx(ctx, tx, contract.Scope(d), "claim-request")
		if err != nil {
			return err
		}
		op, err := automationOperationTx(ctx, tx, "claim-op")
		if err != nil {
			return err
		}
		if request == nil || request.Receipt != receipt || op == nil || *op != receipt {
			return fmt.Errorf("grant permanent request/operation receipt missing")
		}
		for _, q := range []struct{ key, sql string }{
			{"history", `SELECT * FROM local_automation_history ORDER BY sequence`},
			{"anchors", `SELECT * FROM local_automation_anchors ORDER BY sequence`},
			{"requests", `SELECT * FROM local_automation_requests ORDER BY scope,request_id`},
			{"prefix", `SELECT * FROM local_automation_prefix ORDER BY id`},
			{"semantic", `SELECT * FROM local_automation_semantic_heads ORDER BY stage`},
			{"resource", `SELECT * FROM local_automation_resources ORDER BY stage,uid`},
			{"admission", `SELECT * FROM local_automation_admissions ORDER BY stage,operation_id`},
		} {
			rows, err := tx.Query(ctx, q.sql)
			if err != nil {
				return err
			}
			out[q.key] = rows
		}
		if len(out["history"]) != 12 || len(out["anchors"]) != 12 || len(out["requests"]) != 12 {
			return fmt.Errorf("grant was not atomically retained with twelve original histories/anchors/requests")
		}
		if len(out["resource"]) != 1 || out["resource"][0].String("revision") != "rev:opaque-alpha" || out["resource"][0].String("last_operation_id") != "create-op" || out["resource"][0].Int64("applied_sequence") != 10 {
			return fmt.Errorf("execution altered desired resource revision/admission")
		}
		return nil
	})
	if err != nil {
		t.Fatal("FULL first grant durable snapshot", err)
	}
	return out
}
