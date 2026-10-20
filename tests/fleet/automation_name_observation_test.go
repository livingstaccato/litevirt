package fleet

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/automation"
	"github.com/litevirt/litevirt/internal/pki"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/automation/contract"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func TestAutomationObserveNameCertifiedRecords(t *testing.T) {
	for _, tc := range []struct{ leaf, name, uid string }{
		{"transferred", "machine", "resource-uid"},
		{"enrolled_unowned", "legacy-machine", "legacy-uid"},
		{"complete_absent", "never-enrolled", ""},
	} {
		t.Run(tc.leaf, func(t *testing.T) {
			f := NewAutomationFixture(t, 3)
			observeRetainedHistoryFixture(t, f, 11)
			before := f.Head(t, 0)
			db := f.cluster.Nodes[0].DB
			rows, err := db.Query(f.Context(), `SELECT uid,revision,owner_id,management_key,last_operation_id FROM local_automation_resources WHERE stage='' AND name=?`, tc.name)
			if err != nil {
				t.Fatal(err)
			}
			want := contract.ResourceRecord{ClusterUID: before.ClusterUID, ProjectUID: "project-uid", UID: tc.uid, Name: tc.name}
			witness, disposition := "incarnation", "reserved"
			if tc.uid == "resource-uid" {
				want.AppliedSequence, want.DomainUUID, want.Incarnation = 10, "domain-uuid", "incarnation"
				want.OwnerID, want.ManagementKey, want.BindingGeneration = "target-owner", "target-key", 1
				want.Revision, want.LastOperationID, want.OriginalOperationID = "new-opaque-resource-uid", "transfer_owner-op", "create-op"
			} else if tc.uid == "legacy-uid" {
				want.AppliedSequence, want.DomainUUID, want.Incarnation = 11, "legacy-domain", "legacy-incarnation"
				want.Revision, want.LastOperationID = "legacy-revision", "migration-op"
				witness, disposition = "positive-legacy-witness", "live"
			}
			if tc.uid != "" {
				if len(rows) != 1 || rows[0].String("uid") != tc.uid || rows[0].String("revision") != want.Revision || rows[0].String("owner_id") != want.OwnerID || rows[0].String("management_key") != want.ManagementKey || rows[0].String("last_operation_id") != want.LastOperationID {
					t.Fatalf("retained fixture differs from actual history: %+v", rows)
				}
			} else {
				if len(rows) != 0 {
					t.Fatalf("absent control has resource: %+v", rows)
				}
				refs, e := db.Query(f.Context(), `SELECT EXISTS(SELECT 1 FROM local_automation_names WHERE stage='' AND name=?) OR EXISTS(SELECT 1 FROM local_automation_aliases WHERE stage='' AND kind='vm' AND alias=?) OR EXISTS(SELECT 1 FROM local_automation_identities WHERE stage='' AND kind='vm' AND alias=?) AS present`, tc.name, tc.name, tc.name)
				if e != nil || len(refs) != 1 || refs[0].Int64("present") != 0 {
					t.Fatalf("absent control has retained name references: %+v %v", refs, e)
				}
			}
			got, err := f.Engine(0).ObserveName(f.Context(), tc.name, before.Sequence)
			if err != nil {
				t.Fatalf("certified name availability missing: %v", err)
			}
			after := f.Head(t, 0)
			if after.Sequence <= before.Sequence || got.Prefix != after || got.Name != tc.name {
				t.Fatalf("name observation lacks fresh certified frontier: got=%+v before=%+v after=%+v", got, before, after)
			}
			if tc.uid == "" {
				if got.State != corrosion.AutomationNameAbsent || got.Record != nil {
					t.Fatalf("not complete absence: %+v", got)
				}
				return
			}
			if got.State != corrosion.AutomationNamePresent || got.Record == nil {
				t.Fatalf("lost certified present name: %+v", got)
			}
			record := got.Record
			project := contract.IdentityRecord{ClusterUID: before.ClusterUID, Kind: "project", UID: "project-uid", Alias: "project-alias", Witness: "project-source-lifetime", Generation: 1}
			identity := contract.IdentityRecord{ClusterUID: before.ClusterUID, ProjectUID: "project-uid", Kind: "vm", UID: tc.uid, Alias: tc.name, Witness: witness, Generation: 1}
			name := contract.NameRecord{ClusterUID: before.ClusterUID, Name: tc.name, ResourceUID: tc.uid, Generation: 1, Disposition: disposition}
			if record.Resource != want || record.Project != project || record.VMIdentity != identity || record.Name != name {
				t.Fatalf("record differs from independently known retained facts: %+v", record)
			}
			if tc.uid == "legacy-uid" {
				if record.Owner != nil || record.Binding != nil {
					t.Fatalf("unowned enrollment gained owner/binding: %+v", record)
				}
				return
			}
			owner := contract.OwnerRecord{ClusterUID: before.ClusterUID, ProjectUID: "project-uid", OwnerID: "target-owner", FounderPrincipalUID: "principal-uid", SessionID: "target-session", SessionPrincipalUID: "principal-uid", Activation: 1}
			binding := contract.BindingRecord{ClusterUID: before.ClusterUID, ProjectUID: "project-uid", OwnerID: "target-owner", ManagementKey: "target-key", ResourceUID: tc.uid, OperationID: "transfer_owner-op", Generation: 1, Revision: want.Revision}
			if record.Owner == nil || *record.Owner != owner || record.Binding == nil || *record.Binding != binding {
				t.Fatalf("lost current target ownership after transfer: %+v", record)
			}
		})
	}
}

func TestAutomationObserveNameCreatedAndReconstructed(t *testing.T) {
	for _, reconstruct := range []bool{false, true} {
		leaf := "created"
		if reconstruct {
			leaf = "reconstructed"
		}
		t.Run(leaf, func(t *testing.T) {
			f := NewAutomationFixture(t, 3)
			observeRetainedHistoryFixture(t, f, 7)
			before := f.Head(t, 0)
			if reconstruct {
				for _, table := range []string{"local_automation_resources", "local_automation_names", "local_automation_bindings", "local_automation_admissions", "local_automation_identities", "local_automation_aliases", "local_automation_owners", "local_automation_semantic_heads", "local_automation_prefix"} {
					if err := localExec(f.Context(), f.cluster.Nodes[0].DB, "DELETE FROM "+table); err != nil {
						t.Fatal(err)
					}
				}
			}
			got, err := f.Engine(0).ObserveName(f.Context(), "machine", 7)
			if err != nil || got.State != corrosion.AutomationNamePresent || got.Record == nil {
				t.Fatalf("created name unavailable: %+v %v", got, err)
			}
			r := got.Record
			if r.Resource.UID != "resource-uid" || r.Resource.AppliedSequence != 7 || r.Resource.LastOperationID != "create-op" || r.Resource.OriginalOperationID != "create-op" || r.Resource.Revision != "rev:opaque-alpha" || r.Owner == nil || r.Owner.OwnerID != "owner" || r.Binding == nil || r.Binding.ManagementKey != "key" || got.Prefix.Sequence <= before.Sequence {
				t.Fatalf("created name facts: %+v", got)
			}
			barrier, found, err := f.cluster.Nodes[0].DB.AutomationRecord(f.Context(), got.Prefix.Sequence)
			if err != nil || !found {
				t.Fatalf("missing real barrier: %v", err)
			}
			d, err := contract.DecodeDecision(barrier.Value.Automation.Envelope)
			if err != nil || d.Command.Kind != "read_barrier" {
				t.Fatalf("read did not use actual barrier: %+v %v", d, err)
			}
		})
	}
}

func TestAutomationObserveNameBarrierFailures(t *testing.T) {
	for _, failure := range []string{"quorum", "fetch-transport", "authority"} {
		t.Run(failure, func(t *testing.T) {
			f := NewAutomationFixture(t, 3)
			observeRetainedHistoryFixture(t, f, 11)
			got, err := f.Engine(0).ObserveName(f.Context(), "never-enrolled", 0)
			if err != nil || got.State != corrosion.AutomationNameAbsent {
				t.Fatalf("positive before fault: %+v %v", got, err)
			}
			before := f.Head(t, 0)
			got, err = f.Engine(0).ObserveName(f.Context(), "never-enrolled", before.Sequence+129)
			if automation.Code(err) != automation.CodeUnavailable || got != (corrosion.AutomationNameObservation{}) || f.Head(t, 0) != before {
				t.Fatalf("unmet minimum became complete: %+v %v", got, err)
			}
			node := 0
			var fetches atomic.Int64
			switch failure {
			case "quorum":
				f.Isolate(0)
			case "fetch-transport":
				node = 2
				f.resetReplicaHistory(t, node)
				f.cluster.SetClaimScript(func(m ClaimMsg) ClaimFate {
					if m.From == f.cluster.Nodes[node].Name && m.Method == "GetAutomationDecision" {
						fetches.Add(1)
						return ClaimDropRequest
					}
					return ClaimDefault
				})
				t.Cleanup(func() { f.cluster.SetClaimScript(nil) })
			case "authority":
				if err := localExec(f.Context(), f.cluster.Nodes[node].DB, `UPDATE local_automation_authority SET members_hash='untrusted'`); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(f.Context(), 2*time.Second)
			got, err = f.Engine(node).ObserveName(ctx, "never-enrolled", 0)
			cancel()
			if err == nil || got != (corrosion.AutomationNameObservation{}) || automation.IsAbsent(err) {
				t.Fatalf("%s became a complete observation: %+v %v", failure, got, err)
			}
			if failure == "fetch-transport" && fetches.Load() != 2 {
				t.Fatalf("did not fault both real peer fetches: %d", fetches.Load())
			}
			switch failure {
			case "quorum":
				f.Heal(0)
			case "fetch-transport":
				f.cluster.SetClaimScript(nil)
			case "authority":
				cfg, err := corrosion.AdoptedVoterConfig(f.Context(), f.cluster.Nodes[node].DB)
				if err != nil {
					t.Fatal(err)
				}
				if err := localExec(f.Context(), f.cluster.Nodes[node].DB, `UPDATE local_automation_authority SET members_hash=?`, corrosion.MembersHash(cfg.Members)); err != nil {
					t.Fatal(err)
				}
			}
			got, err = f.Engine(node).ObserveName(f.Context(), "machine", 0)
			if err != nil || got.State != corrosion.AutomationNamePresent || got.Record == nil || got.Record.Resource.OwnerID != "target-owner" {
				t.Fatalf("restored positive: %+v %v", got, err)
			}
			got, err = f.Engine(node).ObserveName(f.Context(), "never-enrolled", 0)
			if err != nil || got.State != corrosion.AutomationNameAbsent {
				t.Fatalf("restored absence: %+v %v", got, err)
			}
		})
	}
}

func TestAutomationObserveNameLaggingReplicaRecoversOwnership(t *testing.T) {
	f := NewAutomationFixture(t, 3)
	observeRetainedHistoryFixture(t, f, 11)
	// Retained consumer history has no fresh voter acceptance. Establish an
	// actual accepted head before losing a replica's history and anchors.
	retained := f.Head(t, 0)
	preloss, err := f.Engine(0).Submit(f.Context(), f.Barrier(0, "name-read-preloss-lagging"))
	if err != nil {
		t.Fatalf("pre-loss consensus barrier: %v", err)
	}
	head := f.Head(t, 0)
	if head.Sequence <= retained.Sequence || preloss.Sequence != head.Sequence {
		t.Fatalf("pre-loss barrier did not advance retained history: retained=%+v receipt=%+v head=%+v", retained, preloss, head)
	}
	record, found, err := f.cluster.Nodes[0].DB.AutomationRecord(f.Context(), head.Sequence)
	if err != nil || !found || record.Value.Automation == nil || record.Value.MustDigest() != head.Digest {
		t.Fatalf("pre-loss accepted head missing: head=%+v found=%v err=%v", head, found, err)
	}
	decision, err := contract.DecodeDecision(record.Value.Automation.Envelope)
	if err != nil || decision.Command.Kind != "read_barrier" || decision.Sequence != head.Sequence {
		t.Fatalf("pre-loss head is not the real barrier: decision=%+v err=%v", decision, err)
	}
	key, err := corrosion.AutomationClaimKey(head.Sequence)
	if err != nil {
		t.Fatal(err)
	}
	acceptedSurvivors := 0
	for _, peer := range f.cluster.Nodes[:2] {
		accepted, err := peer.DB.Query(f.Context(), `SELECT accepted_round,value_digest FROM local_recovery_claims WHERE target_kind=? AND target_name=? AND owner_epoch=? AND attempt=?`, key.TargetKind, key.TargetName, key.OwnerEpoch, key.Attempt)
		if err != nil || len(accepted) > 1 {
			t.Fatalf("surviving peer %s acceptance query failed: rows=%+v err=%v", peer.Name, accepted, err)
		}
		if len(accepted) == 1 && accepted[0].Int64("accepted_round") > 0 && accepted[0].String("value_digest") == head.Digest {
			acceptedSurvivors++
		}
	}
	// A chosen two-of-three quorum intersects these two survivors.
	if acceptedSurvivors < 1 {
		t.Fatalf("survivors lack an exact accepted pre-loss head %d/%s", head.Sequence, head.Digest)
	}
	f.resetReplicaHistory(t, 2)
	lagger := f.cluster.Nodes[2].Name
	var held atomic.Int64
	f.cluster.SetClaimScript(func(m ClaimMsg) ClaimFate {
		if m.To == lagger && m.Method == "InstallAutomationDecision" {
			held.Add(1)
			return ClaimDropRequest
		}
		return ClaimDefault
	})
	t.Cleanup(func() { f.cluster.SetClaimScript(nil); f.cluster.ReleaseHeldClaims() })
	if _, err := f.Engine(0).Submit(f.Context(), f.Barrier(0, "name-read-held-propagation")); err != nil {
		t.Fatal(err)
	}
	if held.Load() == 0 || f.Head(t, 2).Sequence != 0 {
		t.Fatalf("lag witness was not held: held=%d head=%+v", held.Load(), f.Head(t, 2))
	}
	newer := f.Head(t, 0)
	got, err := f.Engine(2).ObserveName(f.Context(), "machine", newer.Sequence)
	if err != nil || got.State != corrosion.AutomationNamePresent || got.Record == nil || got.Record.Resource.OwnerID != "target-owner" || got.Record.Binding == nil || got.Record.Binding.OperationID != "transfer_owner-op" || got.Prefix.Sequence < newer.Sequence {
		t.Fatalf("lagger returned stale name/ownership: %+v %v", got, err)
	}
	f.cluster.SetClaimScript(nil)
	f.cluster.ReleaseHeldClaims()
	f.Converge(t)
}

// Only Fetch is needed: both actual private RPCs refuse this authenticated
// public-client certificate before a prefix is learned. The embedded transport
// deliberately supplies no substitute consensus implementation.
type nameReadDeniedTransport struct {
	automation.Transport
	clients map[string]pb.LiteVirtClient
	denied  atomic.Int64
}

func (tr *nameReadDeniedTransport) Fetch(ctx context.Context, voter string, sequence uint64) (corrosion.AutomationRecord, bool, error) {
	_, err := tr.clients[voter].GetAutomationDecision(ctx, &pb.GetAutomationDecisionRequest{Sequence: sequence})
	if status.Code(err) == codes.PermissionDenied {
		tr.denied.Add(1)
	}
	if err == nil {
		err = fmt.Errorf("public client unexpectedly fetched private automation history")
	}
	return corrosion.AutomationRecord{}, false, err
}

func TestAutomationObserveNameAuthenticatedFetchRefusal(t *testing.T) {
	f := NewAutomationFixture(t, 3)
	observeRetainedHistoryFixture(t, f, 11)
	// Retained consumer history has no fresh voter acceptance. Establish an
	// actual accepted head before losing a replica's history and anchors.
	retained := f.Head(t, 0)
	preloss, err := f.Engine(0).Submit(f.Context(), f.Barrier(0, "name-read-preloss-auth"))
	if err != nil {
		t.Fatalf("pre-loss consensus barrier: %v", err)
	}
	head := f.Head(t, 0)
	if head.Sequence <= retained.Sequence || preloss.Sequence != head.Sequence {
		t.Fatalf("pre-loss barrier did not advance retained history: retained=%+v receipt=%+v head=%+v", retained, preloss, head)
	}
	record, found, err := f.cluster.Nodes[0].DB.AutomationRecord(f.Context(), head.Sequence)
	if err != nil || !found || record.Value.Automation == nil || record.Value.MustDigest() != head.Digest {
		t.Fatalf("pre-loss accepted head missing: head=%+v found=%v err=%v", head, found, err)
	}
	decision, err := contract.DecodeDecision(record.Value.Automation.Envelope)
	if err != nil || decision.Command.Kind != "read_barrier" || decision.Sequence != head.Sequence {
		t.Fatalf("pre-loss head is not the real barrier: decision=%+v err=%v", decision, err)
	}
	key, err := corrosion.AutomationClaimKey(head.Sequence)
	if err != nil {
		t.Fatal(err)
	}
	acceptedSurvivors := 0
	for _, peer := range f.cluster.Nodes[:2] {
		accepted, err := peer.DB.Query(f.Context(), `SELECT accepted_round,value_digest FROM local_recovery_claims WHERE target_kind=? AND target_name=? AND owner_epoch=? AND attempt=?`, key.TargetKind, key.TargetName, key.OwnerEpoch, key.Attempt)
		if err != nil || len(accepted) > 1 {
			t.Fatalf("surviving peer %s acceptance query failed: rows=%+v err=%v", peer.Name, accepted, err)
		}
		if len(accepted) == 1 && accepted[0].Int64("accepted_round") > 0 && accepted[0].String("value_digest") == head.Digest {
			acceptedSurvivors++
		}
	}
	// A chosen two-of-three quorum intersects these two survivors.
	if acceptedSurvivors < 1 {
		t.Fatalf("survivors lack an exact accepted pre-loss head %d/%s", head.Sequence, head.Digest)
	}
	f.resetReplicaHistory(t, 2)
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "client.crt"), filepath.Join(dir, "client.key")
	if err := pki.GenerateClientCert(f.cluster.caCert, f.cluster.caKey, certPath, keyPath, "name-read-public-client"); err != nil {
		t.Fatal(err)
	}
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := os.ReadFile(f.cluster.caCert)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("invalid CA fixture")
	}
	tr := &nameReadDeniedTransport{clients: map[string]pb.LiteVirtClient{}}
	for _, n := range f.cluster.Nodes[:2] {
		conn, err := grpc.NewClient(fmt.Sprintf("%s:%d", n.Address, n.Port), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{RootCAs: roots, Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12})))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		tr.clients[n.Name] = pb.NewLiteVirtClient(conn)
	}
	n := f.cluster.Nodes[2]
	verifier, err := corrosion.LoadClaimVerifier(n.PKIDir)
	if err != nil {
		t.Fatal(err)
	}
	engine := automation.NewEngine(n.Name, n.DB, verifier, tr)
	got, err := engine.ObserveName(f.Context(), "never-enrolled", 0)
	if automation.Code(err) != automation.CodeUnavailable || got != (corrosion.AutomationNameObservation{}) || tr.denied.Load() != 2 {
		t.Fatalf("actual peer-only authentication refusal became observation: %+v %v denials=%d", got, err, tr.denied.Load())
	}
	got, err = f.Engine(2).ObserveName(f.Context(), "machine", 0)
	if err != nil || got.State != corrosion.AutomationNamePresent || got.Record == nil || got.Record.Resource.OwnerID != "target-owner" {
		t.Fatalf("host-authenticated positive after refusal: %+v %v", got, err)
	}
}
