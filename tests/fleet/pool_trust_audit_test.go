package fleet

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pooltrust"
)

// auditRows is n's own audit rows of action: "username result".
func auditRows(t *testing.T, n *Node, action string) []string {
	t.Helper()
	rows, err := n.DB.Query(context.Background(), `SELECT username, result FROM audit_log WHERE action = ? AND host_name = ? ORDER BY timestamp, rowid`, action, n.Name)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, r := range rows {
		out = append(out, r.String("username")+" "+r.String("result"))
	}
	return out
}

// (review r0 I4) alice confirms a row on node-1 through node-2, and creates a
// pool there through node-2. Each is audited as alice on both nodes: node-2
// records what it forwarded, node-1 what it did, taking the operator from the
// forward (repairActor), not the peer's bearerless admin. A refused
// confirmation is audited on both too.
//
// Mutations: forward without the actor — node-1's rows read admin, red; drop
// the entry node's audit — node-2 has none, red; skip auditing a refusal —
// red.
func TestFleet_PoolTrust_AuditNamesTheOperator(t *testing.T) {
	c := New(t, Options{Nodes: 3, IndependentReplicas: true})
	c.openClusterPolicyGate()
	t.Cleanup(c.Stop)
	ctx := context.Background()
	attacker, target, entry := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	for _, n := range c.Nodes {
		pt, err := pooltrust.Open(filepath.Join(c.tmpRoot, n.Name, "data"), n.PKIDir)
		if err != nil {
			t.Fatal(err)
		}
		n.Server.SetPoolTrust(pt)
	}
	pwn := filepath.Join(c.tmpRoot, "srv-pwn")
	made := filepath.Join(c.tmpRoot, "srv-made")
	for _, d := range []string{pwn, made} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := corrosion.UpsertStoragePool(ctx, attacker.DB, corrosion.StoragePoolRecord{
		HostName: target.Name, Name: "pwn", Driver: "dir", Target: pwn, State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	tok := adminUserToken(t, c, entry, "alice")
	c.WaitConverged(t, convergeTimeout)
	alice := c.bearerClient(entry, tok)

	// A confirmation of values the row does not have: refused, and audited.
	if _, err := alice.TrustStoragePool(ctx, &pb.TrustStoragePoolRequest{Name: "pwn", Host: target.Name, Driver: "dir", Target: made}); err == nil {
		t.Fatal("a confirmation of values the row does not have was accepted")
	}
	if _, err := alice.TrustStoragePool(ctx, &pb.TrustStoragePoolRequest{Name: "pwn", Host: target.Name, Driver: "dir", Target: pwn}); err != nil {
		t.Fatalf("trust through node-2: %v", err)
	}
	if _, err := alice.CreateStoragePool(ctx, &pb.CreateStoragePoolRequest{Name: "made", Driver: "dir", Target: made, Host: target.Name}); err != nil {
		t.Fatalf("create through node-2: %v", err)
	}
	for _, n := range []*Node{target, entry} {
		got := auditRows(t, n, "storage.pool.trust")
		if len(got) != 2 || !strings.HasPrefix(got[0], "alice error: FailedPrecondition") || got[1] != "alice ok" {
			t.Errorf("%s's trust audit = %q, want alice's refusal then alice ok", n.Name, got)
		}
		if got := auditRows(t, n, "storage.pool.create"); len(got) != 1 || got[0] != "alice ok" {
			t.Errorf("%s's create audit = %q, want one alice ok", n.Name, got)
		}
	}
}
