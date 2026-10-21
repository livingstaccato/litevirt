package fleet

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// reportsCA makes n report a valid set trusting fps, with its certificate from issuer.
func reportsCA(n *Node, issuer string, fps ...string) {
	n.Server.SetMigrationTLSStatus(func() *pb.MigrationTLSHostStatus {
		row := &pb.MigrationTLSHostStatus{Provisioned: true, CertIssuerFingerprint: issuer}
		for _, fp := range fps {
			row.TrustedCas = append(row.TrustedCas, &pb.MigrationTLSCA{Fingerprint: fp})
		}
		return row
	})
}

func migrationTLSRows(t *testing.T, c *Cluster, via *Node) map[string]*pb.MigrationTLSHostStatus {
	t.Helper()
	resp, err := c.SelfClient(via).MigrationTLSStatus(context.Background(), &pb.MigrationTLSStatusRequest{})
	if err != nil {
		t.Fatalf("MigrationTLSStatus: %v", err)
	}
	rows := map[string]*pb.MigrationTLSHostStatus{}
	for _, r := range resp.GetHosts() {
		rows[r.GetHost()] = r
	}
	return rows
}

// One row per host, each host's own answer, asked through one daemon.
//
// Mutation: answer every row from s.localMigrationTLSStatus() — node-2's
// issuer reads "old".
func TestFleet_MigrationTLSStatusFansOutToEveryHost(t *testing.T) {
	c := New(t, Options{Nodes: 3, SharedCRDT: true})
	defer c.Stop()
	reportsCA(c.Nodes[0], "old", "old")
	reportsCA(c.Nodes[1], "new", "old", "new")
	reportsCA(c.Nodes[2], "old", "old", "new")
	c.Nodes[2].Server.SetAllowUnencryptedStorageMigration(true)

	rows := migrationTLSRows(t, c, c.Nodes[0])
	if len(rows) != 3 {
		t.Fatalf("got %d rows; want 3: %v", len(rows), rows)
	}
	if r := rows[c.Nodes[1].Name]; r.GetCertIssuerFingerprint() != "new" || len(r.GetTrustedCas()) != 2 {
		t.Errorf("%s row = %v; want its own answer (issuer new, two CAs)", c.Nodes[1].Name, r)
	}
	if !rows[c.Nodes[2].Name].GetAllowUnencryptedStorage() {
		t.Errorf("%s allows plaintext but its row does not say so", c.Nodes[2].Name)
	}
}

// A peer whose daemon cannot install its migration credentials says so in its
// row, through the fan-out, so the doctor and the rotation's gates see it.
//
// Mutation: do not copy the read-only check's error into the row — node-2's
// row reads clean.
func TestFleet_MigrationTLSStatusReportsAnInstallRefusal(t *testing.T) {
	c := New(t, Options{Nodes: 3, SharedCRDT: true})
	defer c.Stop()
	for _, n := range c.Nodes {
		reportsCA(n, "old", "old")
		migrationTLSReady(n, true)
	}
	c.Nodes[1].Server.SetMigrationTLSCheck(func() error {
		return errors.New("cannot tell which user QEMU runs as")
	})

	rows := migrationTLSRows(t, c, c.Nodes[0])
	if r := rows[c.Nodes[1].Name]; r == nil || !strings.Contains(r.GetInstallError(), "QEMU runs as") {
		t.Fatalf("%s row = %v; want its install refusal", c.Nodes[1].Name, r)
	}
	if r := rows[c.Nodes[2].Name]; r.GetInstallError() != "" || r.GetError() != "" {
		t.Errorf("healthy peer row = %v; want no install error", r)
	}
}

// A peer on an older build answers Unimplemented. It is a row with an error,
// not a failed call — the rotation needs to see the other hosts.
//
// Mutation: return the peer error from the handler — the call fails.
func TestFleet_MigrationTLSStatusReportsAnOldBuildAsARow(t *testing.T) {
	c := New(t, Options{Nodes: 3, SharedCRDT: true})
	defer c.Stop()
	for _, n := range c.Nodes {
		reportsCA(n, "old", "old")
	}
	defer c.Nodes[2].DoNotImplement("MigrationTLSStatus")()

	rows := migrationTLSRows(t, c, c.Nodes[0])
	if r := rows[c.Nodes[2].Name]; r == nil || r.GetError() == "" {
		t.Fatalf("old-build row = %v; want a row with an error", r)
	}
	if r := rows[c.Nodes[1].Name]; r.GetError() != "" {
		t.Errorf("healthy peer row carries error %q", r.GetError())
	}
}

// A partitioned host is a row with an error too.
//
// c.Partition only severs the fixed set of replication/state-sync RPCs
// (tests/fleet/cluster.go partitionedMethods) — MigrationTLSStatus is
// ordinary peer traffic, not one of those, so it is unaffected by Partition.
// SetLinkFaultBoth(..., LinkFault{Block: true, BlockAll: true}) is the
// harness's actual "every peer RPC fails in both directions" fault (see
// gossip_real.go's own use of BlockAll for the same reason), so that is what
// blocks this RPC.
func TestFleet_MigrationTLSStatusReportsAnUnreachableHostAsARow(t *testing.T) {
	c := New(t, Options{Nodes: 3, SharedCRDT: true})
	defer c.Stop()
	for _, n := range c.Nodes {
		reportsCA(n, "old", "old")
	}
	c.SetLinkFaultBoth(c.Nodes[0], c.Nodes[2], LinkFault{Block: true, BlockAll: true})
	defer c.ClearLinkFaults()

	rows := migrationTLSRows(t, c, c.Nodes[0])
	if r := rows[c.Nodes[2].Name]; r == nil || r.GetError() == "" {
		t.Fatalf("unreachable row = %v; want a row with an error", r)
	}
}

// A status report is a read on every host: asked through one daemon, no
// daemon runs its migration-TLS installer (the write into /etc/pki/qemu).
//
// Mutation: run the installer in localMigrationTLSStatus — installs != 0.
func TestFleet_MigrationTLSStatusInstallsNothing(t *testing.T) {
	c := New(t, Options{Nodes: 3, SharedCRDT: true})
	defer c.Stop()
	var installs atomic.Int32
	for _, n := range c.Nodes {
		reportsCA(n, "old", "old")
		n.Server.SetMigrationTLS(func() (bool, error) { installs.Add(1); return true, nil })
		n.Server.SetMigrationTLSCheck(func() error { return nil })
	}
	if rows := migrationTLSRows(t, c, c.Nodes[0]); len(rows) != 3 {
		t.Fatalf("got %d rows; want 3", len(rows))
	}
	if n := installs.Load(); n != 0 {
		t.Fatalf("a status report ran the migration-TLS installer %d time(s)", n)
	}
}

// A credential no role gate can evaluate (a token scoped to one project) is
// refused, both for the report and for one host's own row, end to end
// through the auth interceptor. A peer's own row is still answered.
//
// Mutations: drop the role gate (F2) — the scoped fan-out is answered; answer
// local_only before the gate (F3) — the scoped local_only call is answered.
func TestFleet_MigrationTLSStatusRefusesAScopedToken(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	defer c.Stop()
	for _, n := range c.Nodes {
		reportsCA(n, "old", "old")
	}
	ctx := context.Background()
	admin := c.SelfClient(c.Nodes[0])
	if _, err := admin.CreateUser(ctx, &pb.CreateUserRequest{Username: "scoped-bot", Password: "p4ssw0rd-0123456789", Role: "operator"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	tok, err := admin.CreateToken(ctx, &pb.CreateTokenRequest{Username: "scoped-bot", Name: "narrow",
		ScopePaths: []string{"/projects/_default/vms/one"}})
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	scoped := c.bearerClient(c.Nodes[0], tok.Token)
	for _, local := range []bool{false, true} {
		_, err := scoped.MigrationTLSStatus(ctx, &pb.MigrationTLSStatusRequest{LocalOnly: local})
		if code := status.Code(err); code != codes.PermissionDenied && code != codes.Unauthenticated {
			t.Errorf("scoped token, local_only=%v: err = %v; want refused", local, err)
		}
	}
	resp, err := c.PeerClient(c.Nodes[1], c.Nodes[0]).MigrationTLSStatus(ctx, &pb.MigrationTLSStatusRequest{LocalOnly: true})
	if err != nil || len(resp.GetHosts()) != 1 || resp.GetHosts()[0].GetHost() != c.Nodes[0].Name {
		t.Fatalf("peer's local_only call = %v, %v; want %s's own row", resp, err, c.Nodes[0].Name)
	}
}
