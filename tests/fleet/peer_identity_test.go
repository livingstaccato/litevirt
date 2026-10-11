// Fleet scenarios for the caller identity a peer's call carries
// (peer_identity.go). Until the harness presented a peer's connection with the
// peer's own address, every node-to-node call in tests/fleet arrived from
// loopback and was classified as the on-node root, so no rule that refuses a
// PEER could be reached here. These pin that it can: each is red under
// FLEET_LOOPBACK_PEERS=1, the old view.

package fleet

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// TestFleet_PeerIdentity_APeerCannotAcknowledgeALeaseTermTie: another node's
// daemon is refused outright, before the request is even read, while the
// on-node root reaches the request's own validation. The fleet's lease-term
// tie test had to leave this to a grpcapi unit test, because every fleet
// node then dialled from loopback.
func TestFleet_PeerIdentity_APeerCannotAcknowledgeALeaseTermTie(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	ctx := context.Background()
	a, b := c.Node("node-0"), c.Node("node-1")
	req := &pb.AcknowledgeLeaseTermTieRequest{Key: "no-such-lease", Term: 1}

	_, err := c.PeerClient(b, a).AcknowledgeLeaseTermTie(ctx, req)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("%s's daemon acknowledging a tie on %s: err = %v, want PermissionDenied "+
			"(a node must never acknowledge a contest it may be party to)", b.Name, a.Name, err)
	}
	// Control: the same request from the on-node root gets past the peer
	// refusal to the request's own validation.
	if _, err := c.SelfClient(a).AcknowledgeLeaseTermTie(ctx, req); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("on-node root: err = %v, want InvalidArgument for the unknown key", err)
	}
}

// TestFleet_PeerIdentity_AHostKeyFromOffTheBoxCannotResetAdmin: reset-admin is
// root on THIS host and nothing wider. Its own certificate is not enough — a
// copy of host.key used from another machine names the right host and must
// still be refused, which only the transport tells apart. The existing fleet
// test's peer case (another node's certificate) is refused by the name check
// too, so it could not see the transport check go.
func TestFleet_PeerIdentity_AHostKeyFromOffTheBoxCannotResetAdmin(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	ctx := context.Background()
	a := c.Node("node-0")
	if err := corrosion.InsertUser(ctx, a.DB, "admin", "admin", "old-hash"); err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("fleet-reset-password-0123456789"), auth.BcryptCost)
	if err != nil {
		t.Fatal(err)
	}
	req := &pb.ResetAdminPasswordRequest{PasswordHash: string(hash)}

	if _, err := c.RemoteClient(a).ResetAdminPassword(ctx, req); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("%s's own certificate from off the box: err = %v, want PermissionDenied", a.Name, err)
	}
	if u, _ := corrosion.GetUser(ctx, a.DB, "admin"); u == nil || u.PasswordHash != "old-hash" {
		t.Fatal("a reset from off the box changed the admin password")
	}
	// Control: the same request over the local root channel is accepted.
	if _, err := c.SelfClient(a).ResetAdminPassword(ctx, req); err != nil {
		t.Fatalf("over the local root channel: %v", err)
	}
}

// TestFleet_PeerIdentity_TheOwnerJudgesAForwardedCallAsTheUser is forwarded
// identity end to end, which no fleet scenario could reach before: a peer's
// relayed bearer is promoted to the user only for a PEER, and every fleet peer
// used to be the on-node root.
//
// An operator's session is revoked, and the revocation has reached the VM's
// owner but not the node the operator talks to (owner→entry replication is
// blocked). The entry still accepts the session and forwards the stop; the
// owner, judging the forwarded call as the operator, refuses it. Judged as
// the forwarding peer — an admin — the revoked session would stop the VM.
func TestFleet_PeerIdentity_TheOwnerJudgesAForwardedCallAsTheUser(t *testing.T) {
	c := New(t, Options{Nodes: 2, IndependentReplicas: true, FaultSeed: 1224})
	ctx := context.Background()
	entry, owner := c.Node("node-0"), c.Node("node-1")
	gates := gateAll(t, c)
	for _, n := range c.Nodes {
		n.Server.SetForwardedIdentity(true)
	}
	for _, n := range c.Nodes {
		g := gates[n.Name]
		eventually(t, 10*time.Second, n.Name+" to latch forwarded_identity_v1", func() bool {
			return g.Enforced(ctx, capabilities.ForwardedIdentityV1)
		})
	}

	if _, err := c.SelfClient(entry).CreateUser(ctx, &pb.CreateUserRequest{
		Username: "op", Password: "op-password-0123456789", Role: "operator",
	}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	login, err := c.SelfClient(entry).Login(ctx, &pb.LoginRequest{Username: "op", Password: "op-password-0123456789"})
	if err != nil || !strings.HasPrefix(login.GetToken(), grpcapi.SessionTokenPrefix) {
		t.Fatalf("Login: %+v %v", login, err)
	}
	for _, vm := range []string{"fw-ok", "fw-revoked"} {
		if err := corrosion.InsertVM(ctx, owner.DB, corrosion.VMRecord{
			Name: vm, HostName: owner.Name, State: "running", Spec: "{}",
		}, nil, nil); err != nil {
			t.Fatalf("InsertVM %s: %v", vm, err)
		}
		owner.Virt.SetState(vm, libvirtfake.StateRunning)
	}
	c.WaitConverged(t, convergeTimeout)
	op := c.bearerClient(entry, login.GetToken())

	// Control: the forwarded stop lands, promoted to the operator on the owner.
	if _, err := op.StopVM(ctx, &pb.StopVMRequest{Name: "fw-ok", Force: true}); err != nil {
		t.Fatalf("forwarded stop with a live session: %v", err)
	}

	c.SetLinkFault(owner, entry, LinkFault{Block: true})
	sid := strings.TrimPrefix(login.GetToken(), grpcapi.SessionTokenPrefix)
	if err := corrosion.RevokeSession(ctx, owner.DB, sid); err != nil {
		t.Fatalf("revoke on %s: %v", owner.Name, err)
	}
	// The precondition the refusal below depends on: the entry node, which has
	// not heard of the revocation, still accepts the session. Without it an
	// Unauthenticated could be the entry's own refusal, never reaching the owner.
	if _, err := op.ListVMs(ctx, &pb.ListVMsRequest{}); err != nil {
		t.Fatalf("the entry node no longer accepts the session (the revocation reached it?): %v", err)
	}
	if s, _ := corrosion.GetSession(ctx, entry.DB, sid); s == nil || s.RevokedAt != "" {
		t.Fatalf("the entry node's copy of the session is %+v; the scenario needs it live there", s)
	}
	_, err = op.StopVM(ctx, &pb.StopVMRequest{Name: "fw-revoked", Force: true})
	// "forwarded session revoked" is the OWNER's refusal of a promoted bearer
	// (authenticateForwardedBearer); the entry's own would not say forwarded.
	if status.Code(err) != codes.Unauthenticated || !strings.Contains(status.Convert(err).Message(), "forwarded session revoked") {
		t.Fatalf("forwarded stop with a session the owner holds revoked: err = %v, want the owner's Unauthenticated "+
			"(forwarded session revoked) — the owner judged the forwarded call as the forwarding peer, not as the operator", err)
	}
	if st, _ := owner.Virt.DomainState("fw-revoked"); st != "running" {
		t.Fatalf("fw-revoked is %q on %s; a revoked session stopped it", st, owner.Name)
	}
}

// TestFleetHarness_ARemoteClientMarkIsGoneOnceItsConnectionCloses: the mark
// RemoteClient leaves on a connection's local address is removed when the
// connection closes, so a later loopback connection the kernel hands the same
// ephemeral port is classified on its own certificate, not as a peer.
func TestFleetHarness_ARemoteClientMarkIsGoneOnceItsConnectionCloses(t *testing.T) {
	var m remoteMarks
	a, b := net.Pipe()
	defer b.Close()
	const addr = "127.0.0.1:40000"
	m.mark(addr, 1)
	conn := &markedConn{Conn: a, unmark: func() { m.unmark(addr) }}
	if i, ok := m.lookup(addr); !ok || i != 1 {
		t.Fatalf("lookup before close = %d, %v; want 1, true", i, ok)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.lookup(addr); ok {
		t.Fatal("the mark outlived its connection")
	}
}

// TestFleetHarness_ARemoteClientsMarkIsGoneOnceItCloses: closing a
// RemoteClient connection removes the mark its dialer left, end to end — the
// dialer hands gRPC the connection that unmarks, not the raw one.
func TestFleetHarness_ARemoteClientsMarkIsGoneOnceItCloses(t *testing.T) {
	c := New(t, Options{Nodes: 1})
	a := c.Nodes[0]
	cc := c.remoteConn(a)
	if _, err := pb.NewLiteVirtClient(cc).Ping(context.Background(), &pb.PingRequest{}); err != nil {
		t.Fatalf("Ping over the remote connection: %v", err)
	}
	if n := c.remote.marked(); n != 1 {
		t.Fatalf("%d connections marked after a dial, want 1", n)
	}
	if err := cc.Close(); err != nil {
		t.Fatal(err)
	}
	eventually(t, 5*time.Second, "the closed connection's mark to go", func() bool { return c.remote.marked() == 0 })
}
