package fleet

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
	automationv1 "github.com/livingstaccato/litevirt/api/gen/litevirt/automation/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

func remainingOwnerLogin(t *testing.T, c nativeOwnerClient, hard time.Duration) (nativeOwnerClient, time.Time) {
	t.Helper()
	n := c.f.cluster.Nodes[0]
	n.Server.SetSessionTimeouts(time.Hour, hard)
	r, e := c.f.cluster.SelfClient(n).Login(c.f.Context(), &pb.LoginRequest{Username: nativeOwnerUsername, Password: "native-owner-password-0123456789", Realm: "local"})
	if e != nil || !strings.HasPrefix(r.GetToken(), grpcapi.SessionTokenPrefix) {
		t.Fatalf("actual expiring Login failed: %v", e)
	}
	expiry, e := time.Parse(time.RFC3339, r.GetExpiresAt())
	if e != nil || !time.Now().Before(expiry) {
		t.Fatalf("Login expiry is not future: %v", e)
	}
	p, e := corrosion.AutomationSessionPrincipal(c.f.Context(), n.DB, strings.TrimPrefix(r.GetToken(), grpcapi.SessionTokenPrefix))
	if e != nil || p == nil || p.UID != nativeOwnerPrincipalUID || p.ClusterUID != c.f.Head(t, 0).ClusterUID {
		t.Fatalf("expiring Login lacks actual stable provenance: %+v %v", p, e)
	}
	c.ctx = metadata.AppendToOutgoingContext(c.f.Context(), "authorization", "Bearer "+r.GetToken())
	return c, expiry
}

// Extend the native origin's actual vote to a real same-ballot majority using
// the actual origin's authenticated peer RPC. The normal certificate verifier
// proves chosen status. It is deliberately NOT installed/applied in setup.
func remainingOwnerChooseWithoutPublish(t *testing.T, c nativeOwnerClient, s corrosion.ClaimVoterState) {
	t.Helper()
	origin, holder := c.f.cluster.Nodes[0], c.f.cluster.Nodes[1]
	r, e := c.f.cluster.PeerClient(origin, holder).AcceptRecoveryClaim(c.f.Context(), &pb.AcceptRecoveryClaimRequest{
		Key: claimKeyPB(s.Key), ConfigGeneration: s.ConfigGeneration,
		Ballot: &pb.ClaimBallot{Round: s.Accepted.Round, Coordinator: s.Accepted.Coordinator, BootNonce: append([]byte(nil), s.Accepted.Nonce...)},
		Value:  &pb.RecoveryClaimValue{Automation: &pb.AutomationClaimValue{Envelope: append([]byte(nil), s.Value.Automation.Envelope...)}},
	})
	if e != nil || !r.GetAccepted() || r.GetAccept() == nil {
		t.Fatalf("actual same-ballot second vote: %+v %v", r, e)
	}
	second, found, e := holder.DB.ClaimState(c.f.Context(), s.Key)
	if e != nil || !found || second.Accept == nil || second.Value == nil || !second.Accepted.Equal(s.Accepted) || second.ValueDigest != s.ValueDigest {
		t.Fatalf("second stored vote not same-ballot exact value: %+v %v", second, e)
	}
	cfg, e := corrosion.AdoptedVoterConfig(c.f.Context(), holder.DB)
	if e != nil {
		t.Fatal(e)
	}
	v, e := corrosion.LoadClaimVerifier(holder.PKIDir)
	if e != nil {
		t.Fatal(e)
	}
	cert := corrosion.ClaimCertificate{Key: s.Key, ConfigGeneration: s.ConfigGeneration, Ballot: s.Accepted, ValueDigest: s.ValueDigest, Accepts: []corrosion.ClaimAccept{*s.Accept, *second.Accept}}
	if e := v.Verify(cert, corrosion.CertExpectation{Key: s.Key, ConfigGeneration: cfg.Generation, ValueDigest: s.ValueDigest, Electorate: cfg.Members, Quorum: corrosion.MajorityOf(len(cfg.Members))}); e != nil {
		t.Fatalf("not actually chosen: %v", e)
	}
}

func TestAutomationOwnerSessionNativeChosenOriginLossActualExpiry(t *testing.T) {
	c, expiry := remainingOwnerLogin(t, newNativeOwnerClient(t, false), 10*time.Second)
	before, s := nativeOwnerUnpublished(t, c)
	remainingOwnerChooseWithoutPublish(t, c, s)
	if !time.Now().Before(expiry) {
		t.Fatal("fixture failed to choose while the actual bearer remained valid")
	}
	c.assertNoOwnerEffects(t, before, "unpublished-native-owner")
	c.f.Isolate(0)
	t.Cleanup(func() { c.f.Heal(0) })
	nativeOwnerWaitExpiry(t, c.f.Context(), expiry)
	// Isolate cuts peer links, not the source's self RPC. Prove that actual
	// bearer authentication now refuses before any surviving recovery occurs.
	if _, e := c.f.cluster.SelfClient(c.f.cluster.Nodes[0]).Whoami(c.ctx, &emptypb.Empty{}); status.Code(e) != codes.Unauthenticated {
		t.Fatalf("expired bearer still authenticates or expiry was not exercised: %v", e)
	}
	r, e := c.f.Engine(1).Submit(c.f.Context(), c.f.Barrier(1, "chosen-origin-loss-real-expiry"))
	if e != nil || r.Sequence != before.Sequence+2 {
		t.Fatalf("surviving holder did not recover chosen owner before barrier: %+v %v", r, e)
	}
	for _, n := range c.f.cluster.Nodes[1:] {
		record, found, e := n.DB.AutomationRecord(c.f.Context(), before.Sequence+1)
		if e != nil || !found || record.Value.Automation == nil || !bytes.Equal(record.Value.Automation.Envelope, s.Value.Automation.Envelope) {
			t.Fatalf("%s lost/changed original chosen bytes: %+v %v", n.Name, record, e)
		}
	}
	c.f.Heal(0)
	c.f.Converge(t)
	c.assertDecision(t, &automationv1.ReadCursor{AppliedSequence: before.Sequence + 1}, "ensure_owner", "unpublished-native-owner", "", 0)
	c.assertOwner(t, "", 0)
}

func remainingOwnerJoin(t *testing.T, done <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s did not terminate after actual server stop", what)
	}
}

func TestAutomationOwnerSessionNativeServerRestartBeforeAcceptReply(t *testing.T) {
	nativeOwnerRestartBeforeAcceptReply(t, false)
}

func TestAutomationOwnerSessionNativeDiskReopenBeforeAcceptReply(t *testing.T) {
	nativeOwnerRestartBeforeAcceptReply(t, true)
}

func nativeOwnerRestartBeforeAcceptReply(t *testing.T, persistent bool) {
	f := newAutomationFixtureWithStorage(t, 3, true, nil, persistent)
	if persistent {
		for _, node := range f.cluster.Nodes {
			info, e := os.Stat(filepath.Join(f.cluster.tmpRoot, node.Name, "state", "state.db"))
			if e != nil || !info.Mode().IsRegular() || info.Size() == 0 {
				t.Fatalf("persistent fixture was not on disk before Login: %v", e)
			}
			level, e := node.DB.SynchronousLevel(f.Context())
			if e != nil || level < corrosion.SynchronousFull {
				t.Fatalf("native voter file is not FULL: %d %v", level, e)
			}
		}
	}
	c := newNativeOwnerClientWithFixture(t, f, false)
	n := c.f.cluster.Nodes[0]
	before := c.f.Head(t, 0)
	key, e := corrosion.AutomationClaimKey(before.Sequence + 1)
	if e != nil {
		t.Fatal(e)
	}
	request := &automationv1.EnsureOwnerRequest{Owner: c.owner, RequestId: "native-restart-before-accept-reply"}
	callCtx := make(chan context.Context, 1)
	committed, observerExited, handlerExited, clientExited := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	clientResult := make(chan error, 1)
	ctx, cancel := context.WithTimeout(c.ctx, 25*time.Second)
	var observed sync.Once
	// Capture the real SERVER context, which Node.Stop cancels. Do not use a
	// caller-created boolean as an indication of a daemon exit.
	n.HookUnary("EnsureOwner", func(serverCtx context.Context, req any, next grpc.UnaryHandler) (any, error) {
		defer close(handlerExited)
		callCtx <- serverCtx
		return next(serverCtx, req)
	})
	n.Server.SetClaimVoteObserverForTest(func(v grpcapi.ClaimVote) {
		if v.Phase != "accept" || v.Key != key {
			return
		}
		observed.Do(func() {
			serverCtx := <-callCtx
			close(committed)
			<-serverCtx.Done()
			close(observerExited)
		})
	})
	t.Cleanup(func() {
		cancel()
		select {
		case <-clientExited:
		case <-time.After(5 * time.Second):
			t.Error("restart client call did not join")
		}
		// On a failed precondition this also unblocks the observer by ending
		// the actual server transport; no background owner may outlive cleanup.
		downNode(n)
		select {
		case <-handlerExited:
		case <-time.After(5 * time.Second):
			t.Error("restart handler did not join")
		}
	})
	go func() { defer close(clientExited); _, e := c.public.EnsureOwner(ctx, request); clientResult <- e }()
	select {
	case <-committed:
	case e := <-clientResult:
		t.Fatalf("request returned before native commit: %v", e)
	case <-ctx.Done():
		t.Fatal("native commit not reached")
	}
	s, found, e := n.DB.ClaimState(c.f.Context(), key)
	if e != nil || !found || s.Accept == nil || s.Value == nil || s.ValueDigest == "" {
		t.Fatalf("native postcommit boundary lacks stored signed vote: %+v %v", s, e)
	}
	c.assertNoOwnerEffects(t, before, request.RequestId)
	// Use exactly the supported restart ownership sequence, with an extra
	// explicit handler/client join BEFORE constructing the replacement server.
	downNode(n)
	remainingOwnerJoin(t, observerExited, "native postcommit observer")
	remainingOwnerJoin(t, handlerExited, "old public handler")
	remainingOwnerJoin(t, clientExited, "old public client")
	if e := <-clientResult; e == nil {
		t.Fatal("stopped native call returned public success")
	}
	c.assertNoOwnerEffects(t, before, request.RequestId)
	oldServer := n.Server
	if persistent {
		remainingOwnerReopenFleet(t, c)
	} else {
		restartNode(t, c.f.cluster, n) // existing supported in-process server restart
	}
	if n.Server == oldServer {
		t.Fatal("restart did not replace process-owned Server")
	}
	// Restore existing fixture enforcement, not any owner permission. The
	// real credential issuance, electorate and signed vote remain in storage.
	enableRecoveryClaims(t, c.f.cluster, n)
	n.Server.SetAuthEngine(auth.NewEngine(n.DB))
	engine, e := n.Server.AutomationEngine()
	if e != nil {
		t.Fatal(e)
	}
	c.f.engines[0] = engine
	after, found, e := n.DB.ClaimState(c.f.Context(), key)
	if e != nil || !found || after.Value == nil || after.Accept == nil || !bytes.Equal(after.Value.Automation.Envelope, s.Value.Automation.Envelope) || !reflect.DeepEqual(after.Accept, s.Accept) {
		t.Fatalf("server restart lost actual stored signature/value: %+v %v", after, e)
	}
	c.f.cluster.SelfClient(n) // creates a new real TLS connection after Stop
	c.public = automationv1.NewAutomationClient(n.selfConn)
	r, e := c.public.EnsureOwner(c.ctx, request)
	if e != nil {
		t.Fatalf("restart could not recover original authorized accepted bytes: %v", e)
	}
	record, found, e := n.DB.AutomationRecord(c.f.Context(), before.Sequence+1)
	if e != nil || !found || record.Value.Automation == nil || !bytes.Equal(record.Value.Automation.Envelope, s.Value.Automation.Envelope) {
		t.Fatalf("restart retry changed original accepted bytes: %+v %v", record, e)
	}
	c.assertDecision(t, r.GetCursor(), "ensure_owner", request.RequestId, "", 0)
	c.assertOwner(t, "", 0)
}

// All three stores were files before genesis/Login/issuance. Join their
// server/replicator DB users, close every original handle, and open those same
// files. There is no snapshot copy or shared-memory keeper in this boundary.
func remainingOwnerReopenFleet(t *testing.T, c nativeOwnerClient) {
	t.Helper()
	cluster := c.f.cluster
	old := make([]*corrosion.Client, len(cluster.Nodes))
	servers := make([]*grpcapi.Server, len(cluster.Nodes))
	incarnations := make([]string, len(cluster.Nodes))
	for i, n := range cluster.Nodes {
		old[i] = n.DB
		inc, e := n.DB.VoterIncarnation(c.f.Context())
		if e != nil {
			t.Fatal(e)
		}
		incarnations[i] = inc
		servers[i] = n.Server
		n.Server.StopDeleteVMAdmission()
		n.Server.StopFirewallTagAdmission()
		n.Server.StopMigrationAdmission()
	}
	for _, server := range servers {
		server.WaitDeleteVMWork()
	}
	cluster.checkReplicatedShapes()
	for _, n := range cluster.Nodes {
		n.Server.StopDHCPReservations()
		if n.stopServerLoops != nil {
			n.stopServerLoops()
		}
	}
	cluster.waitLBWork()
	// Keep peer transports and replication available until the current
	// server's captured child joins finish, as Cluster.Stop/downNode do.
	for _, n := range cluster.Nodes {
		if n.replStarted {
			n.repl.Stop()
			n.replStarted = false
		}
	}
	// Match Cluster.Stop: stop peer transports concurrently so an admitted
	// handler awaiting another peer cannot strand sequential shutdown.
	var transports sync.WaitGroup
	for _, n := range cluster.Nodes {
		transports.Add(1)
		go func(n *Node) {
			defer transports.Done()
			n.GRPCSrv.GracefulStop()
			if n.serveDone != nil {
				<-n.serveDone
			}
		}(n)
	}
	transports.Wait()
	cluster.waitLBWork()
	for _, server := range servers {
		server.WaitFirewallTagWork()
		server.WaitGatewayAnnouncements()
	}
	for _, n := range cluster.Nodes {
		n.Stop()
	}
	for _, db := range old {
		if e := db.Close(); e != nil {
			t.Fatalf("close original voter file: %v", e)
		}
	}
	for _, db := range old {
		if _, e := db.Query(c.f.Context(), "SELECT 1"); e == nil {
			t.Fatal("old voter handle stayed usable across purported close")
		}
	}
	for i, n := range cluster.Nodes {
		cluster.openDB(n, false)
		if n.DB == old[i] {
			t.Fatal("file reopen reused original client")
		}
		inc, e := n.DB.VoterIncarnation(c.f.Context())
		if e != nil || inc != incarnations[i] {
			t.Fatalf("file reopen changed durable voter incarnation: %q %v", inc, e)
		}
		level, e := n.DB.SynchronousLevel(c.f.Context())
		if e != nil || level < corrosion.SynchronousFull {
			t.Fatalf("reopened voter file lost FULL: %d %v", level, e)
		}
	}
	cluster.seedGossipMembership()
	openVoterConfigGates(cluster)
	for _, n := range cluster.Nodes {
		n.rebindPort(t)
		cluster.buildServer(n)
	}
	enableRecoveryClaims(t, cluster)
	for i, n := range cluster.Nodes {
		n.Server.SetAuthEngine(auth.NewEngine(n.DB))
		e, err := n.Server.AutomationEngine()
		if err != nil {
			t.Fatal(err)
		}
		c.f.engines[i] = e
	}
	cluster.startReplicators()
}
