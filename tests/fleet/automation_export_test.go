package fleet

import (
	"bytes"
	"context"
	"crypto/tls"
	"github.com/litevirt/litevirt/internal/pki"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Removing the real peer exporter must prevent a legitimate successor from
// receiving the exact artifact committed by the actual publication owner.
func exportFleetFixture(t *testing.T) (*Cluster, *Node, *Node, *pb.AutomationSourceExportRequest, []byte) {
	t.Helper()
	ctx := context.Background()
	c := New(t, Options{Nodes: 4, IndependentReplicas: true, FaultSeed: 52631})
	source, target, removed, parked := c.Nodes[0], c.Nodes[1], c.Nodes[2], c.Nodes[3]
	initVoters(t, c, parked, source, target, removed)
	old := voterRow(t, source, 1)
	if err := source.DB.SealVoterGeneration(ctx, 1, "export test"); err != nil {
		t.Fatal(err)
	}
	engine, err := source.Server.AutomationEngine()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.FreezeMembershipCut(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SelfClient(target).ChangeVoterConfig(ctx, &pb.ChangeVoterConfigRequest{Op: "rm", Host: removed.Name}); err != nil {
		t.Fatal(err)
	}
	adoptAll(t, c, 2)
	if err := source.Server.InitializeAutomationSource(ctx); err != nil {
		t.Fatal(err)
	}
	intent := corrosion.AutomationSourceRequest{Generation: 1, Target: target.Name, Job: "peer-export", Revision: 1, Sources: old.Members}
	preparation, err := source.Server.PrepareAutomationSource(ctx, intent)
	if err != nil {
		t.Fatal(err)
	}
	id, err := source.Server.PublishAutomationSource(ctx, preparation)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := source.DB.Query(ctx, `SELECT artifact FROM local_automation_publications WHERE id=?`, id)
	if err != nil || len(rows) != 1 {
		t.Fatal("committed artifact missing", err)
	}
	req := &pb.AutomationSourceExportRequest{Version: 1, Purpose: "automation-membership-source", Stream: "automation", Generation: 1, Target: target.Name, Job: intent.Job, Revision: 1, PublicationId: id}
	for _, m := range old.Members {
		req.Sources = append(req.Sources, &pb.ClaimVoterMember{Name: m.Name, Incarnation: m.Incarnation})
	}
	return c, source, target, req, rows[0].Bytes("artifact")
}
func TestFleet_AutomationExportPublishedArtifact(t *testing.T) {
	c, source, target, req, artifact := exportFleetFixture(t)
	stream, err := c.PeerClient(target, source).ExportAutomationSource(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	assertExportArtifact(t, stream, req.PublicationId, artifact)
}
func assertExportArtifact(t *testing.T, stream grpc.ServerStreamingClient[pb.AutomationSourceExportResponse], id string, artifact []byte) {
	t.Helper()
	page, err := stream.Recv()
	if err != nil {
		t.Fatal("authorized export", err)
	}
	if !page.Terminal || page.PublicationId != id || !bytes.Equal(page.Chunk, artifact) {
		t.Fatal("export changed exact committed artifact")
	}
	if _, err = stream.Recv(); err != io.EOF {
		t.Fatal("one operation emitted more than one page", err)
	}
}

// Required when enabled: a real normal-interface connection, with no fleet
// address rewrite or fake dialer. The certificate's DNS SAN verifies the server.
func TestFleet_AutomationExportDirectTLS(t *testing.T) {
	address := os.Getenv("LITEVIRT_EXPORT_TEST_ADDRESS")
	if address == "" {
		t.Skip("explicit normal-interface fixture address not enabled")
	}
	ip := net.ParseIP(address)
	if ip == nil || ip.IsLoopback() {
		t.Fatal("required fixture must use a normal non-loopback interface")
	}
	c, source, target, req, artifact := exportFleetFixture(t)
	listener, err := net.Listen("tcp", net.JoinHostPort(address, "0"))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := pki.ServerTLSConfig(source.PKIDir)
	if err != nil {
		t.Fatal(err)
	}
	tracker := pki.NewConnTracker(source.PKIDir)
	server := grpc.NewServer(grpc.Creds(tracker.ServerCreds(credentials.NewTLS(cfg))), grpc.StatsHandler(tracker.StatsHandler()), grpc.ChainUnaryInterceptor(source.Server.UnaryAuthInterceptor), grpc.ChainStreamInterceptor(source.Server.StreamAuthInterceptor, source.hookStreamInterceptor))
	pb.RegisterLiteVirtServer(server, source.Server)
	go server.Serve(listener)
	t.Cleanup(server.Stop)
	dial := func(cfg *tls.Config) pb.LiteVirtClient {
		t.Helper()
		cfg.ServerName = source.Name
		conn, e := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { conn.Close() })
		return pb.NewLiteVirtClient(conn)
	}
	targetTLS, err := pki.PeerTLSConfig(target.PKIDir)
	if err != nil {
		t.Fatal(err)
	}
	client := dial(targetTLS)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	stream, err := client.ExportAutomationSource(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	assertExportArtifact(t, stream, req.PublicationId, artifact)
	reject := func(t *testing.T, client pb.LiteVirtClient, ctx context.Context, r *pb.AutomationSourceExportRequest) {
		t.Helper()
		stream, e := client.ExportAutomationSource(ctx, r)
		if e == nil {
			_, e = stream.Recv()
		}
		if e == nil {
			t.Fatal("unauthorized export succeeded")
		}
	}

	t.Run("valid-admin-and-forwarded-bearer", func(t *testing.T) {
		admin := c.SelfClient(source)
		if _, e := admin.CreateUser(ctx, &pb.CreateUserRequest{Username: "export-admin", Password: "test-fixture-password", Role: "admin"}); e != nil {
			t.Fatal(e)
		}
		token, e := admin.CreateToken(ctx, &pb.CreateTokenRequest{Username: "export-admin", Name: "export-gate"})
		if e != nil {
			t.Fatal(e)
		}

		bearerCtx := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token.Token)
		who, e := client.Whoami(bearerCtx, &emptypb.Empty{})
		if e != nil || who.Username != "export-admin" || who.Role != "admin" {
			t.Fatal("real valid admin credential positive", who, e)
		}
		reject(t, client, bearerCtx, req)
		forwardedCtx := metadata.AppendToOutgoingContext(ctx, pki.FwdBearerMDKey, "Bearer "+token.Token)
		// A relayed user token also refuses when identity promotion is disabled.
		reject(t, client, forwardedCtx, req)
		gates := gateAll(t, c)
		for _, n := range c.Nodes {
			n.Server.SetForwardedIdentity(true)
		}
		eventually(t, 10*time.Second, "actual forwarded identity capability", func() bool { return gates[source.Name].Enforced(ctx, capabilities.ForwardedIdentityV1) })
		who, e = client.Whoami(forwardedCtx, &emptypb.Empty{})
		if e != nil || who.Username != "export-admin" || who.Role != "admin" {
			t.Fatal("real promoted admin credential positive", who, e)
		}
		reject(t, client, forwardedCtx, req)

	})
	for _, kind := range []string{"wrong-target", "wrong-job", "wrong-revision", "wrong-publication", "forwarded", "bearer", "purpose", "stream", "unknown", "metadata-count", "metadata-value"} {
		t.Run(kind, func(t *testing.T) {
			bad := proto.Clone(req).(*pb.AutomationSourceExportRequest)
			callCtx := ctx
			switch kind {
			case "wrong-target":
				bad.Target = source.Name
			case "wrong-job":
				bad.Job = "different"
			case "wrong-revision":
				bad.Revision++
			case "wrong-publication":
				bad.PublicationId = string(bytes.Repeat([]byte("0"), 64))
			case "forwarded":
				callCtx = metadata.AppendToOutgoingContext(ctx, pki.FwdBearerMDKey, "not-a-user-token")
			case "bearer":
				callCtx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer not-a-user-token")
			case "purpose":
				bad.Purpose = "recovery"
			case "stream":
				bad.Stream = "claims"
			case "unknown":
				bad.ProtoReflect().SetUnknown([]byte{0xa0, 6, 1})
			case "metadata-count":
				for i := 0; i < 33; i++ {
					callCtx = metadata.AppendToOutgoingContext(callCtx, "x-export", "x")
				}
			case "metadata-value":
				callCtx = metadata.AppendToOutgoingContext(ctx, "x-export", string(bytes.Repeat([]byte("x"), 2049)))
			}
			reject(t, client, callCtx, bad)
		})
	}
	t.Run("current-target-reimage", func(t *testing.T) {
		inc, e := target.DB.VoterIncarnation(ctx)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = target.DB.ReplaceVoterIncarnationForTest(ctx); e != nil {
			t.Fatal(e)
		}
		reject(t, client, ctx, req)
		if e = target.DB.ExecOutOfProcessForTest(`UPDATE local_voter_incarnation SET incarnation=? WHERE id=1`, inc); e != nil {
			t.Fatal(e)
		}
		stream, e := client.ExportAutomationSource(ctx, req)
		if e != nil {
			t.Fatal(e)
		}
		assertExportArtifact(t, stream, req.PublicationId, artifact)
	})
	t.Run("expected-host-address", func(t *testing.T) {
		host, e := corrosion.GetHost(ctx, source.DB, target.Name)
		if e != nil {
			t.Fatal(e)
		}
		other := c.Nodes[2]
		if e = source.DB.ExecOutOfProcessForTest(`UPDATE hosts SET address=?,grpc_port=? WHERE name=?`, other.Address, other.Port, target.Name); e != nil {
			t.Fatal(e)
		}
		reject(t, client, ctx, req)
		if e = source.DB.ExecOutOfProcessForTest(`UPDATE hosts SET address=?,grpc_port=? WHERE name=?`, host.Address, host.GRPCPort, target.Name); e != nil {
			t.Fatal(e)
		}
	})
	t.Run("current-policy-and-toggle-during-observation", func(t *testing.T) {
		source.Server.SetTrustRotatedPeerCerts(true)
		reject(t, client, ctx, req)
		source.Server.SetTrustRotatedPeerCerts(false)
		reached := false
		target.HookUnary("GetRecoveryClaim", func(callCtx context.Context, raw any, h grpc.UnaryHandler) (any, error) {
			reached = true
			source.Server.SetTrustRotatedPeerCerts(true)
			source.Server.SetTrustRotatedPeerCerts(false)
			return h(callCtx, raw)
		})
		reject(t, client, ctx, req)
		if !reached {
			t.Fatal("real target observation hook not reached")
		}
		stream, e := client.ExportAutomationSource(ctx, req)
		if e != nil {
			t.Fatal(e)
		}
		assertExportArtifact(t, stream, req.PublicationId, artifact)
	})
	t.Run("ordinary-client", func(t *testing.T) {
		dir := t.TempDir()
		cert, key := filepath.Join(dir, "client.crt"), filepath.Join(dir, "client.key")
		if e := pki.GenerateClientCert(c.caCert, c.caKey, cert, key, "export-operator"); e != nil {
			t.Fatal(e)
		}
		pair, e := tls.LoadX509KeyPair(cert, key)
		if e != nil {
			t.Fatal(e)
		}
		cfg := targetTLS.Clone()
		cfg.GetClientCertificate = nil
		cfg.Certificates = []tls.Certificate{pair}
		reject(t, dial(cfg), ctx, req)
	})
	t.Run("two-slots-through-send", func(t *testing.T) {
		entered := make(chan struct{}, 2)
		done := make(chan struct{}, 2)
		hook := func(srv any, ss grpc.ServerStream, h grpc.StreamHandler) error {
			defer func() { done <- struct{}{} }()
			return h(srv, &exportBlockedSend{ServerStream: ss, entered: entered})
		}
		var cancels []context.CancelFunc
		for i := 0; i < 2; i++ {
			source.HookStream("ExportAutomationSource", hook)
			callCtx, stop := context.WithCancel(ctx)
			cancels = append(cancels, stop)
			defer stop()
			if _, e := client.ExportAutomationSource(callCtx, req); e != nil {
				t.Fatal(e)
			}
			select {
			case <-entered:
			case <-ctx.Done():
				t.Fatal("export never held slot through Send")
			}
		}
		started := time.Now()
		third, e := client.ExportAutomationSource(ctx, req)
		if e == nil {
			_, e = third.Recv()
		}
		if status.Code(e) != codes.ResourceExhausted || time.Since(started) > time.Second {
			t.Fatal("saturation did not refuse immediately", e, time.Since(started))
		}
		for _, stop := range cancels {
			stop()
		}
		for i := 0; i < 2; i++ {
			select {
			case <-done:
			case <-ctx.Done():
				t.Fatal("cancelled Send did not release handler")
			}
		}
		retry, e := client.ExportAutomationSource(ctx, req)
		if e != nil {
			t.Fatal(e)
		}
		assertExportArtifact(t, retry, req.PublicationId, artifact)
	})
	t.Run("local-root", func(t *testing.T) { reject(t, c.SelfClient(source), ctx, req) })
	t.Run("other-valid-peer", func(t *testing.T) {
		otherTLS, e := pki.PeerTLSConfig(source.PKIDir)
		if e != nil {
			t.Fatal(e)
		}
		other := dial(otherTLS)
		bad := proto.Clone(req).(*pb.AutomationSourceExportRequest)
		bad.Target = source.Name
		// Prove this peer can export its own actual publication, then refuse the
		// other target's publication under the same otherwise valid current identity.
		own := proto.Clone(bad).(*pb.AutomationSourceExportRequest)
		own.Job = "own-direct"
		own.PublicationId = ""
		s, e := other.ExportAutomationSource(ctx, own)
		if e != nil {
			t.Fatal(e)
		}
		page, e := s.Recv()
		if e != nil || !page.Terminal {
			t.Fatal("other legitimate target positive", e)
		}
		reject(t, other, ctx, bad)
	})
}

type exportBlockedSend struct {
	grpc.ServerStream
	entered chan<- struct{}
}

func (s *exportBlockedSend) SendMsg(any) error {
	s.entered <- struct{}{}
	<-s.Context().Done()
	return s.Context().Err()
}

// These are actual near-limit chosen decisions, persisted by real accepts and
// Install, then frozen and published. Synthetic exact-wire tests live separately.
func TestFleet_AutomationExportManyLargePages(t *testing.T) {
	f, old, cutID := largeAutomationCutFixture(t)
	c := f.cluster
	source, target, removed := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	ctx := f.ctx
	if _, e := c.SelfClient(target).ChangeVoterConfig(ctx, &pb.ChangeVoterConfigRequest{Op: "rm", Host: removed.Name}); e != nil {
		t.Fatal(e)
	}
	adoptAll(t, c, old.Generation+1)
	if e := source.Server.InitializeAutomationSource(ctx); e != nil {
		t.Fatal(e)
	}
	intent := corrosion.AutomationSourceRequest{Generation: old.Generation, Target: target.Name, Job: "many-pages", Revision: 1, Sources: old.Members}
	candidate, e := source.Server.PrepareAutomationSource(ctx, intent)
	if e != nil {
		t.Fatal(e)
	}
	id, e := source.Server.PublishAutomationSource(ctx, candidate)
	if e != nil {
		t.Fatal(e)
	}
	req := &pb.AutomationSourceExportRequest{Version: 1, Purpose: "automation-membership-source", Stream: "automation", Generation: intent.Generation, Target: target.Name, Job: intent.Job, Revision: 1, PublicationId: id}
	for _, m := range old.Members {
		req.Sources = append(req.Sources, &pb.ClaimVoterMember{Name: m.Name, Incarnation: m.Incarnation})
	}
	client := c.PeerClient(target, source)
	for _, section := range []uint32{0, 2} {
		req.Component = section + 3
		req.Cursor = ""
		expected, e := source.DB.Query(ctx, `SELECT record FROM local_automation_cut_records WHERE cut_id=? AND section=? ORDER BY ordinal`, cutID, section)
		if e != nil {
			t.Fatal(e)
		}
		index, pages, total, biggest, maxCount := 0, 0, 0, 0, 0
		for {
			stream, e := client.ExportAutomationSource(ctx, req)
			if e != nil {
				t.Fatal(e)
			}
			page, e := stream.Recv()
			if e != nil {
				t.Fatal(e)
			}
			if _, e = stream.Recv(); e != io.EOF {
				t.Fatal("extra page", e)
			}
			raw, e := proto.Marshal(page)
			if e != nil || len(raw) >= 4194304 {
				t.Fatal("complete authorized page exceeds default client", len(raw), e)
			}
			retry, e := client.ExportAutomationSource(ctx, req)
			if e != nil {
				t.Fatal(e)
			}
			again, e := retry.Recv()
			if e != nil || !proto.Equal(page, again) {
				t.Fatal("actual immutable retry changed", e)
			}
			pageBytes := 0
			for _, record := range page.Records {
				if index >= len(expected) || !bytes.Equal(record, expected[index].Bytes("record")) {
					t.Fatal("actual published bytes omitted or changed", section, index)
				}
				index++
				pageBytes += len(record)
				if len(record) > biggest {
					biggest = len(record)
				}
			}
			if len(page.Records) > maxCount {
				maxCount = len(page.Records)
			}
			total += pageBytes
			pages++
			if len(page.Records) > 64 || pageBytes > 3670016 {
				t.Fatal("production count/byte page overflow")
			}
			if page.Terminal {
				if index != len(expected) || page.TerminalRecords != int64(index) || page.TerminalBytes != int64(total) {
					t.Fatal("signed terminal count/bytes differs")
				}
				break
			}
			if page.Cursor == "" || pages > 200 {
				t.Fatal("missing/nonterminating cursor")
			}
			req.Cursor = page.Cursor
		}
		if pages < 2 {
			t.Fatal("fixture did not exercise several pages", section)
		}
		if section == 0 && maxCount != 64 {
			t.Fatal("finite default never filled a count-bound page", maxCount)
		}
		if section == 2 && biggest < 1<<20 {
			t.Fatal("near-limit accepted history not exported")
		}
		t.Logf("authorized component=%d pages=%d records=%d bytes=%d largest raw=%d", section+3, pages, index, total, biggest)
	}
}

func TestFleet_AutomationExportArchivedAfterLaterAdoption(t *testing.T) {
	c, source, target, req, artifact := exportFleetFixture(t)
	ctx := context.Background()
	client := c.PeerClient(target, source)
	parked := c.Nodes[3]
	for _, op := range []string{"add", "rm"} {
		if _, e := c.SelfClient(target).ChangeVoterConfig(ctx, &pb.ChangeVoterConfigRequest{Op: op, Host: parked.Name}); e != nil {
			t.Fatal(e)
		}
		generation := int64(3)
		if op == "rm" {
			generation = 4
		}
		adoptAll(t, c, generation)
	}
	positive := func() {
		t.Helper()
		stream, e := client.ExportAutomationSource(ctx, req)
		if e != nil {
			t.Fatal(e)
		}
		assertExportArtifact(t, stream, req.PublicationId, artifact)
	}
	positive()
	result, e := source.DB.ClaimPrepare(ctx, corrosion.ClaimKey{TargetKind: corrosion.ClaimKindVM, TargetName: "later-live-promise", OwnerEpoch: 1}, corrosion.Ballot{Round: 1, Coordinator: source.Name, Nonce: []byte("later-live")}, 4)
	if e != nil || !result.Promised {
		t.Fatal("later live write", result, e)
	}
	positive()
	newRevision := proto.Clone(req).(*pb.AutomationSourceExportRequest)
	newRevision.Revision++
	newRevision.PublicationId = ""
	stream, e := client.ExportAutomationSource(ctx, newRevision)
	if e != nil {
		t.Fatal(e)
	}
	next, e := stream.Recv()
	if e != nil || next.PublicationId == req.PublicationId {
		t.Fatal("explicit next revision publication", e)
	}
	positive()
	for _, kind := range []string{"missing-intermediate-adoption", "forced-intermediate-config"} {
		t.Run(kind, func(t *testing.T) {
			var restore func()
			switch kind {
			case "missing-intermediate-adoption":
				if e := source.DB.ExecOutOfProcessForTest(`UPDATE local_voter_adoption SET generation=100 WHERE generation=3`); e != nil {
					t.Fatal(e)
				}
				restore = func() {
					if e := source.DB.ExecOutOfProcessForTest(`UPDATE local_voter_adoption SET generation=3 WHERE generation=100`); e != nil {
						t.Fatal(e)
					}
				}
			case "forced-intermediate-config":
				rows, e := source.DB.Query(ctx, `SELECT change FROM voter_configs WHERE generation=3`)
				if e != nil || len(rows) != 1 {
					t.Fatal(e)
				}
				original := rows[0].String("change")
				if e = source.DB.ExecOutOfProcessForTest(`UPDATE voter_configs SET change='force:invalid' WHERE generation=3`); e != nil {
					t.Fatal(e)
				}
				restore = func() {
					if e := source.DB.ExecOutOfProcessForTest(`UPDATE voter_configs SET change=? WHERE generation=3`, original); e != nil {
						t.Fatal(e)
					}
				}
			}
			defer restore()
			stream, e := client.ExportAutomationSource(ctx, req)
			if e == nil {
				_, e = stream.Recv()
			}
			if e == nil {
				t.Fatal("archived export ignored changed intermediate normal ancestry")
			}
		})
		positive()
	}
}
