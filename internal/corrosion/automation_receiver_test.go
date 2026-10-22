package corrosion

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/pki"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"net"
	"testing"
)

func TestReceiverSchemaInertInventory(t *testing.T) {
	_, a, _, _ := threeVoters(t)
	for _, table := range []string{"local_automation_receiver_jobs", "local_automation_receiver_current", "local_automation_receiver_validations", "local_automation_receiver_sources", "local_automation_receiver_components", "local_automation_receiver_records", "local_automation_receiver_pages"} {
		rows, err := a.c.Query(context.Background(), `SELECT name FROM sqlite_master WHERE type='table' AND name=?`, table)
		if err != nil || len(rows) != 1 {
			t.Fatalf("durable inert receiver storage missing: %s (%v)", table, err)
		}
		if !IsNodeLocalClaimTable(table) || IsReplicatedTable(table) {
			t.Fatalf("receiver evidence is not exclusively local: %s", table)
		}
	}
	for _, schema := range []int{69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82} {
		if !supportedAutomationCutDescriptor(schema, 1) {
			t.Fatalf("explicit compatible descriptor %d/1 missing", schema)
		}
	}
	if !supportedAutomationCutDescriptor(83, 1) || !supportedAutomationCutDescriptor(84, 1) || !supportedAutomationCutDescriptor(85, 1) || !supportedAutomationCutDescriptor(86, 1) || supportedAutomationCutDescriptor(87, 1) || supportedAutomationCutDescriptor(71, 2) {
		t.Fatal("unknown source provenance accepted")
	}
}

// The receiver is the genuinely new b incarnation, with no old adoption. Its
// configs are ordinary certified values from actual a votes. Source export uses
// its real owner. Loopback TLS below observes actual local SQLite incarnation;
// this storage fixture does not claim the fleet's peer-role interceptor proof.
type receiverPeerServer struct {
	pb.UnimplementedLiteVirtServer
	c *Client
}

func (s receiverPeerServer) GetRecoveryClaim(ctx context.Context, q *pb.GetRecoveryClaimRequest) (*pb.GetRecoveryClaimResponse, error) {
	inc, err := s.c.VoterIncarnation(ctx)
	if err != nil {
		return nil, err
	}
	return &pb.GetRecoveryClaimResponse{State: &pb.PrepareRecoveryClaimResponse{Voter: s.c.hostName, VoterIncarnation: inc}}, nil
}
func receiverServe(t *testing.T, c *Client, dir string) HostRecord {
	t.Helper()
	cfg, err := pki.ServerTLSConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(cfg)))
	pb.RegisterLiteVirtServer(server, receiverPeerServer{c: c})
	go server.Serve(l)
	t.Cleanup(server.Stop)
	pair, err := pki.ServedHostKeyPair(dir)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return HostRecord{Name: c.hostName, Address: "127.0.0.1", SSHUser: "test", GRPCPort: l.Addr().(*net.TCPAddr).Port, CertSerial: leaf.SerialNumber.Text(16), State: "active"}
}
func receiverFixture(t *testing.T) (*AutomationSourcePreparer, *AutomationReceiver, AutomationExportRequest, context.Context, string) {
	return receiverFixtureSeed(t, nil)
}
func receiverFixtureSeed(t *testing.T, seed func(*claimTestVoter)) (*AutomationSourcePreparer, *AutomationReceiver, AutomationExportRequest, context.Context, string) {
	t.Helper()
	producer, intent, b := sourcePreparationFixtureWithSeed(t, "", seed)
	return receiverFixtureProducer(t, producer, intent, b)
}
func receiverFixtureProducer(t *testing.T, producer *AutomationSourcePreparer, intent AutomationSourceRequest, b *claimTestVoter) (*AutomationSourcePreparer, *AutomationReceiver, AutomationExportRequest, context.Context, string) {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	c, err := NewLocalClient(dir, "b")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	if err = InitSchema(ctx, c); err != nil {
		t.Fatal(err)
	}
	if _, err = c.VoterIncarnation(ctx); err != nil {
		t.Fatal(err)
	}
	// Preserve b's genuine already chosen lifetime when moving this fixture to
	// a file-backed replica, before any receiver attempt exists.
	if _, err = c.db.Exec(`UPDATE local_voter_incarnation SET incarnation=? WHERE id=1`, b.inc); err != nil {
		t.Fatal(err)
	}
	c.SetVoterConfigGate(func() bool { return true })
	b.c = c
	for g := int64(1); g <= intent.Generation+1; g++ {
		rows, err := producer.client.Query(ctx, `SELECT `+automationCutSections[8].columns+` FROM voter_configs WHERE generation=?`, g)
		if err != nil || len(rows) != 1 {
			t.Fatal(err)
		}
		cfg, err := sourceConfigRow(rows[0])
		if err != nil {
			t.Fatal(err)
		}
		cert, err := DecodeClaimCertificate(cfg.Certificate)
		if err != nil {
			t.Fatal(err)
		}
		if err = WriteVoterConfig(ctx, c, cfg.VoterConfigValue, cert); err != nil {
			t.Fatal(err)
		}
	}
	for _, host := range []HostRecord{receiverServe(t, producer.client, producer.dir), receiverServe(t, c, b.pki)} {
		for _, db := range []*Client{producer.client, c} {
			rows, e := db.Query(ctx, `SELECT name FROM hosts WHERE name=?`, host.Name)
			if e != nil {
				t.Fatal(e)
			}
			if len(rows) == 0 {
				if err = InsertHost(ctx, db, host); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err = db.db.Exec(`UPDATE hosts SET address=?,grpc_port=?,cert_serial=? WHERE name=?`, host.Address, host.GRPCPort, host.CertSerial, host.Name); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	intent.Target = "b"
	if err = producer.InitializePublication(ctx); err != nil {
		t.Fatal(err)
	}
	candidate, err := producer.Prepare(ctx, intent)
	if err != nil {
		t.Fatal(err)
	}
	id, err := producer.Publish(ctx, candidate)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := pki.ServedHostKeyPair(b.pki)
	if err != nil {
		t.Fatal(err)
	}
	var chain []*x509.Certificate
	for _, raw := range pair.Certificate {
		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			t.Fatal(err)
		}
		chain = append(chain, cert)
	}
	exportCtx := peer.NewContext(ctx, &peer.Peer{AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{HandshakeComplete: true, PeerCertificates: chain}}})
	return producer, NewAutomationReceiver(c, b.pki), AutomationExportRequest{Intent: intent, Publication: id, MaxRecords: 1}, exportCtx, dir
}
func TestReceiverActualAttemptAndExactPages(t *testing.T) {
	producer, receiver, request, exportCtx, _ := receiverFixture(t)
	ctx := context.Background()
	a, err := receiver.Begin(ctx, request.Intent, nil)
	if err != nil {
		t.Fatal("actual unadopted successor cannot establish receiver attempt", err)
	}
	again, err := receiver.Begin(ctx, request.Intent, nil)
	if err != nil || again.id != a.id {
		t.Fatal("exact begin changed immutable attempt", err)
	}
	for component := uint32(0); component < 12; component++ {
		request.Component = component
		request.Cursor = ""
		for {
			page, err := producer.ExportAutomationSource(exportCtx, request)
			if err != nil {
				t.Fatal(err)
			}
			progress, err := receiver.Stage(ctx, a, "a", request, page)
			if err != nil {
				t.Fatalf("actual page %d refused: %v", component, err)
			}
			retry, err := receiver.Stage(ctx, a, "a", request, page)
			if err != nil || retry != progress {
				t.Fatal("exact retry advanced or changed position", err)
			}
			if progress.Terminal != page.Terminal || progress.Cursor != page.Cursor {
				t.Fatal("stored progress differs")
			}
			if component < 2 && progress.Authenticated {
				t.Fatal("pending metadata acquired publication status")
			}
			if component >= 2 && !progress.Authenticated {
				t.Fatal("complete signed metadata never authenticated")
			}
			if component >= 3 {
				for _, raw := range page.Records {
					ordinal := progress.Records - int64(len(page.Records)) + 1
					row, err := receiver.client.Query(ctx, `SELECT record FROM local_automation_receiver_records WHERE attempt=? AND source='a' AND component=? AND ordinal=?`, a.id, component, ordinal)
					if err != nil || len(row) != 1 || !bytes.Equal(row[0].Bytes("record"), raw) {
						t.Fatal("full canonical payload lost", err)
					}
				}
			}
			if page.Terminal {
				break
			}
			request.Cursor = page.Cursor
		}
	}
}
