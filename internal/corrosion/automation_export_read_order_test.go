package corrosion

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"fmt"
	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/pki"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"modernc.org/sqlite"
	"net"
	"strings"
	"sync/atomic"
	"testing"
)

type exportReadDriver struct {
	driver.Driver
	bodies  *atomic.Int64
	records *atomic.Int64
	cuts    *atomic.Int64
}
type exportReadConn struct {
	driver.Conn
	bodies  *atomic.Int64
	records *atomic.Int64
	cuts    *atomic.Int64
}

func (d *exportReadDriver) Open(name string) (driver.Conn, error) {
	c, e := d.Driver.Open(name)
	if e != nil {
		return nil, e
	}
	return &exportReadConn{c, d.bodies, d.records, d.cuts}, nil
}
func (c *exportReadConn) BeginTx(ctx context.Context, o driver.TxOptions) (driver.Tx, error) {
	return c.Conn.(driver.ConnBeginTx).BeginTx(ctx, o)
}
func (c *exportReadConn) QueryContext(ctx context.Context, q string, a []driver.NamedValue) (driver.Rows, error) {
	projection := strings.SplitN(q, " FROM ", 2)[0]
	if c.cuts != nil && strings.Contains(q, "FROM local_automation_cuts") && strings.Contains(projection, "metadata") && !strings.Contains(projection, "length(") {
		c.cuts.Add(1)
	}
	if c.records != nil && strings.Contains(q, "FROM local_automation_cut_records") && strings.Contains(projection, "record") && !strings.Contains(projection, "length(") {
		c.records.Add(1)
	}
	if strings.Contains(q, "FROM local_automation_publications") && !strings.Contains(projection, "length(") && (strings.Contains(projection, "artifact") || strings.Contains(projection, "evidence") || strings.Contains(projection, "membership")) {
		c.bodies.Add(1)
	}
	return c.Conn.(driver.QueryerContext).QueryContext(ctx, q, a)
}

// A valid peer asking with the wrong existing job/revision must be refused
// before the exact persisted artifact/evidence bodies or manifest are decoded.
func TestSourceExportWrongContextBeforeEvidenceRead(t *testing.T) {
	p, r, ctx := exportFixtureAt(t, t.TempDir())
	var bodies atomic.Int64
	name := fmt.Sprintf("export-read-%d", sourceReadDriverSequence.Add(1))
	sql.Register(name, &exportReadDriver{Driver: &sqlite.Driver{}, bodies: &bodies})
	observed, err := sql.Open(name, p.client.dsn)
	if err != nil {
		t.Fatal(err)
	}
	original := p.client.db
	p.client.db = observed
	defer func() { p.client.db = original; observed.Close() }()
	if _, err := p.ExportAutomationSource(ctx, r); err != nil {
		t.Fatal("bounded positive export", err)
	}
	if bodies.Load() == 0 {
		t.Fatal("observer missed real evidence body reads")
	}
	for _, which := range []string{"job", "revision"} {
		t.Run(which, func(t *testing.T) {
			bad := r
			if which == "job" {
				bad.Intent.Job = "another"
			} else {
				bad.Intent.Revision++
			}
			before := bodies.Load()
			if _, err := p.ExportAutomationSource(ctx, bad); err == nil {
				t.Fatal("wrong context exported")
			}
			if bodies.Load() != before {
				t.Fatal("wrong context read publication evidence before pin authorization")
			}
		})
	}
}

// This receiver fixture answers from its actual independent storage incarnation.
// The producer uses its production expected-host TLS constructor; inbound
// contexts below remain storage-layer fixtures, separately covered by fleet TLS.
type exportStorageReceiver struct {
	pb.UnimplementedLiteVirtServer
	v *claimTestVoter
}

func (s *exportStorageReceiver) GetRecoveryClaim(ctx context.Context, r *pb.GetRecoveryClaimRequest) (*pb.GetRecoveryClaimResponse, error) {
	inc, e := s.v.c.VoterIncarnation(ctx)
	if e != nil {
		return nil, e
	}
	return &pb.GetRecoveryClaimResponse{State: &pb.PrepareRecoveryClaimResponse{Voter: s.v.name, VoterIncarnation: inc}}, nil
}
func TestSourceExportOtherTargetBeforeEvidenceRead(t *testing.T) {
	p, intent, b := sourcePreparationFixtureWithPeer(t, t.TempDir())
	ctx := context.Background()
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	cfg, e := pki.ServerTLSConfig(b.pki)
	if e != nil {
		t.Fatal(e)
	}
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(cfg)))
	pb.RegisterLiteVirtServer(server, &exportStorageReceiver{v: b})
	go server.Serve(listener)
	t.Cleanup(server.Stop)
	pair, e := pki.ServedHostKeyPair(b.pki)
	if e != nil {
		t.Fatal(e)
	}
	leaf, e := x509.ParseCertificate(pair.Certificate[0])
	if e != nil {
		t.Fatal(e)
	}
	if e = InsertHost(ctx, p.client, HostRecord{Name: b.name, Address: "127.0.0.1", GRPCPort: listener.Addr().(*net.TCPAddr).Port, CertSerial: leaf.SerialNumber.Text(16), State: "active"}); e != nil {
		t.Fatal(e)
	}
	if e = p.InitializePublication(ctx); e != nil {
		t.Fatal(e)
	}
	original, e := p.Prepare(ctx, intent)
	if e != nil {
		t.Fatal(e)
	}
	originalID, e := p.Publish(ctx, original)
	if e != nil {
		t.Fatal(e)
	}
	other := intent
	other.Target = b.name
	other.Job = "other-target"
	prepared, e := p.Prepare(ctx, other)
	if e != nil {
		t.Fatal(e)
	}
	otherID, e := p.Publish(ctx, prepared)
	if e != nil {
		t.Fatal(e)
	}
	otherCtx := peer.NewContext(ctx, &peer.Peer{AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{HandshakeComplete: true, PeerCertificates: []*x509.Certificate{leaf}}}})
	var bodies atomic.Int64
	name := fmt.Sprintf("export-target-read-%d", sourceReadDriverSequence.Add(1))
	sql.Register(name, &exportReadDriver{Driver: &sqlite.Driver{}, bodies: &bodies})
	observed, e := sql.Open(name, p.client.dsn)
	if e != nil {
		t.Fatal(e)
	}
	originalDB := p.client.db
	p.client.db = observed
	defer func() { p.client.db = originalDB; observed.Close() }()
	positive := AutomationExportRequest{Intent: other, Publication: otherID}
	if _, e = p.ExportAutomationSource(otherCtx, positive); e != nil {
		t.Fatal("other target legitimate positive", e)
	}
	if bodies.Load() == 0 {
		t.Fatal("observer missed actual positive body")
	}
	// Retain the original job/revision, change only the actual peer and intended
	// target. The publication header matches, so the owned recipient pin must act.
	bad := AutomationExportRequest{Intent: intent, Publication: originalID}
	bad.Intent.Target = b.name
	before := bodies.Load()
	if _, e = p.ExportAutomationSource(otherCtx, bad); e == nil {
		t.Fatal("other valid target exported original publication")
	}
	if bodies.Load() != before {
		t.Fatal("other valid target read evidence before recipient pin authorization")
	}
}

func TestSourceExportCursorRejectedBeforeEvidenceRead(t *testing.T) {
	p, r, ctx := exportFixtureAt(t, t.TempDir())
	r.Component = 3
	r.MaxRecords = 1
	first, e := p.ExportAutomationSource(ctx, r)
	if e != nil || first.Cursor == "" {
		t.Fatal("real continuation fixture", e)
	}
	var bodies atomic.Int64
	name := fmt.Sprintf("export-cursor-read-%d", sourceReadDriverSequence.Add(1))
	sql.Register(name, &exportReadDriver{Driver: &sqlite.Driver{}, bodies: &bodies})
	observed, e := sql.Open(name, p.client.dsn)
	if e != nil {
		t.Fatal(e)
	}
	original := p.client.db
	p.client.db = observed
	defer func() { p.client.db = original; observed.Close() }()
	r.Cursor = first.Cursor
	if _, e = p.ExportAutomationSource(ctx, r); e != nil {
		t.Fatal("positive continuation", e)
	}
	if bodies.Load() == 0 {
		t.Fatal("observer missed actual bodies")
	}
	for _, kind := range []string{"malformed", "tampered", "component", "publication", "overflow"} {
		t.Run(kind, func(t *testing.T) {
			bad := r
			switch kind {
			case "malformed":
				bad.Cursor = "!"
			case "tampered":
				raw, e := base64.RawURLEncoding.DecodeString(bad.Cursor)
				if e != nil {
					t.Fatal(e)
				}
				raw[len(raw)-1] ^= 1
				bad.Cursor = base64.RawURLEncoding.EncodeToString(raw)
			case "component":
				bad.Component++
			case "publication":
				bad.Publication = strings.Repeat("0", 64)
			case "overflow":
				pair, e := pki.ServedHostKeyPair(p.dir)
				if e != nil {
					t.Fatal(e)
				}
				key := pair.PrivateKey.(*ecdsa.PrivateKey)
				cursor, e := decodeSourceExportCursor(r.Cursor, &key.PublicKey)
				if e != nil {
					t.Fatal(e)
				}
				cursor.Position = -1
				bad.Cursor, e = cursor.encode(key)
				if e != nil {
					t.Fatal(e)
				}
			}
			before := bodies.Load()
			if _, e = p.ExportAutomationSource(ctx, bad); e == nil {
				t.Fatal("bad cursor exported")
			}
			if bodies.Load() != before {
				t.Fatal("bad cursor read publication bodies before rejection")
			}
		})
	}
}

func TestSourceExportLengthBeforePersistedBody(t *testing.T) {
	for _, kind := range []string{"artifact", "evidence", "membership", "record"} {
		t.Run(kind, func(t *testing.T) {
			p, r, ctx := exportFixtureAt(t, t.TempDir())
			r.Component = 3
			r.MaxRecords = 64
			var bodies, records atomic.Int64
			name := fmt.Sprintf("export-length-read-%d", sourceReadDriverSequence.Add(1))
			sql.Register(name, &exportReadDriver{Driver: &sqlite.Driver{}, bodies: &bodies, records: &records})
			observed, e := sql.Open(name, p.client.dsn)
			if e != nil {
				t.Fatal(e)
			}
			original := p.client.db
			p.client.db = observed
			defer func() { p.client.db = original; observed.Close() }()
			if _, e = p.ExportAutomationSource(ctx, r); e != nil {
				t.Fatal(e)
			}
			if bodies.Load() == 0 || records.Load() == 0 {
				t.Fatal("observer missed actual positive reads")
			}
			switch kind {
			case "artifact":
				e = p.client.ExecOutOfProcessForTest(`UPDATE local_automation_publications SET artifact=zeroblob(?)`, maxSourceArtifactBytes+1)
			case "evidence":
				e = p.client.ExecOutOfProcessForTest(`UPDATE local_automation_publications SET evidence=zeroblob(?)`, pki.MaxHostTrustEvidenceBytes+1)
			case "membership":
				e = p.client.ExecOutOfProcessForTest(`UPDATE local_automation_publications SET membership=zeroblob(?)`, maxSourceMembershipEvidenceBytes+1)
			case "record":
				e = p.client.ExecOutOfProcessForTest(`UPDATE local_automation_cut_records SET record=zeroblob(?) WHERE section=0 AND ordinal=1`, AutomationExportMaxBytes+1)
			}
			if e != nil {
				t.Fatal(e)
			}
			b, n := bodies.Load(), records.Load()
			if _, e = p.ExportAutomationSource(ctx, r); e == nil {
				t.Fatal("oversized persisted component exported")
			}
			if records.Load() != n || (kind != "record" && bodies.Load() != b) {
				t.Fatal("oversized persisted body loaded before bound check")
			}
		})
	}
}

func TestSourceExportCutHeaderLengthBeforeBody(t *testing.T) {
	for _, column := range []string{"root", "metadata"} {
		t.Run(column, func(t *testing.T) {
			p, r, ctx := exportFixtureAt(t, t.TempDir())
			var bodies, cuts atomic.Int64
			name := fmt.Sprintf("export-cut-read-%d", sourceReadDriverSequence.Add(1))
			sql.Register(name, &exportReadDriver{Driver: &sqlite.Driver{}, bodies: &bodies, cuts: &cuts})
			observed, e := sql.Open(name, p.client.dsn)
			if e != nil {
				t.Fatal(e)
			}
			original := p.client.db
			p.client.db = observed
			defer func() { p.client.db = original; observed.Close() }()
			if _, e = p.ExportAutomationSource(ctx, r); e != nil {
				t.Fatal(e)
			}
			if cuts.Load() == 0 {
				t.Fatal("observer missed actual metadata body")
			}
			if e = p.client.ExecOutOfProcessForTest(`UPDATE local_automation_cuts SET `+column+`=zeroblob(?)`, maxAutomationCutMetadataBytes+1); e != nil {
				t.Fatal(e)
			}
			before := cuts.Load()
			if _, e = p.ExportAutomationSource(ctx, r); e == nil {
				t.Fatal("oversized cut header exported")
			}
			if cuts.Load() != before {
				t.Fatal("oversized cut header body query before length preflight")
			}
		})
	}
}
