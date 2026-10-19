package corrosion

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// streamingPeer serves the two row streams, each empty, counting the streams
// opened. onPublic runs inside the n'th public stream (1-based), standing in
// for what merging that stream changes on the puller: a newer row for the
// peer, its isolation, or a CRL installed while it ran.
type streamingPeer struct {
	slowPeer
	mu        sync.Mutex
	public    int
	sensitive int
	onPublic  func(n int)
}

func (p *streamingPeer) StreamTableRows(_ *pb.TableDumpRequest, _ grpc.ServerStreamingServer[pb.TableRowsPage]) error {
	return p.openPublic()
}

// The blob dumps the stand-down pulls over count as the same streams.
func (p *streamingPeer) StreamTableDump(_ *pb.TableDumpRequest, _ grpc.ServerStreamingServer[pb.StateDumpChunk]) error {
	return p.openPublic()
}

func (p *streamingPeer) StreamSensitiveStateDump(_ *pb.SensitiveStateRequest, _ grpc.ServerStreamingServer[pb.StateDumpChunk]) error {
	return p.openSensitive()
}

func (p *streamingPeer) openPublic() error {
	p.mu.Lock()
	p.public++
	n, f := p.public, p.onPublic
	p.mu.Unlock()
	if f != nil {
		f(n)
	}
	return nil
}

func (p *streamingPeer) StreamSensitiveTableRows(_ *pb.SensitiveStateRequest, _ grpc.ServerStreamingServer[pb.TableRowsPage]) error {
	return p.openSensitive()
}

func (p *streamingPeer) openSensitive() error {
	p.mu.Lock()
	p.sensitive++
	p.mu.Unlock()
	return nil
}

func (p *streamingPeer) counts() (int, int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.public, p.sensitive
}

// openDriftingExchange opens an exchange with peer-a whose public digest
// differs from ours on tables and whose sensitive digest differs on
// user_credentials, so finishing it opens a public pull, then the sensitive
// lane's cluster_policies pull, then the sensitive stream.
func openDriftingExchange(t *testing.T, peer *streamingPeer, tables ...string) (*AntiEntropy, *Client, string, *peerExchange, map[string]TableDigest) {
	t.Helper()
	pkiDir := testPKI(t, "self")
	c := newPruneTestClient(t)
	port, _ := servePeer(t, pkiDir, peer)
	addPeerHost(t, c, "peer-a", port, "aa01")
	c.SetMembersForTests(aeMembers("peer-a"))
	ae := newTestAE(t, c, pkiDir)
	ex := ae.openExchange(context.Background(), "peer-a", nil, false)
	if ex == nil {
		t.Fatal("precondition: no exchange opened with a reachable, unisolated peer")
	}
	local := map[string]TableDigest{}
	ex.digest = &pb.StateDigestResponse{}
	for _, tbl := range tables {
		ex.digest.Tables = append(ex.digest.Tables, &pb.TableDigest{Name: tbl, Count: 1, Hash: "peer"})
		local[tbl] = TableDigest{Count: 1, Hash: "local"}
	}
	ex.sensitive = &sensitiveExchange{
		digest: &pb.StateDigestResponse{Tables: []*pb.TableDigest{{Name: "user_credentials", Count: 1, Hash: "peer"}}},
		local:  map[string]TableDigest{"user_credentials": {Count: 1, Hash: "local"}},
	}
	return ae, c, pkiDir, ex, local
}

// The changes a public merge can bring in about the peer it came from.
var midExchangeChanges = []struct {
	name   string
	change func(t *testing.T, c *Client, pkiDir string)
}{
	{"certificate serial", func(t *testing.T, c *Client, _ string) {
		if _, err := c.DB().Exec(`UPDATE hosts SET cert_serial = 'bb02' WHERE name = 'peer-a'`); err != nil {
			t.Error(err)
		}
	}},
	{"local CRL", func(t *testing.T, _ *Client, pkiDir string) {
		if err := os.WriteFile(filepath.Join(pkiDir, "crl.pem"), []byte("newer"), 0o600); err != nil {
			t.Error(err)
		}
	}},
	{"isolation", func(t *testing.T, c *Client, _ string) {
		if err := IsolateHost(context.Background(), c, "self", "peer-a", "manual"); err != nil {
			t.Error(err)
		}
	}},
}

// A public merge that changes the peer's identity, the local CRL or the
// peer's isolation stops the exchange before its next stream: the sensitive
// lane's pulls ran over the old session, checked once at the exchange's
// start.
func TestFinishExchange_RechecksThePeerBeforeTheSensitivePull(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		for _, tc := range midExchangeChanges {
			name := tc.name
			if legacy {
				name += "/stand-down blob dump"
			}
			t.Run(name, func(t *testing.T) {
				peer := &streamingPeer{}
				ae, c, pkiDir, ex, local := openDriftingExchange(t, peer, "vms")
				ae.legacyRepair = legacy
				peer.onPublic = func(n int) {
					if n == 1 {
						tc.change(t, c, pkiDir)
					}
				}
				if ae.finishExchange(context.Background(), ex, local, false) {
					t.Error("an exchange whose peer changed under its public merge completed")
				}
				pub, sens := peer.counts()
				if pub != 1 || sens != 0 {
					t.Errorf("streams opened after the change: public=%d sensitive=%d, want public=1 sensitive=0", pub, sens)
				}
				if !ex.pc.isClosed() || ae.conns.lookup("peer-a") != nil {
					t.Error("the obsolete connection was kept")
				}
			})
		}
	}
}

// The policy-first pull is a stream of its own: a change it merges stops the
// feature tables' pull that follows it.
func TestFinishExchange_RechecksThePeerAfterThePolicyFirstPull(t *testing.T) {
	for _, tc := range midExchangeChanges {
		t.Run(tc.name, func(t *testing.T) {
			peer := &streamingPeer{}
			ae, c, pkiDir, ex, local := openDriftingExchange(t, peer, "cluster_policies", "vms")
			ex.sensitive = nil
			peer.onPublic = func(n int) {
				if n == 1 {
					tc.change(t, c, pkiDir)
				}
			}
			if ae.finishExchange(context.Background(), ex, local, false) {
				t.Error("an exchange whose peer changed under its policy-first merge completed")
			}
			if pub, _ := peer.counts(); pub != 1 {
				t.Errorf("%d public streams opened, want only the policy-first one", pub)
			}
		})
	}
}

// Nothing changing, the same exchange opens all three streams and completes:
// the recheck refuses only a change.
func TestFinishExchange_AnUnchangedPeerGetsEveryPull(t *testing.T) {
	peer := &streamingPeer{}
	ae, _, _, ex, local := openDriftingExchange(t, peer, "vms")
	if !ae.finishExchange(context.Background(), ex, local, false) {
		t.Error("an exchange with an unchanged peer did not complete")
	}
	if pub, sens := peer.counts(); pub != 2 || sens != 1 {
		t.Errorf("streams: public=%d sensitive=%d, want public=2 (vms, then the sensitive lane's cluster_policies) sensitive=1", pub, sens)
	}
}

// olderPeer is a peer on an older build: every narrower dump answers
// Unimplemented, and the pull falls back to the next. change runs inside the
// RPC named by changeIn, before its Unimplemented answer goes back.
type olderPeer struct {
	slowPeer
	mu       sync.Mutex
	opened   []string
	changeIn string
	change   func()
}

func (p *olderPeer) open(rpc string) {
	p.mu.Lock()
	p.opened = append(p.opened, rpc)
	f := p.change
	if rpc != p.changeIn {
		f = nil
	}
	p.mu.Unlock()
	if f != nil {
		f()
	}
}

func (p *olderPeer) calls() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.opened...)
}

func (p *olderPeer) StreamTableDump(_ *pb.TableDumpRequest, _ grpc.ServerStreamingServer[pb.StateDumpChunk]) error {
	p.open("StreamTableDump")
	return status.Error(codes.Unimplemented, "older build")
}

func (p *olderPeer) StreamStateDump(_ *emptypb.Empty, _ grpc.ServerStreamingServer[pb.StateDumpChunk]) error {
	p.open("StreamStateDump")
	return status.Error(codes.Unimplemented, "older build")
}

func (p *olderPeer) GetStateDump(context.Context, *emptypb.Empty) (*pb.StateDumpResponse, error) {
	p.open("GetStateDump")
	return &pb.StateDumpResponse{}, nil
}

// A change that lands while an older peer's Unimplemented answer is in flight
// stops the fallback it would have opened next: each fallback is a new stream
// (or a unary call) over the old session, and is re-checked like any other.
func TestFinishExchange_RechecksThePeerBeforeEachLegacyFallback(t *testing.T) {
	for _, in := range []struct{ rpc, wantLast string }{
		{"StreamTableDump", "StreamTableDump"},
		{"StreamStateDump", "StreamStateDump"},
	} {
		for _, tc := range midExchangeChanges {
			t.Run(in.rpc+"/"+tc.name, func(t *testing.T) {
				pkiDir := testPKI(t, "self")
				c := newPruneTestClient(t)
				peer := &olderPeer{changeIn: in.rpc}
				port, _ := servePeer(t, pkiDir, peer)
				addPeerHost(t, c, "peer-a", port, "aa01")
				c.SetMembersForTests(aeMembers("peer-a"))
				ae := newTestAE(t, c, pkiDir)
				ae.legacyRepair = true
				ex := ae.openExchange(context.Background(), "peer-a", nil, false)
				if ex == nil {
					t.Fatal("precondition: no exchange opened")
				}
				ex.digest = &pb.StateDigestResponse{Tables: []*pb.TableDigest{{Name: "vms", Count: 1, Hash: "peer"}}}
				local := map[string]TableDigest{"vms": {Count: 1, Hash: "local"}}
				peer.change = func() { tc.change(t, c, pkiDir) }

				if ae.finishExchange(context.Background(), ex, local, false) {
					t.Error("an exchange whose peer changed under a fallback completed")
				}
				calls := peer.calls()
				if len(calls) == 0 || calls[len(calls)-1] != in.wantLast {
					t.Errorf("RPCs opened: %v; nothing may follow the %s the change landed in", calls, in.wantLast)
				}
				if !ex.pc.isClosed() || ae.conns.lookup("peer-a") != nil {
					t.Error("the obsolete connection was kept")
				}
			})
		}
	}
}
