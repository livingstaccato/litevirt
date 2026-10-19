package grpcapi

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// admissionServer is a seeded, caught-up admitter, as AdmitHost requires.
func admissionServer(t *testing.T) *Server {
	t.Helper()
	ctx := context.Background()
	s := testServer(t)
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: s.hostName, Address: "10.0.0.1", State: "active"}); err != nil {
		t.Fatal(err)
	}
	if err := s.db.MarkAuditSeeded(ctx, "genesis"); err != nil {
		t.Fatal(err)
	}
	s.db.MarkReplicaCaughtUpForTests("peer")
	return s
}

// barrierPuller is the currency pull an admission makes before its write. It
// holds each pull until n have arrived, so every admission has passed its
// earlier reads before any writes.
type barrierPuller struct {
	mu      sync.Mutex
	arrived int
	n       int
	all     chan struct{}
}

func (p *barrierPuller) RunOnce(context.Context) bool { return true }
func (p *barrierPuller) PullTableNow(context.Context, string, string) (string, []string, error) {
	p.mu.Lock()
	p.arrived++
	if p.arrived == p.n {
		close(p.all)
	}
	p.mu.Unlock()
	select {
	case <-p.all:
	case <-time.After(10 * time.Second):
	}
	return "peer-host", nil, nil
}

func liveAt(t *testing.T, s *Server, addr string) []string {
	t.Helper()
	rows, err := s.db.Query(context.Background(), `SELECT name FROM hosts WHERE address = ? AND deleted_at IS NULL`, addr)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, r := range rows {
		out = append(out, r.String("name"))
	}
	return out
}

// Codex cand30 I1: two admissions of distinct names at one address, each held
// after its address check has read no holder, both committed. The check now
// runs again inside the admission's write transaction: one is admitted, the
// other refused naming it, and nothing of the refused one is written or
// logged.
//
// Mutation: drop the guard from the insert — both are admitted.
func TestAdmitHost_ConcurrentAdmissionsAtOneAddressAdmitOne(t *testing.T) {
	s := admissionServer(t)
	s.antiEntropy = &barrierPuller{n: 2, all: make(chan struct{})}
	names := []string{"node-a", "node-b"}
	errs := make([]error, len(names))
	var wg sync.WaitGroup
	for i, n := range names {
		wg.Add(1)
		go func(i int, n string) {
			defer wg.Done()
			_, errs[i] = admitAt(s, n, "10.0.0.9")
		}(i, n)
	}
	wg.Wait()
	var won, lost []string
	for i, err := range errs {
		switch {
		case err == nil:
			won = append(won, names[i])
		case status.Code(err) == codes.FailedPrecondition:
			lost = append(lost, names[i])
			other := names[1-i]
			if !strings.Contains(err.Error(), "lv host rm "+other) || !strings.Contains(err.Error(), "lv host rm --dead "+other) {
				t.Errorf("the refusal of %s does not name %s: %v", names[i], other, err)
			}
		default:
			t.Errorf("%s: %v", names[i], err)
		}
	}
	if len(won) != 1 || len(lost) != 1 {
		t.Fatalf("admitted %v, refused %v; want one of each", won, lost)
	}
	if got := liveAt(t, s, "10.0.0.9"); len(got) != 1 || got[0] != won[0] {
		t.Errorf("live hosts at the address: %v, want only %s", got, won[0])
	}
	ml, err := s.db.Query(context.Background(), `SELECT stmts FROM mutation_log WHERE stmts LIKE ?`, "%"+lost[0]+"%")
	if err != nil {
		t.Fatal(err)
	}
	if len(ml) != 0 {
		t.Errorf("the refused admission of %s was logged for peers: %v", lost[0], ml)
	}
}

// Codex cand30 I1: AdmitHost read the address before its currency pull, so a
// peer's admission at the address that arrived in the pull was never checked.
//
// Mutation: drop the guard from the insert — node-1 is admitted beside other.
func TestAdmitHost_AnAddressArrivingInTheCurrencyPullIsRefused(t *testing.T) {
	ctx := context.Background()
	s := admissionServer(t)
	s.antiEntropy = &fakePuller{pull: func() {
		if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: "other", Address: "10.0.0.9",
			GRPCPort: admitGRPCPort, State: corrosion.HostStateJoining, CertSerial: "ffee"}); err != nil {
			t.Error(err)
		}
	}}
	_, err := admit(s, "node-1")
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "lv host rm other") ||
		!strings.Contains(err.Error(), "lv host rm --dead other") {
		t.Fatalf("admit with other arriving in the pull = %v, want a refusal naming it", err)
	}
	if h, _ := corrosion.GetHost(ctx, s.db, "node-1"); h != nil {
		t.Error("the refused host was admitted")
	}
}
