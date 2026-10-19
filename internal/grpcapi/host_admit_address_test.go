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

// copyHostRow puts name's row as from holds it into to, as replication
// delivers it: its address, port, state, serial and admission stamp.
func copyHostRow(t *testing.T, from, to *Server, name string) {
	t.Helper()
	rows, err := from.db.Query(context.Background(), `SELECT address, grpc_port, state, cert_serial, created_at, updated_at
		FROM hosts WHERE name = ?`, name)
	if err != nil || len(rows) != 1 {
		t.Errorf("read %s: %v (%d rows)", name, err, len(rows))
		return
	}
	r := rows[0]
	if _, err := to.db.DB().Exec(`INSERT INTO hosts (name, address, ssh_user, ssh_port, grpc_port, state, cert_serial,
		created_at, updated_at) VALUES (?, ?, 'root', 22, ?, ?, ?, ?, ?)`, name, r.String("address"), r.Int("grpc_port"),
		r.String("state"), r.String("cert_serial"), r.String("created_at"), r.String("updated_at")); err != nil {
		t.Error(err)
	}
}

// replicaPuller is one replica's currency pulls. The first (before the
// admission's write) finds nothing new. Each later one waits until every
// replica has written, then delivers the other replica's admission: the two
// admissions were made before either reached the other.
type replicaPuller struct {
	mu      sync.Mutex
	calls   int
	written *sync.WaitGroup
	deliver func()
}

func (p *replicaPuller) RunOnce(context.Context) bool { return true }
func (p *replicaPuller) PullTableNow(context.Context, string, string) (string, []string, error) {
	p.mu.Lock()
	p.calls++
	n := p.calls
	p.mu.Unlock()
	if n == 2 {
		p.written.Done()
		done := make(chan struct{})
		go func() { p.written.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
		}
	}
	if n >= 2 {
		p.deliver()
	}
	return "peer-host", nil, nil
}

// Codex 612c78ba I1: two replicas, each admitting a name at one address
// before the other's admission reached it, both admitted, and both CLIs went
// on to install on the one machine. Each admission now pulls the hosts table
// again after its write, and only the deterministic winner — the earlier
// admission, the lesser name on a tie — is answered; the other is refused
// with the command that removes it, so its CLI installs nothing.
//
// Mutation: drop the check after the write — both are admitted.
func TestAdmitHost_TwoReplicasAdmittingOneAddressAnswerOne(t *testing.T) {
	a, b := admissionServer(t), admissionServer(t)
	var written sync.WaitGroup
	written.Add(2)
	a.antiEntropy = &replicaPuller{written: &written, deliver: func() { copyHostRow(t, b, a, "node-b") }}
	b.antiEntropy = &replicaPuller{written: &written, deliver: func() { copyHostRow(t, a, b, "node-a") }}
	var errA, errB error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, errA = admitAt(a, "node-a", "10.0.0.9") }()
	go func() { defer wg.Done(); _, errB = admitAt(b, "node-b", "10.0.0.9") }()
	wg.Wait()
	stamp := func(s *Server, name string) string {
		rows, err := s.db.Query(context.Background(), `SELECT created_at FROM hosts WHERE name = ?`, name)
		if err != nil || len(rows) != 1 {
			t.Fatalf("read %s: %v", name, err)
		}
		return rows[0].String("created_at")
	}
	winner, loser, errWin, errLose := "node-a", "node-b", errA, errB
	if at, bt := stamp(a, "node-a"), stamp(b, "node-b"); bt < at {
		winner, loser, errWin, errLose = "node-b", "node-a", errB, errA
	}
	if errWin != nil {
		t.Errorf("the earlier admission, %s: %v", winner, errWin)
	}
	if status.Code(errLose) != codes.FailedPrecondition || !strings.Contains(errLose.Error(), winner) ||
		!strings.Contains(errLose.Error(), "lv host rm "+loser) {
		t.Errorf("the later admission, %s = %v, want a refusal naming %s and lv host rm %s", loser, errLose, winner, loser)
	}
}

// Codex 612c78ba I1: a rerun's admission of a joining name under the serial
// it was admitted with returned success at once, never checking the address,
// so a conflicting row the currency pull had just delivered did not stop its
// install. It is checked like any admission now.
//
// Mutation: drop the check after the write — the rerun is answered.
func TestAdmitHost_ARerunChecksAnAddressTheCurrencyPullDelivered(t *testing.T) {
	ctx := context.Background()
	s := admissionServer(t)
	if _, err := admit(s, "node-1"); err != nil {
		t.Fatal(err)
	}
	delivered := false
	s.antiEntropy = &fakePuller{pull: func() {
		if delivered {
			return
		}
		delivered = true
		if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: "other", Address: "10.0.0.9",
			GRPCPort: admitGRPCPort, State: corrosion.HostStateJoining, CertSerial: "ffee"}); err != nil {
			t.Error(err)
		}
		// Admitted before node-1 by the replica it came from.
		if _, err := s.db.DB().Exec(`UPDATE hosts SET created_at = '2000-01-01T00:00:00.000000000Z' WHERE name = 'other'`); err != nil {
			t.Error(err)
		}
	}}
	_, err := admit(s, "node-1")
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "other") ||
		!strings.Contains(err.Error(), "lv host rm node-1") {
		t.Fatalf("the rerun of node-1 with other delivered = %v, want a refusal naming other", err)
	}
}
