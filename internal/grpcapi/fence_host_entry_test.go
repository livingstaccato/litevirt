package grpcapi

import (
	"context"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fence"
)

// `lv host fence` and `lv host fence-confirm` write the host's state and the
// fence row as ONE replicated entry. As two, a leader cycle between them saw
// an operator-fenced host 'offline' with no successful fence row, cached it as
// handled and never resumed its recovery; and a 'fenced' state could reach a
// peer before the confirmation that proves it (colonelpanik/litevirt#253).
//
// Mutation: write UpdateHostState and InsertFenceLog separately again — each
// case finds the state in an entry of its own and goes red.
func TestFenceHost_StateAndRowShareOneEntry(t *testing.T) {
	for _, tc := range []struct {
		name    string
		req     *pb.FenceHostRequest
		state   string
		wantRow string
	}{
		{"fence", &pb.FenceHostRequest{Name: "peer", Confirmed: true}, "offline", "ssh"},
		{"fence-confirm", &pb.FenceHostRequest{Name: "peer", Confirmed: true, ConfirmManualOnly: true}, "fenced", "manual-confirmed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := fenceTestServer(t, false, false)
			ctx := context.Background()
			if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
				Name: "peer", Address: "10.0.0.2", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "active", FenceStrategy: "ssh",
			}); err != nil {
				t.Fatal(err)
			}
			s.SetFenceExecutor(func(context.Context, fence.HostConfig) fence.Result {
				return fence.Result{Method: "ssh", Detail: "poweroff sent", Success: true}
			})
			if _, err := s.FenceHost(adminCtx(), tc.req); err != nil {
				t.Fatalf("FenceHost: %v", err)
			}
			rows, err := s.db.Query(ctx, `SELECT stmts FROM mutation_log`)
			if err != nil {
				t.Fatalf("read mutation_log: %v", err)
			}
			var withRow []string
			stateAlone := 0
			for _, r := range rows {
				st := r.String("stmts")
				switch {
				case strings.Contains(st, "INTO fencing_log"):
					withRow = append(withRow, st)
				case strings.Contains(st, "UPDATE hosts SET state") && strings.Contains(st, `"`+tc.state+`"`):
					stateAlone++
				}
			}
			if len(withRow) != 1 || !strings.Contains(withRow[0], "UPDATE hosts SET state") || !strings.Contains(withRow[0], tc.wantRow) {
				t.Errorf("fence row entries = %v; want one carrying the host's %q state", withRow, tc.state)
			}
			if stateAlone != 0 {
				t.Errorf("%d separate entries write the %q state; a peer can apply it without the row", stateAlone, tc.state)
			}
			if h, _ := corrosion.GetHost(ctx, s.db, "peer"); h == nil || h.State != tc.state {
				t.Errorf("peer is %+v, want %q", h, tc.state)
			}
		})
	}
}
