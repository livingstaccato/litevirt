package grpcapi

import (
	"context"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fence"
)

// An operator's `lv host fence` of a host, an SSH power-off the remote shell
// confirmed, records whether the host trusted one at that moment, as the
// coordinator's own fence does: a coordinator resuming a recovery from the row
// judges it by that decision, never by the label as it reads later.
//
// Mutation: drop fence.WithTrust from FenceHost — the trusted case records no
// trust, red.
func TestFenceHost_RecordsTheTrustDecision(t *testing.T) {
	for _, trusted := range []bool{true, false} {
		s := fenceTestServer(t, false, false)
		ctx := context.Background()
		if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
			Name: "peer", Address: "10.0.0.2", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "active", FenceStrategy: "ssh",
		}); err != nil {
			t.Fatal(err)
		}
		if trusted {
			if err := corrosion.SetHostLabel(ctx, s.db, "peer", corrosion.LabelTrustSSHPoweroff, "true"); err != nil {
				t.Fatal(err)
			}
		}
		s.SetFenceExecutor(func(context.Context, fence.HostConfig) fence.Result {
			return fence.Result{Method: "ssh", Detail: "litevirt-fence-armed [path=managed]", Success: true}
		})
		if _, err := s.FenceHost(adminCtx(), &pb.FenceHostRequest{Name: "peer", Confirmed: true}); err != nil {
			t.Fatalf("FenceHost: %v", err)
		}
		rows, err := s.db.Query(ctx, `SELECT detail FROM fencing_log WHERE host_name = 'peer'`)
		if err != nil || len(rows) != 1 {
			t.Fatalf("fencing_log rows %d (%v)", len(rows), err)
		}
		if got := fence.RecordedTrust(rows[0].String("detail")); got != trusted {
			t.Errorf("trusted=%v: the row %q records trust %v", trusted, rows[0].String("detail"), got)
		}
	}
}

// The token is written LAST, after the target note with its admin-set BMC
// address: an address that carries "[trust=on]" cannot flip the decision of
// a host that does not trust a confirmed SSH power-off.
//
// Mutation: append the token before the target note, as before — red.
func TestFenceHost_TheTrustTokenIsLast(t *testing.T) {
	s := fenceTestServer(t, false, false)
	ctx := context.Background()
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
		Name: "peer", Address: "10.0.0.2", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "active",
		FenceStrategy: "ssh",
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.db.Execute(ctx, `UPDATE hosts SET ipmi_address = '10.0.0.9 [trust=on]' WHERE name = 'peer'`); err != nil {
		t.Fatal(err)
	}
	s.SetFenceExecutor(func(context.Context, fence.HostConfig) fence.Result {
		return fence.Result{Method: "ssh", Detail: "litevirt-fence-armed [path=managed]", Success: true}
	})
	if _, err := s.FenceHost(adminCtx(), &pb.FenceHostRequest{Name: "peer", Confirmed: true}); err != nil {
		t.Fatalf("FenceHost: %v", err)
	}
	rows, err := s.db.Query(ctx, `SELECT detail FROM fencing_log WHERE host_name = 'peer'`)
	if err != nil || len(rows) != 1 {
		t.Fatalf("fencing_log rows %d (%v)", len(rows), err)
	}
	d := rows[0].String("detail")
	if fence.RecordedTrust(d) {
		t.Fatalf("an admin-set BMC address recorded trust for an untrusting host: %q", d)
	}
	if !strings.HasSuffix(d, "[trust=off]") {
		t.Errorf("the trust token is not last: %q", d)
	}
}
