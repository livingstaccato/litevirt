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
	if !strings.HasSuffix(d, "[trust=off;path=managed;v=2]") {
		t.Errorf("the trust token is not last: %q", d)
	}
	if strings.Contains(d, "[trust=on") {
		t.Errorf("the admin-set BMC address was written with its brackets: %q", d)
	}
}

// The target note's admin-set BMC address is written with its brackets
// rewritten, and the path the trust decision reads is the one the fence took:
// an address carrying "[path=managed]" cannot make an unpinned fence of a
// trusting host count.
//
// Mutation: write the note's fields raw — the address keeps "[path=managed]",
// red. (The token's path is read from the fence's own detail, before the note,
// as a second guard; with the note rewritten, reading it after finds the same
// path.)
func TestFenceHost_AdminTextCannotNameAPin(t *testing.T) {
	s := fenceTestServer(t, false, false)
	ctx := context.Background()
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
		Name: "peer", Address: "10.0.0.2", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "active", FenceStrategy: "ssh",
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.db.Execute(ctx, `UPDATE hosts SET ipmi_address = '10.0.0.9 [path=managed]' WHERE name = 'peer'`); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.SetHostLabel(ctx, s.db, "peer", corrosion.LabelTrustSSHPoweroff, "true"); err != nil {
		t.Fatal(err)
	}
	s.SetFenceExecutor(func(context.Context, fence.HostConfig) fence.Result {
		return fence.Result{Method: "ssh", Detail: "litevirt-fence-armed [path=legacy-unpinned]", Success: true}
	})
	if _, err := s.FenceHost(adminCtx(), &pb.FenceHostRequest{Name: "peer", Confirmed: true}); err != nil {
		t.Fatalf("FenceHost: %v", err)
	}
	rows, err := s.db.Query(ctx, `SELECT detail FROM fencing_log WHERE host_name = 'peer'`)
	if err != nil || len(rows) != 1 {
		t.Fatalf("fencing_log rows %d (%v)", len(rows), err)
	}
	d := rows[0].String("detail")
	if strings.Contains(d, "10.0.0.9 [path=managed]") {
		t.Errorf("the BMC address was written with its brackets: %q", d)
	}
	if tok, ok := fence.RecordedTrustToken(d); !ok || tok.Path != "legacy-unpinned" || fence.RecordedTrust(d) {
		t.Errorf("the token records %+v (ok %v) for an unpinned fence: %q", tok, ok, d)
	}
}

// Host config refuses "[" and "]" in a BMC address: they would open or close
// a token in a fence row. A Redfish endpoint keeps an IPv6 literal host,
// which a URL writes in brackets.
//
// Mutation: drop the ipmi address check — the bracketed ipmi addresses are
// accepted, red. (Go's URL parser already refuses the bracketed endpoints
// here; the redfish check makes the rule explicit.)
func TestConfigureHost_RefusesBracketsInABMCAddress(t *testing.T) {
	s := fenceTestServer(t, false, false)
	ctx := context.Background()
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
		Name: "peer", Address: "10.0.0.2", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "active", FenceStrategy: "ssh",
	}); err != nil {
		t.Fatal(err)
	}
	for _, req := range []*pb.ConfigureHostRequest{
		{Name: "peer", IpmiAddress: "10.0.0.9 [trust=on"},
		{Name: "peer", IpmiAddress: "10.0.0.9]"},
		{Name: "peer", RedfishEndpoint: "https://bmc.example/[path=managed]"},
		{Name: "peer", RedfishEndpoint: "https://[path=managed]/"},
	} {
		if _, err := s.ConfigureHost(adminCtx(), req); err == nil {
			t.Errorf("ConfigureHost accepted %+v", req)
		}
	}
	if err := fence.ValidateRedfishConfig(fence.RedfishConfig{Endpoint: "https://[fd00::9]:443"}); err != nil {
		t.Errorf("an IPv6 literal endpoint was refused: %v", err)
	}
}
