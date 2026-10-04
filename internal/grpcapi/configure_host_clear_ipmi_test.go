package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// `lv host config` treats an empty ipmi_* field as "leave alone", so until
// clear_ipmi there was no way to remove a host's IPMI address, user or
// password once set: the BMC password of a machine that no longer has one, or
// whose BMC was retired, stayed in both copies forever.

func ipmiConfiguredServer(t *testing.T, strategy string) *Server {
	t.Helper()
	s := testServerR2(t)
	s.db.SetCredentialsSplitGate(func() bool { return true })
	ctx := adminCtx()
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: "h", Address: "10.0.0.1", State: "active"}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	if _, err := s.ConfigureHost(ctx, &pb.ConfigureHostRequest{
		Name: "h", FenceStrategy: strategy, IpmiAddress: "10.0.1.1", IpmiUser: "root", IpmiPass: "bmc-pass",
	}); err != nil {
		t.Fatalf("configure IPMI: %v", err)
	}
	return s
}

func TestConfigureHost_ClearIPMIRemovesEveryCopy(t *testing.T) {
	s := ipmiConfiguredServer(t, "ssh")
	ctx := adminCtx()
	out, err := s.ConfigureHost(ctx, &pb.ConfigureHostRequest{Name: "h", ClearIpmi: true})
	if err != nil {
		t.Fatalf("ConfigureHost(clear_ipmi): %v", err)
	}
	if out.IpmiAddress != "" {
		t.Errorf("returned host still has ipmi_address %q", out.IpmiAddress)
	}
	h, err := corrosion.GetHost(ctx, s.db, "h")
	if err != nil || h == nil {
		t.Fatalf("GetHost: %v", err)
	}
	if h.IPMIAddress != "" || h.IPMIUser != "" || h.IPMIPass != "" {
		t.Errorf("after clear_ipmi the host still fences with ipmi %q / %q @ %q", h.IPMIUser, h.IPMIPass, h.IPMIAddress)
	}
	if h.FenceStrategy != "ssh" {
		t.Errorf("fence_strategy = %q; clear_ipmi must leave the other settings alone", h.FenceStrategy)
	}
	// Both copies of the password: the credential row this release reads, and
	// the old column a host rolled back one release reads.
	rows, err := s.db.Query(ctx, `SELECT h.ipmi_pass AS old, c.ipmi_pass AS cred FROM hosts h
		JOIN host_fence_credentials c ON c.host_name = h.name WHERE h.name = 'h'`)
	if err != nil || len(rows) != 1 {
		t.Fatalf("read both copies: %d %v", len(rows), err)
	}
	if rows[0].String("old") != "" || rows[0].String("cred") != "" {
		t.Errorf("password copies after clear: hosts.ipmi_pass %q, credential row %q; want both empty",
			rows[0].String("old"), rows[0].String("cred"))
	}
}

func TestConfigureHost_ClearIPMIRefusals(t *testing.T) {
	ctx := adminCtx()

	s := ipmiConfiguredServer(t, "ssh")
	if _, err := s.ConfigureHost(ctx, &pb.ConfigureHostRequest{Name: "h", ClearIpmi: true, IpmiUser: "x"}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("clear_ipmi with ipmi_user: got %v, want InvalidArgument", err)
	}

	// A host left fencing by ipmi with no credentials would fail every fence.
	s = ipmiConfiguredServer(t, "ipmi")
	if _, err := s.ConfigureHost(ctx, &pb.ConfigureHostRequest{Name: "h", ClearIpmi: true}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("clear_ipmi on an ipmi-fenced host: got %v, want FailedPrecondition", err)
	}
	if _, err := s.ConfigureHost(ctx, &pb.ConfigureHostRequest{Name: "h", ClearIpmi: true, FenceStrategy: "ipmi"}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("clear_ipmi with fence_strategy=ipmi: got %v, want FailedPrecondition", err)
	}
	if _, err := s.ConfigureHost(ctx, &pb.ConfigureHostRequest{Name: "h", ClearIpmi: true, FenceStrategy: "manual"}); err != nil {
		t.Errorf("clear_ipmi with fence_strategy=manual: %v", err)
	}
	if h, _ := corrosion.GetHost(ctx, s.db, "h"); h == nil || h.FenceStrategy != "manual" || h.IPMIPass != "" {
		t.Errorf("after clear + manual: %+v", h)
	}
}

// A node whose credentials_split_v1 gate is closed cannot write the credential
// row, and an empty old column is never absorbed into one (credentials_absorb.go),
// so a latched peer would go on serving the password. Refuse rather than
// half-clear.
func TestConfigureHost_ClearIPMIRefusedBeforeTheSplitLatches(t *testing.T) {
	s := ipmiConfiguredServer(t, "ssh")
	s.db.SetCredentialsSplitGate(func() bool { return false })
	_, err := s.ConfigureHost(adminCtx(), &pb.ConfigureHostRequest{Name: "h", ClearIpmi: true})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("clear_ipmi with the split gate closed: got %v, want FailedPrecondition", err)
	}
	if h, _ := corrosion.GetHost(context.Background(), s.db, "h"); h == nil || h.IPMIPass != "bmc-pass" {
		t.Errorf("a refused clear changed the host: %+v", h)
	}
}
