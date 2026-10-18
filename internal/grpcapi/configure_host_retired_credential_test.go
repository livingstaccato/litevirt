package grpcapi

import (
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// After a removal or re-admission retires a host's fence credential, the
// operator sets the new machine's password with `lv host config --ipmi-pass`,
// through the real ConfigureHost statements, before and after
// credentials_clear_v1 (which writes an empty old column beside the upsert).
//
// Mutation: the revive guard treats the operator's entry as unpaired — red.
func TestConfigureHost_SetsAPasswordOverARetiredCredential(t *testing.T) {
	for _, clear := range []bool{false, true} {
		s := ipmiConfiguredServer(t, "ipmi")
		ctx := adminCtx()
		if clear {
			s.db.SetCredentialsClearGate(func() bool { return true })
		}
		// The retirement a removal or re-admission leaves (host_readmit.go).
		if _, err := s.db.DB().Exec(`UPDATE host_fence_credentials SET ipmi_pass = '', deleted_at = updated_at
			WHERE host_name = 'h'`); err != nil {
			t.Fatal(err)
		}
		if h, _ := corrosion.GetHost(ctx, s.db, "h"); h == nil || !h.IPMIPassRetired {
			t.Fatalf("clear %v: fixture: the credential row is not retired", clear)
		}
		if _, err := s.ConfigureHost(ctx, &pb.ConfigureHostRequest{Name: "h", IpmiPass: "new-machine-pass"}); err != nil {
			t.Fatalf("clear %v: ConfigureHost: %v", clear, err)
		}
		h, err := corrosion.GetHost(ctx, s.db, "h")
		if err != nil || h == nil || h.IPMIPass != "new-machine-pass" || h.IPMIPassRetired {
			t.Errorf("clear %v: after lv host config --ipmi-pass the host reads password set %v, retired %v (err %v); "+
				"want the new password", clear, h != nil && h.IPMIPass != "", h != nil && h.IPMIPassRetired, err)
		}
	}
}

// On a node whose hosts row predates the admission the retirement belongs to
// (its replica lags the re-admission), the password write cannot carry the
// retirement, so it is not set. The operator is told so, and nothing is
// written.
//
// Mutation: the local write path drops the credential upsert again and
// returns success — red.
func TestConfigureHost_APasswordOnALaggingReplicaIsRefused(t *testing.T) {
	s := ipmiConfiguredServer(t, "ipmi")
	ctx := adminCtx()
	if _, err := s.db.DB().Exec(`UPDATE host_fence_credentials SET ipmi_pass = '', deleted_at = updated_at
		WHERE host_name = 'h'`); err != nil {
		t.Fatal(err)
	}
	// This node's row is an admission older than that retirement.
	if _, err := s.db.DB().Exec(`UPDATE hosts SET incarnation = 1, created_at = '2020-01-01T00:00:00.000000000Z'
		WHERE name = 'h'`); err != nil {
		t.Fatal(err)
	}
	_, err := s.ConfigureHost(ctx, &pb.ConfigureHostRequest{Name: "h", IpmiPass: "new-machine-pass"})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "predates the host's current admission") {
		t.Fatalf("ConfigureHost on a lagging replica = %v; want FailedPrecondition naming the lagging admission", err)
	}
	if got := oneHostIPMIPassColumn(t, s); got == "new-machine-pass" {
		t.Error("the refused write's hosts half was committed")
	}
	if h, _ := corrosion.GetHost(ctx, s.db, "h"); h == nil || !h.IPMIPassRetired {
		t.Error("the credential row is no longer the retirement")
	}
}

func oneHostIPMIPassColumn(t *testing.T, s *Server) string {
	t.Helper()
	var p string
	if err := s.db.DB().QueryRow(`SELECT ipmi_pass FROM hosts WHERE name = 'h'`).Scan(&p); err != nil {
		t.Fatal(err)
	}
	return p
}
