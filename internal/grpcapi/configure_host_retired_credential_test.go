package grpcapi

import (
	"testing"

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
