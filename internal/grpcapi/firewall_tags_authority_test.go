package grpcapi

import (
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// The firewall-tags authority is minted only after sg.write at the cluster
// root: Operator (sg.read only) and Viewer are refused and get the zero
// authority, NetworkAdmin and Admin get one SetFirewallTags accepts.
//
// Mutation: mint before (or without) the sg.write check — Operator gets an
// authority: red.
func TestFWTagAuthority_NeedsSGWrite(t *testing.T) {
	for role, allowed := range map[string]bool{"Operator": false, "Viewer": false, "NetworkAdmin": true, "Admin": true} {
		t.Run(role, func(t *testing.T) {
			s := testServer(t)
			ctx := boundCtx(t, s, "u", "admin", role)
			a, err := s.fwTagAuthority(ctx)
			if !allowed {
				if status.Code(err) != codes.PermissionDenied || a != (corrosion.FWTagAuthority{}) {
					t.Fatalf("%s: authority %+v, err %v; want the zero authority and PermissionDenied", role, a, err)
				}
				return
			}
			if err != nil || a == (corrosion.FWTagAuthority{}) {
				t.Fatalf("%s: authority %+v, err %v", role, a, err)
			}
		})
	}
}
