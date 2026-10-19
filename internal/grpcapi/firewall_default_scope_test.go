package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// default-deny's --scope follows synflood's rule (Track B review m-1): no
// scope is the cluster, and a scope is a host this replica knows (NotFound
// otherwise; it used to write a row for any name). "cluster" still means the
// cluster for the web UI and older lv, until a host is named cluster: its row
// and the cluster's share one key in firewall_defaults, so that scope is then
// refused rather than guessed.
//
// Mutations: drop the host lookup — an unknown host is written: red; read
// "cluster" as the cluster while a host has that name — red.
func TestSetFirewallDefault_ScopeIsTheClusterOrAKnownHost(t *testing.T) {
	ctx := context.Background()
	s := synfloodServer(t, true, "h1")
	op := userCtx("olga", "operator")
	if _, err := s.SetFirewallDefault(op, &pb.SetFirewallDefaultRequest{Scope: "nope", DefaultDeny: true}); status.Code(err) != codes.NotFound {
		t.Errorf("an unknown host: %v, want NotFound", err)
	}
	if rows, err := s.db.Query(ctx, `SELECT scope FROM firewall_defaults WHERE scope = 'nope'`); err != nil || len(rows) != 0 {
		t.Errorf("an unknown host's row was written: %v %v", rows, err)
	}
	for _, scope := range []string{"", "cluster", "h1"} {
		if _, err := s.SetFirewallDefault(op, &pb.SetFirewallDefaultRequest{Scope: scope, DefaultDeny: true}); err != nil {
			t.Errorf("scope %q: %v", scope, err)
		}
	}
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: "cluster", Address: "10.0.0.9", State: "active"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetFirewallDefault(op, &pb.SetFirewallDefaultRequest{Scope: "cluster"}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("scope cluster with a host named cluster: %v, want FailedPrecondition", err)
	}
	if _, err := s.SetFirewallDefault(op, &pb.SetFirewallDefaultRequest{}); err != nil {
		t.Errorf("no scope with a host named cluster: %v", err)
	}
}
