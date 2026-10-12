package grpcapi

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// A create whose release-feature grant the combined writer would refuse is
// refused BEFORE its domain is defined, so the refusal can never leave a
// running domain with no row (the row write after the start logs a failure
// and carries on). wrongGrantGate opens but hands out another feature's
// grant, which only the writer's check notices.
//
// Mutations: remove the pre-define check — the domain is defined (and, with
// the writer-refusal teardown also removed, left running with no row).
func TestCreateVM_AGrantTheWriterRefusesIsRefusedBeforeDefine(t *testing.T) {
	s, fake := provableCreateServer(t)
	s.SetReleaseFeatureGate(wrongGrantGate{})
	defined := false
	fake.FailDefineDomain = func(string) error { defined = true; return nil }
	req := disklessCreateRequest("h1")
	req.Spec.MemoryHotplugMaxMib = 4096
	_, err := s.CreateVM(adminCtx(), req)
	// The refusal is the grant check's own, not a later failure (before the
	// fix the create also failed, but only because vmToProto found no row).
	if status.Code(err) != codes.Internal || !strings.Contains(err.Error(), "vm create") ||
		!strings.Contains(err.Error(), "without a grant from its gate") {
		t.Errorf("CreateVM = %v; want Internal naming the missing grant", err)
	}
	if defined {
		t.Error("the domain was defined before the grant was found wanting")
	}
	if fake.DomainExists("h1") {
		t.Error("the refused create left a domain behind")
	}
	if row, _ := corrosion.GetVM(context.Background(), s.db, "h1"); row != nil {
		t.Errorf("the refused create wrote a row: %+v", row)
	}
}
