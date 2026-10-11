package grpcapi

import (
	"context"
	"testing"

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
	if err == nil {
		t.Error("a create whose grant the writer refuses succeeded")
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
