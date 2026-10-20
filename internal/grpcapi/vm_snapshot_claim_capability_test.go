package grpcapi

import (
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
)

func TestVMSnapshotClaimBinaryAdvertisementAndDriver(t *testing.T) {
	s := testServer(t)
	if !capabilities.Has(s.advertisedCapabilities(), capabilities.VMSnapshotClaimV1) {
		t.Fatal("binary decoder support is not advertised")
	}
	if !s.tokenEnabled(capabilities.VMSnapshotClaimV1) {
		t.Fatal("existing activation driver does not drive snapshot claim readiness")
	}
}
