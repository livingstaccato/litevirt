package restapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"google.golang.org/grpc"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// ioMock records the SetDiskIO a REST call became.
type ioMock struct {
	*mockGRPC
	got *pb.SetDiskIORequest
}

func (m *ioMock) SetDiskIO(_ context.Context, in *pb.SetDiskIORequest, _ ...grpc.CallOption) (*pb.VM, error) {
	m.got = in
	return &pb.VM{Name: in.VmName}, nil
}

// POST /vms/{name}/disks/{disk}/io becomes SetDiskIO with the VM and disk from
// the path and the limits from the body.
//
// Mutation: drop the "io" branch — the call 404s and the recorded request is nil.
func TestVMDiskIO_SetsLimits(t *testing.T) {
	s, base := newMockServer("test-token")
	m := &ioMock{mockGRPC: base}
	s.grpc = m
	req := httptest.NewRequest(http.MethodPost, "/api/v1/vms/vm1/disks/data/io",
		strings.NewReader(`{"limits": {"read_iops_sec": 300, "write_bytes_sec": "1048576"}}`))
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	if m.got == nil || m.got.VmName != "vm1" || m.got.DiskName != "data" ||
		m.got.Limits.GetReadIopsSec() != 300 || m.got.Limits.GetWriteBytesSec() != 1<<20 {
		t.Errorf("SetDiskIO request = %+v", m.got)
	}
}
