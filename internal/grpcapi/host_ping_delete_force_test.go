package grpcapi

import (
	"context"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// I3: Ping advertises delete force, which lv rm --force and a forwarding entry
// node read to decide between the daemon's stop and the old StopVM-first flow.
func TestPing_AdvertisesDeleteForce(t *testing.T) {
	s := testServer(t)
	resp, err := s.Ping(context.Background(), &pb.PingRequest{})
	if err != nil || !resp.GetDeleteForce() {
		t.Fatalf("Ping = %v, %v; want delete_force", resp, err)
	}
}
