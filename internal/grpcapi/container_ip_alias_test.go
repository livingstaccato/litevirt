package grpcapi

import (
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// Lab 6c: lxt3 takes ip=172.16.77.50/24 and lxt4 then asks for the bare
// 172.16.77.50. They are one host address, so the second create is refused
// AlreadyExists instead of aliasing the address to two containers.
func TestCreateContainer_StaticIPCIDRAndBareDoNotAlias(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	s.SetContainerRuntime(&fakeCTRuntime{})
	mkManagedNetwork(t, s, "lxtnet", "br-lxt", "172.16.77.0/24")

	if _, err := s.CreateContainer(ctx, &pb.CreateContainerRequest{
		Name: "lxt3", Template: "download", Distro: "alpine", Release: "3.19",
		Networks: []*pb.ContainerNetwork{{Name: "eth0", NetworkName: "lxtnet", Ip: "172.16.77.50/24"}},
	}); err != nil {
		t.Fatalf("create lxt3: %v", err)
	}
	_, err := s.CreateContainer(ctx, &pb.CreateContainerRequest{
		Name: "lxt4", Template: "download", Distro: "alpine", Release: "3.19",
		Networks: []*pb.ContainerNetwork{{Name: "eth0", NetworkName: "lxtnet", Ip: "172.16.77.50"}},
	})
	if status.Code(err) != codes.AlreadyExists {
		t.Fatalf("bare 172.16.77.50 after 172.16.77.50/24: got %v, want AlreadyExists", err)
	}
}
