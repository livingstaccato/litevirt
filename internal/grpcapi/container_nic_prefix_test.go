package grpcapi

import (
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// An address litevirt allocates on a managed network reached the container
// config bare ("172.16.77.2"); LXC then gave the guest a classful /8 and no
// default route. The runtime NIC carries the network's prefix and gateway.
func TestCreateContainer_ManagedNIC_AllocatedIPCarriesPrefixAndGateway(t *testing.T) {
	s := testServer(t)
	rt := &fakeCTRuntime{}
	s.SetContainerRuntime(rt)
	mkManagedNetwork(t, s, "lxtnet", "br-lxt", "172.16.77.0/24")
	if _, err := s.CreateContainer(adminCtx(), &pb.CreateContainerRequest{
		Name: "lxt2", Template: "download", Distro: "alpine",
		Networks: []*pb.ContainerNetwork{{Name: "eth0", NetworkName: "lxtnet"}},
	}); err != nil {
		t.Fatalf("CreateContainer: %v", err)
	}
	if _, err := s.CreateContainer(adminCtx(), &pb.CreateContainerRequest{
		Name: "lxt3", Template: "download", Distro: "alpine",
		Networks: []*pb.ContainerNetwork{{Name: "eth0", NetworkName: "lxtnet", Ip: "172.16.77.50"}},
	}); err != nil {
		t.Fatalf("CreateContainer static: %v", err)
	}
	for i, want := range []string{"172.16.77.2/24", "172.16.77.50/24"} {
		nic := rt.createCalls[i].Networks[0]
		if nic.IP != want {
			t.Errorf("container %d runtime NIC IP = %q, want %q", i, nic.IP, want)
		}
		if nic.Gateway != "172.16.77.1" {
			t.Errorf("container %d runtime NIC gateway = %q, want 172.16.77.1", i, nic.Gateway)
		}
	}
}
