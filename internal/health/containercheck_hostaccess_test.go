package health

import (
	"context"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// A relocation recreate carries the container's host mounts and devices to
// the runtime, which judges them against the recreating host's own prefixes;
// a recreate that dropped them would hand back a container missing its data.
func TestContainerCheck_RelocateRecreate_CarriesHostAccess(t *testing.T) {
	db := testLogicDB(t)
	rt := newFakeCtRuntime()
	insertCt(t, db, corrosion.ContainerRecord{
		HostName: "node1", Name: "ct1", State: "pending",
		StateDetail: corrosion.ContainerRelocateRecreateDetail, Image: "alpine:3.19",
		CreateSpec: corrosion.EncodeCreateSpec(corrosion.ContainerCreateSpec{
			Template: "download", Distro: "alpine",
			Mounts:  []corrosion.ContainerHostMount{{HostPath: "/srv/data", ContainerPath: "/data", ReadWrite: true}},
			Devices: []corrosion.ContainerHostDevice{{HostPath: "/dev/ttyUSB0"}},
		}),
	})
	c := NewContainerChecker("node1", db, rt)
	c.checkContainer(context.Background(), mustGetCt(t, db, "ct1"), time.Now())
	if m := rt.lastCreate.Mounts; len(m) != 1 || m[0].HostPath != "/srv/data" || m[0].ContainerPath != "/data" || !m[0].ReadWrite {
		t.Fatalf("recreate mounts = %+v", m)
	}
	if d := rt.lastCreate.Devices; len(d) != 1 || d[0].HostPath != "/dev/ttyUSB0" {
		t.Fatalf("recreate devices = %+v", d)
	}
}

// A failover definition of a hot-add VM carries its band: the region, plugged
// to its desired memory — or the next set-memory would find nothing to plug.
func TestDomainXMLFor_CarriesMemoryHotplug(t *testing.T) {
	db := testLogicDB(t)
	r := NewReconciler("node-a", t.TempDir(), db, libvirtfake.New())
	spec := &pb.VMSpec{Name: "hv", Cpu: 1, MemoryMib: 3072, MemoryHotplugBaseMib: 1024, MemoryHotplugMaxMib: 4096}
	x, _, failure := r.domainXMLFor(context.Background(), corrosion.VMRecord{Name: "hv", CPUActual: 1, MemActual: 3072}, spec, nil)
	if failure != "" {
		t.Fatalf("domainXMLFor: %s", failure)
	}
	if !strings.Contains(x, `model="virtio-mem"`) || !strings.Contains(x, `<requested unit="KiB">2097152</requested>`) {
		t.Fatalf("failover definition lacks the hot-add region plugged to 2048 MiB:\n%s", x)
	}
}
