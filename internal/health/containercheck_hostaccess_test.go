package health

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
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
