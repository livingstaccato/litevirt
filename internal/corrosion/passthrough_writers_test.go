package corrosion

import (
	"context"
	"errors"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
)

// The usb_mounts_memory writers write nothing without the feature's grant: not
// with the zero grant, and not with another feature's. With it they write as
// the plain writer does.
//
// Mutation: drop the Check from any one writer — its case goes red (and the
// capabilities guard's TestReleaseFeatureWriters_TakeAGrant still passes, so
// this is the test that pins the check itself).
func TestPassthroughWriters_RefuseWithoutTheFeaturesGrant(t *testing.T) {
	ctx := context.Background()
	for _, g := range []struct {
		name string
		g    capabilities.FeatureGrant
	}{
		{"no grant", capabilities.FeatureGrant{}},
		{"another feature's grant", capabilities.GrantForTest(t, capabilities.FeatureVMLimits)},
	} {
		c := testClient(t)
		vm := VMRecord{Name: "u", HostName: "h1", State: "stopped", Spec: `{"name":"u","usb_devices":[{"vendor":"046d"}]}`}
		if err := InsertVMWithPassthrough(ctx, c, g.g, vm, nil, nil, nil, nil, true); !errors.Is(err, capabilities.ErrNoFeatureGrant) {
			t.Errorf("%s: InsertVMWithPassthrough = %v, want ErrNoFeatureGrant", g.name, err)
		}
		if got, _ := GetVM(ctx, c, "u"); got != nil {
			t.Errorf("%s: a refused insert wrote the VM row", g.name)
		}

		if err := InsertVM(ctx, c, VMRecord{Name: "m", HostName: "h1", State: "stopped", Spec: `{"name":"m"}`}, nil, nil); err != nil {
			t.Fatal(err)
		}
		applied, _, err := MutateDesiredSpecPassthrough(ctx, c, g.g, "m", func(string) (string, error) {
			return `{"name":"m","memory_hotplug_max_mib":4096}`, nil
		})
		if !errors.Is(err, capabilities.ErrNoFeatureGrant) || applied {
			t.Errorf("%s: MutateDesiredSpecPassthrough = %v (applied %v), want ErrNoFeatureGrant", g.name, err, applied)
		}
		if got, _ := GetVM(ctx, c, "m"); got == nil || got.Spec != `{"name":"m"}` {
			t.Errorf("%s: a refused mutate changed the spec: %+v", g.name, got)
		}

		ct := ContainerRecord{HostName: "h1", Name: "c", State: "stopped",
			CreateSpec: EncodeCreateSpec(ContainerCreateSpec{Template: "download", Mounts: []ContainerHostMount{{HostPath: "/srv", ContainerPath: "/s"}}})}
		if err := CreateContainerAtomicWithHostAccess(ctx, c, g.g, ct, nil); !errors.Is(err, capabilities.ErrNoFeatureGrant) {
			t.Errorf("%s: CreateContainerAtomicWithHostAccess = %v, want ErrNoFeatureGrant", g.name, err)
		}
		if err := UpsertContainerWithHostAccess(ctx, c, g.g, ct); !errors.Is(err, capabilities.ErrNoFeatureGrant) {
			t.Errorf("%s: UpsertContainerWithHostAccess = %v, want ErrNoFeatureGrant", g.name, err)
		}
		if got, _ := GetContainer(ctx, c, "h1", "c"); got != nil {
			t.Errorf("%s: a refused container write wrote the row", g.name)
		}
	}

	c := testClient(t)
	g := capabilities.GrantForTest(t, capabilities.FeatureUSBMountsMemory)
	if err := InsertVMWithPassthrough(ctx, c, g, VMRecord{Name: "u", HostName: "h1", State: "stopped", Spec: `{"name":"u"}`}, nil, nil, nil, nil, true); err != nil {
		t.Fatalf("InsertVMWithPassthrough with the grant: %v", err)
	}
	if applied, _, err := MutateDesiredSpecPassthrough(ctx, c, g, "u", func(string) (string, error) {
		return `{"name":"u","memory_hotplug_max_mib":4096}`, nil
	}); err != nil || !applied {
		t.Fatalf("MutateDesiredSpecPassthrough with the grant: %v (applied %v)", err, applied)
	}
	if got, _ := GetVM(ctx, c, "u"); got == nil || got.Spec != `{"name":"u","memory_hotplug_max_mib":4096}` {
		t.Fatalf("granted VM writes: %+v", got)
	}
	ct := ContainerRecord{HostName: "h1", Name: "c", State: "stopped",
		CreateSpec: EncodeCreateSpec(ContainerCreateSpec{Template: "download", Mounts: []ContainerHostMount{{HostPath: "/srv", ContainerPath: "/s"}}})}
	if err := CreateContainerAtomicWithHostAccess(ctx, c, g, ct, nil); err != nil {
		t.Fatalf("CreateContainerAtomicWithHostAccess with the grant: %v", err)
	}
	ct.CreateSpec = EncodeCreateSpec(ContainerCreateSpec{Template: "download", Devices: []ContainerHostDevice{{HostPath: "/dev/ttyUSB0"}}})
	if err := UpsertContainerWithHostAccess(ctx, c, g, ct); err != nil {
		t.Fatalf("UpsertContainerWithHostAccess with the grant: %v", err)
	}
	if got, _ := GetContainer(ctx, c, "h1", "c"); got == nil || len(DecodeCreateSpec(got.CreateSpec).Devices) != 1 {
		t.Fatalf("granted container writes: %+v", got)
	}
}
