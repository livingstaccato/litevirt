package libvirt

import (
	"testing"

	golibvirt "github.com/digitalocean/go-libvirt"
)

// Every typed parameter a migration sends carries its type tag, as libvirtd
// needs it to decode the payload. The bandwidth went without one, so every
// live migration of a VM with migrate.bandwidth-mib-sec failed with "Unable
// to decode message payload" (lab2-drain anomaly 1), and a drain then
// cold-moved the guest, shutting it down.
//
// Mutation: build the bandwidth as TypedParamValue{I: ...} again — red.
func TestMigrationParams_EveryValueCarriesItsType(t *testing.T) {
	p := MigrateParams{
		Live: true, WithStorage: true, TLS: true, BandwidthMiB: 64,
		TargetAddress: "10.0.0.2", TLSDestination: "10.0.0.2",
		DiskTargets: []string{"vda"}, DestXML: "<domain/>", PersistXML: "<domain/>",
	}
	_, params, err := migrationFlagsAndParams(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkTypedParams(params); err != nil {
		t.Fatalf("a parameter libvirtd cannot decode: %v", err)
	}
	found := false
	for _, tp := range params {
		if tp.Field == "bandwidth" {
			found = true
			if tp.Value.D != 4 || tp.Value.I != uint64(64) {
				t.Fatalf("bandwidth = %+v, want an unsigned long long (type 4) of 64", tp.Value)
			}
		}
	}
	if !found {
		t.Fatal("no bandwidth parameter")
	}
	if _, _, err := MigrationOutcome(p); err != nil {
		t.Fatalf("MigrationOutcome refused a valid migration: %v", err)
	}
	if err := checkTypedParams([]golibvirt.TypedParam{{Field: "bandwidth", Value: golibvirt.TypedParamValue{I: uint64(1)}}}); err == nil {
		t.Fatal("an untagged value was accepted")
	}
}
