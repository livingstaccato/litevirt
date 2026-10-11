package libvirt

import (
	"testing"

	golibvirt "github.com/digitalocean/go-libvirt"
)

// stringParam returns the string value of the typed parameter named field and
// how many times it appears.
func stringParam(params []golibvirt.TypedParam, field string) (string, int) {
	val, n := "", 0
	for _, p := range params {
		if p.Field != field {
			continue
		}
		n++
		if s, ok := p.Value.I.(string); ok {
			val = s
		}
	}
	return val, n
}

// An untunnelled storage migration with TLS requested must hand libvirt
// VIR_MIGRATE_TLS and the name the target's certificate is checked against:
// without the flag QEMU copies RAM and disk blocks in plaintext.
//
// Mutation: delete the `flags |= golibvirt.MigrateTLS` line, or the
// tls.destination parameter, in migrationFlagsAndParams — red.
func TestMigrationFlagsAndParams_StorageWithTLS(t *testing.T) {
	flags, params := migrationFlagsAndParams(MigrateParams{
		Live:           true,
		WithStorage:    true,
		TargetAddress:  "10.0.0.2",
		TLS:            true,
		TLSDestination: "10.0.0.2",
	})
	if flags&golibvirt.MigrateTLS == 0 {
		t.Fatalf("flags = %#x; VIR_MIGRATE_TLS is not set on a storage migration that requested TLS", uint64(flags))
	}
	if flags&golibvirt.MigrateNonSharedDisk == 0 {
		t.Errorf("flags = %#x; want VIR_MIGRATE_NON_SHARED_DISK", uint64(flags))
	}
	if flags&golibvirt.MigrateTunnelled != 0 {
		t.Errorf("flags = %#x; a storage migration cannot be tunnelled", uint64(flags))
	}
	if v, n := stringParam(params, golibvirt.MigrateParamTLSDestination); n != 1 || v != "10.0.0.2" {
		t.Errorf("tls.destination = %q (x%d); want exactly one, \"10.0.0.2\"", v, n)
	}
	if v, n := stringParam(params, golibvirt.MigrateParamURI); n != 1 || v != "tcp://10.0.0.2" {
		t.Errorf("migrate_uri = %q (x%d); want exactly one, \"tcp://10.0.0.2\"", v, n)
	}
}

// The plaintext path, explicitly allowed by the caller (TLS false): no TLS flag
// and no tls.destination, so libvirt is not asked for credentials the target
// does not have.
//
// Mutation: set MigrateTLS unconditionally for storage migrations — red.
func TestMigrationFlagsAndParams_StoragePlaintextWhenTLSNotRequested(t *testing.T) {
	flags, params := migrationFlagsAndParams(MigrateParams{
		Live:           true,
		WithStorage:    true,
		TargetAddress:  "10.0.0.2",
		TLS:            false,
		TLSDestination: "10.0.0.2",
	})
	if flags&golibvirt.MigrateTLS != 0 {
		t.Fatalf("flags = %#x; VIR_MIGRATE_TLS set although the plaintext path was chosen", uint64(flags))
	}
	if flags&golibvirt.MigrateNonSharedDisk == 0 {
		t.Errorf("flags = %#x; want VIR_MIGRATE_NON_SHARED_DISK", uint64(flags))
	}
	if v, n := stringParam(params, golibvirt.MigrateParamTLSDestination); n != 0 {
		t.Errorf("tls.destination = %q (x%d); want none on the plaintext path", v, n)
	}
	if v, n := stringParam(params, golibvirt.MigrateParamURI); n != 1 || v != "tcp://10.0.0.2" {
		t.Errorf("migrate_uri = %q (x%d); want exactly one, \"tcp://10.0.0.2\"", v, n)
	}
}

// A memory-only migration is tunnelled through libvirt's own TLS connection;
// it carries neither the QEMU TLS flag nor a direct migrate_uri.
func TestMigrationFlagsAndParams_MemoryOnlyIsTunnelled(t *testing.T) {
	flags, params := migrationFlagsAndParams(MigrateParams{
		Live: true, TargetAddress: "10.0.0.2", TLS: true, TLSDestination: "10.0.0.2",
	})
	if flags&golibvirt.MigrateTunnelled == 0 {
		t.Fatalf("flags = %#x; want VIR_MIGRATE_TUNNELLED", uint64(flags))
	}
	if flags&(golibvirt.MigrateTLS|golibvirt.MigrateNonSharedDisk) != 0 {
		t.Errorf("flags = %#x; a memory-only migration takes neither TLS nor NON_SHARED_DISK", uint64(flags))
	}
	if _, n := stringParam(params, golibvirt.MigrateParamURI); n != 0 {
		t.Errorf("migrate_uri set on a tunnelled migration")
	}
	if _, n := stringParam(params, golibvirt.MigrateParamTLSDestination); n != 0 {
		t.Errorf("tls.destination set on a tunnelled migration")
	}
}

// A memory-only migration over a dedicated migration network leaves libvirt's
// tunnel: QEMU opens its own TLS stream to the address on that network, and the
// certificate is checked against the name the target's migration certificate
// carries (its cluster address), not the dedicated address, which is not in it.
//
// Mutation: drop `p.Direct` from the tunnelled branch, or drop the
// tls.destination parameter, in migrationFlagsAndParams — red.
func TestMigrationFlagsAndParams_DirectMemoryOnlyOverMigrationNetwork(t *testing.T) {
	flags, params := migrationFlagsAndParams(MigrateParams{
		Live: true, Direct: true, TargetAddress: "10.9.0.2", TLS: true, TLSDestination: "192.168.1.2",
	})
	if flags&golibvirt.MigrateTunnelled != 0 {
		t.Fatalf("flags = %#x; a migration over the migration network must not be tunnelled through the cluster address", uint64(flags))
	}
	if flags&golibvirt.MigrateTLS == 0 {
		t.Fatalf("flags = %#x; VIR_MIGRATE_TLS is not set: the memory would cross the network in plaintext", uint64(flags))
	}
	if flags&golibvirt.MigrateNonSharedDisk != 0 {
		t.Errorf("flags = %#x; no disk is copied", uint64(flags))
	}
	if v, n := stringParam(params, golibvirt.MigrateParamURI); n != 1 || v != "tcp://10.9.0.2" {
		t.Errorf("migrate_uri = %q (x%d); want exactly one, tcp://10.9.0.2", v, n)
	}
	if v, n := stringParam(params, golibvirt.MigrateParamTLSDestination); n != 1 || v != "192.168.1.2" {
		t.Errorf("tls.destination = %q (x%d); want exactly one, the cluster address", v, n)
	}
}

// Direct without TLS is not a mode: the caller falls back to the tunnel rather
// than send memory in the clear, and the builder holds that line too.
func TestMigrationFlagsAndParams_DirectWithoutTLSStaysTunnelled(t *testing.T) {
	flags, params := migrationFlagsAndParams(MigrateParams{Live: true, Direct: true, TargetAddress: "10.9.0.2"})
	if flags&golibvirt.MigrateTunnelled == 0 {
		t.Fatalf("flags = %#x; a direct migration without TLS must stay tunnelled", uint64(flags))
	}
	if _, n := stringParam(params, golibvirt.MigrateParamURI); n != 0 {
		t.Errorf("migrate_uri set although the migration stayed tunnelled")
	}
}
