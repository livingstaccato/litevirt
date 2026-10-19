package libvirt

import (
	"testing"

	golibvirt "github.com/digitalocean/go-libvirt"
)

// A migration that is not a firmware move keeps exactly the flags it had
// before FirmwareLive existed: the source definition is undefined, and the
// guest arrives paused only when the caller asked for it.
//
// Mutation: drop MigrateUndefineSource from the base flags, or set
// MigratePaused unconditionally — red.
func TestMigrationFlags_NonFirmwareUnchanged(t *testing.T) {
	const base = golibvirt.MigratePeer2peer | golibvirt.MigratePersistDest | golibvirt.MigrateUndefineSource
	cases := []struct {
		name string
		p    MigrateParams
		want golibvirt.DomainMigrateFlags
	}{
		{"cold tunnelled", MigrateParams{}, base | golibvirt.MigrateTunnelled},
		{"live tunnelled", MigrateParams{Live: true, TargetAddress: "10.0.0.2", TLS: true, TLSDestination: "10.0.0.2"},
			base | golibvirt.MigrateLive | golibvirt.MigrateTunnelled},
		{"live auto-converge", MigrateParams{Live: true, AutoConverge: true},
			base | golibvirt.MigrateLive | golibvirt.MigrateAutoConverge | golibvirt.MigrateTunnelled},
		{"live paused hand-over", MigrateParams{Live: true, Paused: true},
			base | golibvirt.MigrateLive | golibvirt.MigratePaused | golibvirt.MigrateTunnelled},
		{"storage TLS", MigrateParams{Live: true, WithStorage: true, TargetAddress: "10.0.0.2", TLS: true, TLSDestination: "10.0.0.2"},
			base | golibvirt.MigrateLive | golibvirt.MigrateNonSharedDisk | golibvirt.MigrateTLS | golibvirt.MigrateUnsafe},
		{"storage plaintext", MigrateParams{Live: true, WithStorage: true, TargetAddress: "10.0.0.2"},
			base | golibvirt.MigrateLive | golibvirt.MigrateNonSharedDisk | golibvirt.MigrateUnsafe},
		{"storage over migration network", MigrateParams{Live: true, WithStorage: true, TargetAddress: "10.9.0.2", TLS: true, TLSDestination: "10.0.0.2"},
			base | golibvirt.MigrateLive | golibvirt.MigrateNonSharedDisk | golibvirt.MigrateTLS | golibvirt.MigrateUnsafe},
		{"direct TLS", MigrateParams{Live: true, Direct: true, TargetAddress: "10.9.0.2", TLS: true, TLSDestination: "10.0.0.2"},
			base | golibvirt.MigrateLive | golibvirt.MigrateTLS},
		{"direct without TLS", MigrateParams{Live: true, Direct: true, TargetAddress: "10.9.0.2"},
			base | golibvirt.MigrateLive | golibvirt.MigrateTunnelled},
	}
	for _, c := range cases {
		flags, _, err := migrationFlagsAndParams(c.p)
		if err != nil {
			t.Errorf("%s: unexpected error %v", c.name, err)
			continue
		}
		if flags != c.want {
			t.Errorf("%s: flags = %#x; want %#x", c.name, uint64(flags), uint64(c.want))
		}
	}
}

// T-3a. A firmware move keeps the source definition (its swtpm tree and NVRAM
// are the fallback if the target's copy does not verify) and arrives paused
// (the target is checked before the guest runs there). The flags equal what
// libvirt 10.0.0 accepted in the lab probes (66155 storage copy, 47 tunnelled,
// 65579 over the migration network). Routes the probes did not cover are
// errors, not silent fallbacks.
//
// Mutation: re-add MigrateUndefineSource for a firmware move; drop its forced
// MigratePaused; drop any one of the three route errors — red.
func TestMigrationFlags_FirmwareLive(t *testing.T) {
	ok := []struct {
		name string
		p    MigrateParams
		want golibvirt.DomainMigrateFlags
	}{
		{"storage copy, cluster address, TLS",
			MigrateParams{FirmwareLive: true, Live: true, WithStorage: true, TargetAddress: "10.77.0.13", TLS: true, TLSDestination: "10.77.0.13"},
			66155},
		{"memory-only tunnelled",
			MigrateParams{FirmwareLive: true, Live: true, TargetAddress: "10.78.0.15", TLS: true, TLSDestination: "10.78.0.15"},
			47},
		{"memory-only tunnelled, no TLS",
			MigrateParams{FirmwareLive: true, Live: true},
			47},
		{"memory-only Direct with TLS",
			MigrateParams{FirmwareLive: true, Live: true, Direct: true, TargetAddress: "10.78.1.15", TLS: true, TLSDestination: "10.78.0.15"},
			65579},
	}
	for _, c := range ok {
		flags, params, err := migrationFlagsAndParams(c.p)
		if err != nil {
			t.Errorf("%s: refused: %v", c.name, err)
			continue
		}
		if flags&golibvirt.MigrateUndefineSource != 0 {
			t.Errorf("%s: flags = %#x carry VIR_MIGRATE_UNDEFINE_SOURCE; a firmware move keeps the source definition", c.name, uint64(flags))
		}
		if flags&golibvirt.MigratePaused == 0 {
			t.Errorf("%s: flags = %#x lack VIR_MIGRATE_PAUSED; a firmware move arrives paused", c.name, uint64(flags))
		}
		if flags != c.want {
			t.Errorf("%s: flags = %#x (%d); want %d", c.name, uint64(flags), uint64(flags), uint64(c.want))
		}
		if c.p.Direct {
			if v, n := stringParam(params, golibvirt.MigrateParamURI); n != 1 || v != "tcp://10.78.1.15" {
				t.Errorf("%s: migrate_uri = %q (x%d); want the migration-network address", c.name, v, n)
			}
			if v, n := stringParam(params, golibvirt.MigrateParamTLSDestination); n != 1 || v != "10.78.0.15" {
				t.Errorf("%s: tls.destination = %q (x%d); want the cluster address", c.name, v, n)
			}
		}
	}

	refused := []struct {
		name string
		p    MigrateParams
	}{
		{"storage copy to a non-cluster address",
			MigrateParams{FirmwareLive: true, Live: true, WithStorage: true, TargetAddress: "10.9.0.2", TLS: true, TLSDestination: "10.0.0.2"}},
		{"storage copy with neither address",
			MigrateParams{FirmwareLive: true, Live: true, WithStorage: true, TLS: true}},
		{"storage copy without TLS",
			MigrateParams{FirmwareLive: true, Live: true, WithStorage: true, TargetAddress: "10.0.0.2", TLSDestination: "10.0.0.2"}},
		{"Direct without TLS",
			MigrateParams{FirmwareLive: true, Live: true, Direct: true, TargetAddress: "10.9.0.2", TLSDestination: "10.0.0.2"}},
	}
	for _, c := range refused {
		if flags, _, err := migrationFlagsAndParams(c.p); err == nil {
			t.Errorf("%s: accepted with flags %#x; want an error", c.name, uint64(flags))
		}
	}
}
