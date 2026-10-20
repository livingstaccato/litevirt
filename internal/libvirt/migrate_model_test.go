package libvirt

import "testing"

// MigrationOutcome is what the fake asks before it models a migration: it
// answers from the flags MigrateToTarget hands libvirt, and refuses what
// MigrateToTarget refuses, so the fake cannot land a guest running that a
// host would land paused, or move one on a route a host refuses.
//
// Mutations: drop MigratePaused from the firmware branch of
// migrationFlagsAndParams — red; answer from p.Paused — red; return no error
// — red.
func TestMigrationOutcome(t *testing.T) {
	cases := []struct {
		name          string
		p             MigrateParams
		paused, undef bool
		refused       bool
	}{
		{"ordinary", MigrateParams{Live: true}, false, true, false},
		{"ordinary paused hand-over", MigrateParams{Live: true, Paused: true}, true, true, false},
		{"firmware live, Paused unset", MigrateParams{Live: true, FirmwareLive: true}, true, false, false},
		{"firmware live storage over TLS", MigrateParams{Live: true, FirmwareLive: true, WithStorage: true, TLS: true,
			TargetAddress: "10.0.0.2", TLSDestination: "10.0.0.2"}, true, false, false},
		{"firmware live storage without TLS", MigrateParams{Live: true, FirmwareLive: true, WithStorage: true,
			TargetAddress: "10.0.0.2", TLSDestination: "10.0.0.2"}, false, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			paused, undef, err := MigrationOutcome(tc.p)
			if (err != nil) != tc.refused {
				t.Fatalf("err = %v, want refused=%v", err, tc.refused)
			}
			if tc.refused {
				return
			}
			if paused != tc.paused || undef != tc.undef {
				t.Errorf("paused, undefineSource = %v, %v; want %v, %v", paused, undef, tc.paused, tc.undef)
			}
		})
	}
}
