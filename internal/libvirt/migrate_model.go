package libvirt

import golibvirt "github.com/digitalocean/go-libvirt"

// MigrationOutcome reports what libvirt is asked to do with a migration of
// p: whether the guest arrives paused on the target, and whether the source
// definition is undefined. It refuses p exactly as MigrateToTarget does,
// before libvirt is reached. libvirtfake models a migration with it, so the
// fake answers from the flags a host would send.
func MigrationOutcome(p MigrateParams) (paused, undefineSource bool, err error) {
	flags, params, err := migrationFlagsAndParams(p)
	if err != nil {
		return false, false, err
	}
	// libvirtd decodes the typed parameters before anything else: one it
	// cannot decode fails the call.
	if err := checkTypedParams(params); err != nil {
		return false, false, err
	}
	return flags&golibvirt.MigratePaused != 0, flags&golibvirt.MigrateUndefineSource != 0, nil
}
