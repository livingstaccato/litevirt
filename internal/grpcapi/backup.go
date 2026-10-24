package grpcapi

import "github.com/litevirt/litevirt/internal/safename"

// maxRestoreBytes is a sanity ceiling on a single streamed write (image import)
// so a client can't write until the disk fills. Generous for real disks.
const maxRestoreBytes int64 = 2 << 40 // 2 TiB

// validRestoreName rejects names that would let filepath.Join escape dataDir.
// It delegates to internal/safename, the single source of truth for the safe
// name charset (letters, digits, '_', '.', '-'; no '/', no '.'/'..').
func validRestoreName(name string) bool {
	return safename.ValidateName(name) == nil
}

// validResourceName enforces the same safe charset on user-supplied resource
// names rendered into shell/config templates run as root (e.g. load-balancer
// and backend names in the HAProxy/keepalived configs). Same rule as
// validRestoreName; named generically because it guards more than restores.
func validResourceName(name string) bool {
	return validRestoreName(name)
}
