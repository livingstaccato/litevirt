package cloudinit

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/litevirt/litevirt/internal/randid"
)

// Which VM a seed belongs to.
//
// A seed is name-keyed (<data_dir>/cloudinit/<name>.iso), and it outlives its
// VM on a host the VM left without a delete reaching it: a failover's old
// host, a --keep-disks delete. A VM created again under the name and started
// on such a host — a failover, a migration, a start — reused the file it found
// there, and booted the deleted VM's user-data: its SSH keys, its passwords,
// its network-config.
//
// So every seed litevirt writes is stamped with the identity of the VM it was
// written for, in a file beside it (<seed>.owner), and a seed is reused only
// for that VM; any other is generated again from the VM's own spec. The
// identity is the spec's uuid: minted by the server for every create and
// every clone, before the seed is written, and carried in the VM's row.
//
// A seed written before this release has no stamp, and nothing proves whose
// it is: it is generated again from the VM's own spec, and stamped. The
// instance-id is the VM's name either way, so a guest that already booted
// from it does not run its first-boot modules again.

// seedOwnerSuffix names the stamp beside a seed.
const seedOwnerSuffix = ".owner"

// SeedOwnerPath is where the stamp of the seed at iso is.
func SeedOwnerPath(iso string) string { return iso + seedOwnerSuffix }

// StampSeed records that the seed at iso was written for the VM whose spec
// uuid is owner. An empty owner (a VM from before stable uuids) removes the
// stamp, so the seed is judged as an unstamped one.
func StampSeed(iso, owner string) error {
	stamp := SeedOwnerPath(iso)
	if owner == "" {
		if err := os.Remove(stamp); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	// The sweep of stale seed temporaries (sweepStaleSeedTemps) covers this
	// name too.
	tmp := filepath.Join(filepath.Dir(iso), "."+filepath.Base(iso)+"."+randid.New()+".tmp")
	if err := os.WriteFile(tmp, []byte(owner+"\n"), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, stamp); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// RemoveSeed removes the seed at iso and its stamp.
func RemoveSeed(iso string) error {
	err := os.Remove(iso)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if serr := os.Remove(SeedOwnerPath(iso)); serr != nil && !os.IsNotExist(serr) {
		return serr
	}
	return nil
}

// SeedOwner returns the stamp of the seed at iso: ok=false when it has none.
func SeedOwner(iso string) (owner string, ok bool, err error) {
	b, err := os.ReadFile(SeedOwnerPath(iso))
	if errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return strings.TrimSpace(string(b)), true, nil
}

// SeedIsFor reports whether the seed at iso exists and is stamped as written
// for the VM whose spec uuid is owner. An unstamped seed, a VM with no uuid,
// or anything unreadable answers no, and the caller writes the seed again.
func SeedIsFor(iso, owner string) bool {
	fi, err := os.Stat(iso)
	if err != nil || !fi.Mode().IsRegular() || owner == "" {
		return false
	}
	stamp, stamped, err := SeedOwner(iso)
	return err == nil && stamped && stamp == owner
}

// SpecUUID is the uuid of a VM spec stored as JSON, "" when it has none.
func SpecUUID(specJSON string) string {
	var s struct {
		UUID string `json:"uuid"`
	}
	if json.Unmarshal([]byte(specJSON), &s) != nil {
		return ""
	}
	return s.UUID
}
