package storage

import "strings"

// DiscardDefault reports whether a NEW disk on this storage type is given
// discard=unmap when its spec leaves it unset. It is on where the backend
// reclaims what a TRIM frees and is known to accept it: the local image store
// (a qcow2/raw file on the host filesystem), btrfs, ZFS zvols, thin LVM and
// Ceph RBD. It is off for NFS and iSCSI, whose server may not support
// hole-punching or UNMAP — there the guest's TRIM would be an error, not a
// saving — and for any driver this list does not know. An operator can still set
// discard explicitly on a disk of any type.
func DiscardDefault(driver string) bool {
	switch strings.ToLower(driver) {
	case "", "local", "dir", "btrfs", "zfs", "lvm-thin", "lvmthin", "ceph":
		return true
	}
	return false
}
