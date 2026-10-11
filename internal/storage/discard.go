package storage

import "strings"

// DiscardDefault reports whether a NEW disk on this storage type is given
// discard=unmap when its spec leaves it unset. It is on where the backend
// reclaims what a TRIM frees and is known to accept it: the local image store
// (a qcow2/raw file on the host filesystem), btrfs, ZFS zvols, thin LVM and
// Ceph RBD. It is off for NFS and iSCSI as a conservative choice: whether a
// guest's TRIM frees anything there depends on the server's own space
// accounting (qemu tolerates a server that refuses it, so this is not about
// errors), and a `dir` pool may itself sit on NFS — and for any driver this list
// does not know. An operator can still set
// discard explicitly on a disk of any type.
func DiscardDefault(driver string) bool {
	switch strings.ToLower(driver) {
	case "", "local", "dir", "btrfs", "zfs", "lvm-thin", "lvmthin", "ceph":
		return true
	}
	return false
}
