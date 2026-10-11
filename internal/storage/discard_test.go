package storage

import "testing"

// Thin-capable backends default to discard; NFS and iSCSI, whose server may
// refuse a hole punch or UNMAP, and anything unknown do not.
func TestDiscardDefault(t *testing.T) {
	for d, want := range map[string]bool{
		"": true, "local": true, "dir": true, "btrfs": true, "zfs": true,
		"lvm-thin": true, "lvmthin": true, "ceph": true, "ZFS": true,
		"nfs": false, "iscsi": false, "gluster": false,
	} {
		if got := DiscardDefault(d); got != want {
			t.Errorf("DiscardDefault(%q) = %v, want %v", d, got, want)
		}
	}
}
