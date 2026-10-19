//go:build !linux

package libvirt

var osSwtpmFDOps = swtpmFDOps{}

// syncSwtpmTree: no inode flags off Linux.
func syncSwtpmTree(base string, on bool, marker string, ops swtpmFDOps) SwtpmSyncReport {
	if !on {
		return SwtpmSyncReport{State: SwtpmSyncOff, Base: base}
	}
	return SwtpmSyncReport{State: SwtpmSyncUnsupported, Base: base, Err: errFlagsUnavailable}
}
