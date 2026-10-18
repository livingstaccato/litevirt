//go:build !linux

package libvirt

var osSwtpmFlagOps = swtpmFlagOps{
	get: func(string) (uint32, error) { return 0, errFlagsUnavailable },
	set: func(string, uint32) error { return errFlagsUnavailable },
}
