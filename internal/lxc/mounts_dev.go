package lxc

import (
	"io/fs"
	"syscall"
)

// deviceNumbers reads a device node's kind and major:minor.
func deviceNumbers(fi fs.FileInfo) (kind byte, major, minor uint32, ok bool) {
	switch {
	case fi.Mode()&fs.ModeCharDevice != 0:
		kind = 'c'
	case fi.Mode()&fs.ModeDevice != 0:
		kind = 'b'
	default:
		return 0, 0, 0, false
	}
	st, sok := fi.Sys().(*syscall.Stat_t)
	if !sok {
		return 0, 0, 0, false
	}
	rdev := uint64(st.Rdev) // uint64 on linux, int32 on darwin
	major = uint32(((rdev >> 8) & 0xfff) | ((rdev >> 32) & 0xfffff000))
	minor = uint32((rdev & 0xff) | ((rdev >> 12) & 0xffffff00))
	return kind, major, minor, true
}
