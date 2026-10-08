//go:build linux

package safename

import (
	"errors"

	"golang.org/x/sys/unix"
)

var lsetxattr = func(p, name string, v []byte) error { return unix.Lsetxattr(p, name, v, 0) }


// cannotStoreHere reports whether err says this attribute cannot be stored on
// this filesystem — dropped as main dropped every attribute — rather than a
// real failure: no support (ENOTSUP), no xattr space (ENOSPC, E2BIG, ERANGE),
// an SELinux label the target policy does not know (EINVAL, EACCES), or IMA/EVM
// appraisal refusing a foreign signature (EPERM, EINVAL, EACCES). EPERM on a
// file capability and any I/O error are real failures.
func cannotStoreHere(name string, err error) bool {
	switch {
	case errors.Is(err, unix.ENOTSUP), errors.Is(err, unix.ENOSPC), errors.Is(err, unix.E2BIG), errors.Is(err, unix.ERANGE):
		return true
	case name == "security.selinux" || name == "security.ima" || name == "security.evm":
		return errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM)
	}
	return false
}
