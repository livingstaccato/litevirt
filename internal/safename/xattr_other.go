//go:build !linux

package safename

import "errors"

var errNoXattr = errors.New("extended attributes are not supported on this platform")

var lsetxattr = func(string, string, []byte) error { return errNoXattr }

func errorsIsNotSupported(err error) bool { return errors.Is(err, errNoXattr) }
