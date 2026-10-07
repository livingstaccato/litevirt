package grpcapi

import "golang.org/x/sys/unix"

// setImportOriginXattr records origin on p. A filesystem without user xattrs
// keeps none; the host-local placement record still binds the file.
func setImportOriginXattr(p, origin string) error {
	return unix.Lsetxattr(p, importOriginXattr, []byte(origin), 0)
}

func getImportOriginXattr(p string) (string, bool) {
	buf := make([]byte, 512)
	n, err := unix.Lgetxattr(p, importOriginXattr, buf)
	if err != nil || n <= 0 {
		return "", false
	}
	return string(buf[:n]), true
}
