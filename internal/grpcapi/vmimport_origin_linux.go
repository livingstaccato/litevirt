package grpcapi

import "golang.org/x/sys/unix"

// setImportOrigin records origin on p. A filesystem without user xattrs keeps
// none, and its leftovers are judged by age alone.
func setImportOrigin(p, origin string) error {
	return unix.Lsetxattr(p, importOriginXattr, []byte(origin), 0)
}

func getImportOrigin(p string) (string, bool) {
	buf := make([]byte, 512)
	n, err := unix.Lgetxattr(p, importOriginXattr, buf)
	if err != nil || n <= 0 {
		return "", false
	}
	return string(buf[:n]), true
}
