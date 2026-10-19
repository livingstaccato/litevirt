//go:build !unix

package fleet

import "errors"

// portHoldSupported: holdPort does not work here.
const portHoldSupported = false

// holdPort is not implemented here: a stopped node's port is not held.
func holdPort(string, int) (func(), error) {
	return nil, errors.New("hold port: unsupported on this platform")
}
