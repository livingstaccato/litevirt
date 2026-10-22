//go:build !linux

package libvirt

import "errors"

// KillPartitionPaused needs Linux pidfds; elsewhere it always fails, and the
// partition pauser falls back to reporting the pause failed.
func (c *Client) KillPartitionPaused(name, uuid string) error {
	return errors.New("kill qemu: not supported on this platform")
}
