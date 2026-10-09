//go:build !linux

package lxc

func getXattr(string, string) []byte        { return nil }
func setXattr(string, string, []byte) error { return errNoXattr }
func idmappableFS(string) bool              { return false }
