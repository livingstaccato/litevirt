//go:build !linux

package filerestore

// IsAgent is always false off Linux: a restore VM boots a Linux kernel.
func IsAgent() bool { return false }

// RunAgent does nothing off Linux.
func RunAgent() {}
