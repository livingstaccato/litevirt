//go:build !linux

package grpcapi

// fileBirth is 0 off Linux: the identity is the inode alone.
func fileBirth(string) int64 { return 0 }
