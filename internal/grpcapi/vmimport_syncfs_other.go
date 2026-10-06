//go:build !linux

package grpcapi

// syncFilesystem has no syncfs off Linux, where no btrfs is keyed.
func syncFilesystem(string) error { return nil }
