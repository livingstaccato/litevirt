//go:build !linux

package grpcapi

// Off Linux no origin xattr is kept; the placement record alone binds a file.
func setImportOriginXattr(string, string) error { return nil }

func getImportOriginXattr(string) (string, bool) { return "", false }
