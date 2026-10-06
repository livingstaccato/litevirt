//go:build !linux

package grpcapi

// Off Linux no origin is recorded, and leftovers are judged by age alone.
func setImportOrigin(string, string) error { return nil }

func getImportOrigin(string) (string, bool) { return "", false }
