//go:build !linux

package grpcapi

import "os"

// fileCtimeNs is 0 off Linux: a record there binds no change time.
func fileCtimeNs(os.FileInfo) int64 { return 0 }
