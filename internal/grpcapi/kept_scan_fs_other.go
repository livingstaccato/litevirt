//go:build !linux

package grpcapi

import "os"

func keptScanPseudoFS(string) (string, bool, error) { return "", false, nil }

func keptScanPseudoFSOf(*os.File) (string, bool, error) { return "", false, nil }
