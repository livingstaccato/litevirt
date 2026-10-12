//go:build !linux

package grpcapi

import "errors"

// processesHolding cannot be told off Linux: a deleted image's files are kept.
func processesHolding([]string) (map[string]string, error) {
	return nil, errors.New("the open files of other processes cannot be read on this platform")
}

// networkFilesystem cannot be told off Linux: a deleted image's files are kept.
func networkFilesystem(string) (string, error) {
	return "", errors.New("the filesystem type cannot be read on this platform")
}
