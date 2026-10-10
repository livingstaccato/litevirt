//go:build !linux

package lxc

import "errors"

// hostAccessSupported: host bind mounts need Linux's openat2 and mount API.
var hostAccessSupported = func() error { return errors.New("not Linux") }

// RunHook is the LXC start hook; LXC exists on Linux only.
func RunHook(args []string) int { return 1 }

func exclusiveOpenBusyOS(string) bool { return false }
