//go:build !linux

package lxc

import "os/exec"

func dieWithDaemon(cmd *exec.Cmd) *exec.Cmd { return cmd }

func runPinned(fn func() error) error { return fn() }

func stopWorkersIn(string) {}
