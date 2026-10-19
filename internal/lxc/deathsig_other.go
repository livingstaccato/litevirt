//go:build !linux

package lxc

import (
	"os"
	"os/exec"
	"syscall"
)

func dieWithDaemon(cmd *exec.Cmd) *exec.Cmd { return cmd }

func runPinned(fn func() error) error { return fn() }

func stopWorkersIn(string) {}

func flockTry(*os.File) (bool, error) { return true, nil }

func openedFilePath(f *os.File) (string, error) { return f.Name(), nil }

func openNoFollow(path string, dir bool) (*os.File, error) {
	flags := syscall.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC | syscall.O_NONBLOCK
	if dir {
		flags |= syscall.O_DIRECTORY
	}
	return os.OpenFile(path, flags, 0)
}

func reopenRead(ref *os.File, _ bool) (*os.File, error) {
	return os.OpenFile(ref.Name(), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
}
