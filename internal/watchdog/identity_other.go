//go:build !linux

package watchdog

import (
	"errors"
	"time"
)

// isHardwareWatchdog is a no-op off Linux (the watchdog device is Linux-only). It
// reports "not a hardware watchdog" so self-fencing capability is never advertised on
// a platform where WDIOC_GETSUPPORT isn't available.
func isHardwareWatchdog(uintptr) (bool, string) { return false, "" }

// The watchdog ioctls are Linux-only; these are no-ops off Linux. petWatchdog returns an
// error so Heartbeat falls back to the keepalive byte-write.
func armWatchdog(uintptr, int)             {}
func petWatchdog(uintptr) error            { return errors.New("watchdog ioctls unsupported off linux") }
func watchdogTimeLeft(uintptr) (int, bool) { return 0, false }
func disarmWatchdog(uintptr)               {}

// watchdogOptions cannot be read off Linux, so nothing is proven.
func watchdogOptions(uintptr) (uint32, bool) { return 0, false }

// bootClock off Linux is the wall clock; nothing there keeps a boot streak.
func bootClock() time.Duration { return time.Duration(time.Now().UnixNano()) }
