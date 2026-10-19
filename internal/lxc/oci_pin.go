package lxc

import (
	"errors"
	"sync"
	"time"
)

// ErrOCIItemPinned is a replacing pull's refusal of a library item a
// recreate is about to copy (PinOCIItem).
var ErrOCIItemPinned = errors.New("a recreate is about to copy this image")

// ociPinTTL bounds how long a pin outlives a recreate that never reached
// its create (a failed delete, a caller who gave up).
const ociPinTTL = 10 * time.Minute

var ociPins = struct {
	sync.Mutex
	m map[string]map[string]time.Time // item → holder → until
}{m: map[string]map[string]time.Time{}}

// PinOCIItem checks, under the item's lock, that library item dir is
// generation gen and, when it is, keeps every replacing pull of it off
// (ErrOCIItemPinned) for holder, a container a recreate is about to copy
// it into, until UnpinOCIItem(dir, holder) or ociPinTTL. It reports false,
// pinning nothing, when the item is not generation gen.
func PinOCIItem(dir, holder, gen string) bool {
	unlock := LockOCIItem(dir)
	defer unlock()
	if ReadImageGen(dir) != gen {
		return false
	}
	key := canonPath(dir)
	ociPins.Lock()
	defer ociPins.Unlock()
	if ociPins.m[key] == nil {
		ociPins.m[key] = map[string]time.Time{}
	}
	ociPins.m[key][holder] = time.Now().Add(ociPinTTL)
	return true
}

// UnpinOCIItem drops holder's pin on dir, if any.
func UnpinOCIItem(dir, holder string) {
	key := canonPath(dir)
	ociPins.Lock()
	defer ociPins.Unlock()
	delete(ociPins.m[key], holder)
	if len(ociPins.m[key]) == 0 {
		delete(ociPins.m, key)
	}
}

// OCIItemPinnedBy names a holder of a live pin on dir, "" when it has none.
// A replacing pull asks it while holding the item's lock.
func OCIItemPinnedBy(dir string) string {
	key := canonPath(dir)
	now := time.Now()
	ociPins.Lock()
	defer ociPins.Unlock()
	for h, until := range ociPins.m[key] {
		if now.Before(until) {
			return h
		}
		delete(ociPins.m[key], h)
	}
	delete(ociPins.m, key)
	return ""
}
