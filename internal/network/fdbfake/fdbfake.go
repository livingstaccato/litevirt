// Package fdbfake models the kernel's VXLAN forwarding database behind the
// `bridge fdb` commands, for tests: one entry per MAC with a list of
// destinations, as vxlan_fdb_update keeps it.
//
//   - `add` creates an entry (NLM_F_EXCL): a MAC that already has one —
//     including the all-zeros flood entry with another destination — is
//     refused with "File exists", and nothing changes.
//   - `append` adds a destination to the MAC's entry (NLM_F_APPEND); one
//     already there is a no-op.
//   - `del ... dst X` removes that destination only; the entry goes with
//     its last one.
//   - `show dev D` prints one line per destination.
package fdbfake

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
)

// Kernel is one host's VXLAN forwarding database, per device.
type Kernel struct {
	mu  sync.Mutex
	fdb map[string]map[string][]string // device → MAC → destinations
}

// New returns an empty database.
func New() *Kernel { return &Kernel{fdb: map[string]map[string][]string{}} }

var errExit = errors.New("exit status 2")

// Exec answers `bridge fdb add|append|del|show` the way the kernel does;
// every other command succeeds with no output. Its signature is the network
// package's ExecFunc.
func (k *Kernel) Exec(name string, args ...string) ([]byte, error) {
	if name != "bridge" || len(args) < 2 || args[0] != "fdb" {
		return nil, nil
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	verb := args[1]
	if verb == "show" {
		return []byte(k.show(flag(args, "dev"))), nil
	}
	if len(args) < 3 {
		return nil, nil
	}
	mac, dev, dst := strings.ToLower(args[2]), flag(args, "dev"), flag(args, "dst")
	if k.fdb[dev] == nil {
		k.fdb[dev] = map[string][]string{}
	}
	dsts := k.fdb[dev][mac]
	switch verb {
	case "add":
		if len(dsts) > 0 {
			return []byte("RTNETLINK answers: File exists\n"), errExit
		}
		k.fdb[dev][mac] = []string{dst}
	case "append":
		if !slices.Contains(dsts, dst) {
			k.fdb[dev][mac] = append(dsts, dst)
		}
	case "del":
		i := slices.Index(dsts, dst)
		if i < 0 {
			return []byte("RTNETLINK answers: No such file or directory\n"), errExit
		}
		dsts = slices.Delete(dsts, i, i+1)
		if len(dsts) == 0 {
			delete(k.fdb[dev], mac)
		} else {
			k.fdb[dev][mac] = dsts
		}
	}
	return nil, nil
}

func flag(args []string, name string) string {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == name {
			return args[i+1]
		}
	}
	return ""
}

func (k *Kernel) show(dev string) string {
	var b strings.Builder
	macs := make([]string, 0, len(k.fdb[dev]))
	for mac := range k.fdb[dev] {
		macs = append(macs, mac)
	}
	sort.Strings(macs)
	for _, mac := range macs {
		for _, d := range k.fdb[dev][mac] {
			fmt.Fprintf(&b, "%s dst %s self permanent\n", mac, d)
		}
	}
	return b.String()
}

// Dsts returns mac's destinations on dev, sorted.
func (k *Kernel) Dsts(dev, mac string) []string {
	k.mu.Lock()
	defer k.mu.Unlock()
	out := append([]string(nil), k.fdb[dev][strings.ToLower(mac)]...)
	sort.Strings(out)
	return out
}

// Set installs mac's destinations on dev directly, as an earlier build left them.
func (k *Kernel) Set(dev, mac string, dsts ...string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.fdb[dev] == nil {
		k.fdb[dev] = map[string][]string{}
	}
	k.fdb[dev][strings.ToLower(mac)] = append([]string(nil), dsts...)
}
