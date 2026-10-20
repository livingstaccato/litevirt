package fleet

// A daemon killed mid-move, for the crash scenarios of fwlive_restart_test.go
// and fwlive_cleanup_hold_test.go.
//
// The daemon's goroutine stops at the crash point inside a libvirt call (a
// fake's hook calls freeze). The scenario then kills the daemon (die). First
// every way the old daemon has to the world is severed: its libvirt
// connection (libvirtfake SeverDaemon), its database client (corrosion
// SeverWritesForTests), its files (the node's directories made read-only)
// and the network both ways (BlockAll on each link). Then the frozen
// goroutine is ended where it stands (runtime.Goexit: the libvirt call never
// returns, its deferred calls run). Every other goroutine of the old daemon
// ends at its next libvirt call, and what it asks of the database, the files
// or a peer is refused.
//
// die waits for the frozen goroutine to be gone and for the move's own
// handler to have returned, takes the daemon down (downNode, which joins
// what the server still owns), and checks that nothing the dead daemon did
// reached libvirt, the database, the files or a peer. Only then are the
// severs lifted for the replacement. A goroutine that does not end within a
// minute fails the scenario; a wait running out is never taken as an end.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
)

// fwliveCrash is one daemon's death at a crash point.
type fwliveCrash struct {
	t *testing.T
	c *Cluster
	n *Node
	// reached is closed when the daemon's goroutine is at the crash point;
	// kill, closed by die, ends it there.
	reached, kill chan struct{}
	reachOnce     sync.Once
	killOnce      sync.Once
	// goid is the frozen goroutine's id.
	goid atomic.Uint64
	// moveDone is closed when n's MigrateVM handler for the move returned
	// (trackMove); nil when no handler is tracked.
	moveDone chan struct{}
	died     bool
}

// fwliveNewCrash prepares n's daemon to die at a crash point. A scenario
// that fails before die still has the daemon die, severed, at its end, so no
// frozen goroutine outlives it.
func fwliveNewCrash(t *testing.T, c *Cluster, n *Node) *fwliveCrash {
	t.Helper()
	k := &fwliveCrash{t: t, c: c, n: n, reached: make(chan struct{}), kill: make(chan struct{})}
	t.Cleanup(func() {
		select {
		case <-k.reached:
			if !k.died {
				k.die(false)
			}
		default:
			k.killOnce.Do(func() { close(k.kill) })
		}
	})
	return k
}

// trackMove makes die wait for n's next MigrateVM handler to return; armed
// before the move starts.
func (k *fwliveCrash) trackMove() {
	k.moveDone = make(chan struct{})
	done := k.moveDone
	k.n.HookStream("MigrateVM", func(srv any, ss grpc.ServerStream, h grpc.StreamHandler) error {
		defer close(done)
		return h(srv, ss)
	})
}

// freeze is the crash point, called on the daemon's goroutine: it waits for
// the kill and ends the goroutine there.
func (k *fwliveCrash) freeze() {
	k.goid.Store(fwliveGoid())
	k.reachOnce.Do(func() { close(k.reached) })
	<-k.kill
	runtime.Goexit()
}

// die kills the daemon at its crash point (see above). check: the dead
// daemon's effects are asserted (false only on a failed scenario's way out).
func (k *fwliveCrash) die(check bool) {
	t, c, n := k.t, k.c, k.n
	t.Helper()
	k.died = true
	root := filepath.Join(c.tmpRoot, n.Name)

	// Sever everything, then take what the world holds at the death.
	virtRestore := n.Virt.SeverDaemon()
	dbRestore := n.DB.SeverWritesForTests()
	filesRestore := fwliveReadOnly(t, root)
	netRestore := fwliveIsolate(c, n)
	lifted := false
	lift := func() {
		if lifted {
			return
		}
		lifted = true
		calls := virtRestore()
		refused := dbRestore()
		filesRestore()
		netRestore()
		t.Logf("%s's dead daemon: libvirt calls ended %v, commits refused %d", n.Name, calls, refused)
	}
	defer lift()

	virt0 := n.Virt.Fingerprint()
	files0 := fwliveTreeDigest(t, root)
	log0 := fwliveOriginEntries(t, n)
	passed0 := fwlivePassed(c, n)

	k.killOnce.Do(func() { close(k.kill) })
	fail := t.Fatalf
	if !check {
		fail = t.Logf
	}
	if id := k.goid.Load(); id != 0 {
		if !fwliveUntil(time.Minute, func() bool { return !fwliveGoroutineAlive(id) }) {
			fail("%s's frozen goroutine %d did not end within a minute of the kill", n.Name, id)
			return
		}
	}
	if k.moveDone != nil {
		select {
		case <-k.moveDone:
		case <-time.After(time.Minute):
			fail("%s's MigrateVM handler did not return within a minute of the kill", n.Name)
			return
		}
	}
	downNode(n)
	if !check {
		return
	}

	if v := n.Virt.Fingerprint(); v != virt0 {
		t.Errorf("%s's dead daemon changed libvirt after its death", n.Name)
	}
	if f := fwliveTreeDigest(t, root); f != files0 {
		t.Errorf("%s's dead daemon changed its files after its death", n.Name)
	}
	if l := fwliveOriginEntries(t, n); l != log0 {
		t.Errorf("%s's dead daemon wrote %d replicated entries after its death", n.Name, l-log0)
	}
	for name, p := range fwlivePassed(c, n) {
		if p != passed0[name] {
			t.Errorf("%s's dead daemon reached %s with %d calls after its death", n.Name, name, p-passed0[name])
		}
	}
}

// fwliveGoid is the calling goroutine's id.
func fwliveGoid() uint64 {
	var b [64]byte
	s := b[:runtime.Stack(b[:], false)]
	s = bytes.TrimPrefix(s, []byte("goroutine "))
	if i := bytes.IndexByte(s, ' '); i > 0 {
		s = s[:i]
	}
	id, err := strconv.ParseUint(string(s), 10, 64)
	if err != nil {
		panic(fmt.Sprintf("fwliveGoid: %q", b[:]))
	}
	return id
}

// fwliveGoroutineAlive reports whether the goroutine id still exists.
func fwliveGoroutineAlive(id uint64) bool {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	return bytes.Contains(buf, []byte(fmt.Sprintf("goroutine %d [", id)))
}

// fwliveUntil polls cond until it holds (true) or d runs out (false).
func fwliveUntil(d time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(d)
	for {
		if cond() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// fwliveReadOnly takes write permission from everything under root, as the
// dead daemon's open of any file there is refused; restore gives back each
// one's mode. A process running as root is not refused by modes: the digest
// die compares still catches anything written.
func fwliveReadOnly(t *testing.T, root string) (restore func()) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Logf("running as root: file modes do not refuse %s's dead daemon; the file digest still checks it", root)
	}
	modes := map[string]fs.FileMode{}
	var paths []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		modes[p] = info.Mode().Perm()
		paths = append(paths, p)
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	for _, p := range paths {
		if err := os.Chmod(p, modes[p]&^0o222); err != nil {
			t.Fatalf("make %s read-only: %v", p, err)
		}
	}
	return func() {
		for _, p := range paths {
			if err := os.Chmod(p, modes[p]); err != nil {
				t.Errorf("give %s its mode back: %v", p, err)
			}
		}
	}
}

// fwliveTreeDigest digests every name, file content and link under root.
func fwliveTreeDigest(t *testing.T, root string) string {
	t.Helper()
	var lines []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		switch {
		case d.Type()&fs.ModeSymlink != 0:
			target, err := os.Readlink(p)
			if err != nil {
				return err
			}
			lines = append(lines, "L "+rel+" "+target)
		case d.IsDir():
			lines = append(lines, "D "+rel)
		case d.Type().IsRegular():
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			sum := sha256.Sum256(b)
			lines = append(lines, "F "+rel+" "+hex.EncodeToString(sum[:]))
		default:
			lines = append(lines, "O "+rel)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("digest %s: %v", root, err)
	}
	sort.Strings(lines)
	sum := sha256.Sum256([]byte(fmt.Sprint(lines)))
	return hex.EncodeToString(sum[:])
}

// fwliveOriginEntries counts the replicated entries n wrote.
func fwliveOriginEntries(t *testing.T, n *Node) int {
	t.Helper()
	rows, err := n.DB.Query(context.Background(), `SELECT COUNT(*) FROM mutation_log WHERE origin = ?`, n.Name)
	if err != nil || len(rows) != 1 {
		t.Fatalf("count %s's replicated entries: %v", n.Name, err)
	}
	v, ok := rows[0].Values[0].(int64)
	if !ok {
		t.Fatalf("count %s's replicated entries: %T", n.Name, rows[0].Values[0])
	}
	return int(v)
}

// fwliveIsolate refuses every RPC between n and each other node, both ways
// (BlockAll on each link, on top of what the link already does); restore puts
// each link's fault back.
func fwliveIsolate(c *Cluster, n *Node) (restore func()) {
	type link struct {
		from, to *Node
		fault    LinkFault
	}
	var links []link
	for _, o := range c.Nodes {
		if o == n {
			continue
		}
		for _, l := range []link{{from: n, to: o}, {from: o, to: n}} {
			l.fault = c.LinkFaultOf(l.from, l.to)
			links = append(links, l)
			f := l.fault
			f.BlockAll = true
			c.SetLinkFault(l.from, l.to, f)
		}
	}
	return func() {
		for _, l := range links {
			c.SetLinkFault(l.from, l.to, l.fault)
		}
	}
}

// fwlivePassed is, per other node, how many of n's calls its links let past
// BlockAll.
func fwlivePassed(c *Cluster, n *Node) map[string]int {
	out := map[string]int{}
	for _, o := range c.Nodes {
		if o != n {
			out[o.Name] = c.LinkStats(n, o).Passed
		}
	}
	return out
}
