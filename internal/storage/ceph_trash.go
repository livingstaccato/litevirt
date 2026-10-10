package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Removing an rbd image. `rbd rm` deletes every data object of the image
// before it returns — minutes for a large, fully written one — so a delete
// bounded by any fixed cap a request can wait for was killed part-way, and the
// image was left in the trash in the REMOVING state, still using its capacity,
// with nothing in litevirt naming it.
//
// So an image is removed in two steps, the way `rbd rm` itself does them:
//
//  1. `rbd trash mv` once no client watches it. Metadata only: quick, and the
//     same whatever the image's size. The name is free from here on, and the
//     delete reports success.
//  2. `rbd trash rm <pool>/<id>` in the background, with no short cap,
//     retried until rbd has removed it. Each pending purge is tracked
//     (CephPendingPurges), kept in a file under the data directory so a
//     restart resumes it (ResumeCephPurges), and one that keeps failing is
//     named by the ceph_trash_leftover condition.
//
// Only an image this host moved to the trash, or one an interrupted `rbd rm`
// left there (source REMOVING), is ever purged: an image someone moved there
// by hand is theirs to restore.

// cephPurgeStateFile is the file, under the daemon's data directory, the
// pending purges are kept in.
const cephPurgeStateFile = "ceph-trash-purges.json"

// trashMoveTimeout bounds one `rbd trash mv`: metadata only, but it takes the
// image's lock, which a killed client's watch holds for about 30 s.
const trashMoveTimeout = 2 * time.Minute

// purgeCallTimeout bounds one `rbd trash rm`. Not a cap a large image
// outlives: it only keeps a wedged rbd from holding the purge forever; the
// purge is then retried, and resumes where the last one stopped.
const purgeCallTimeout = 12 * time.Hour

// userBusyBudget is how long a user's delete waits for the clients watching
// an image to go before refusing it as in use: past the 30 s a dead client's
// watch lasts (lab 2), so a delete the blocking `rbd rm` it replaces would
// have completed still completes; a live client keeps it refused.
const userBusyBudget = 45 * time.Second

// CephPurge is an rbd image moved to its pool's trash that this host still
// owes a `rbd trash rm`.
type CephPurge struct {
	Pool  string `json:"pool"`  // the rbd pool (and namespace) of the trash
	ID    string `json:"id"`    // the image's id, what `rbd trash rm` removes
	Image string `json:"image"` // the name it had
	// Opts are the pool's identity and monitors (id, keyring, conf,
	// mon_host): paths and names, never a key.
	Opts      map[string]string `json:"opts,omitempty"`
	Since     time.Time         `json:"since"`
	Attempts  int               `json:"attempts"`
	LastError string            `json:"last_error,omitempty"`
}

// TrashRef is the purge's `rbd trash rm` argument, <pool>/<id>.
func (p CephPurge) TrashRef() string { return p.Pool + "/" + p.ID }

type cephPurgeEntry struct {
	CephPurge
	run     cmdRunner // nil → cephRunner (a purge resumed after a restart)
	looping bool
}

type cephPurgeQueue struct {
	mu      sync.Mutex
	m       map[string]*cephPurgeEntry // TrashRef → entry
	dir     string                     // where the queue is kept ("" → memory only)
	writeMu sync.Mutex
}

var cephPurges = &cephPurgeQueue{m: map[string]*cephPurgeEntry{}}

// cephPurgeGo runs a purge loop; tests run purges by hand instead.
var cephPurgeGo = func(f func()) { go f() }

// purgeOpts is the part of a pool's options a purge needs to reach it.
func purgeOpts(opts map[string]string) map[string]string {
	out := map[string]string{}
	for _, k := range []string{"id", "keyring", "conf", "mon_host"} {
		if v := opts[k]; v != "" {
			out[k] = v
		}
	}
	return out
}

// queuePurge records that pool's trash holds image (id) for this host to
// purge, and starts its purge.
func (d *cephDriver) queuePurge(pool, id, image string) {
	ref := pool + "/" + id
	q := cephPurges
	q.mu.Lock()
	e, ok := q.m[ref]
	if !ok {
		// The runner the delete ran with (a test's stand-in stays its own,
		// even after the test restores the real one).
		e = &cephPurgeEntry{CephPurge: CephPurge{Pool: pool, ID: id, Image: image, Opts: purgeOpts(d.opts), Since: time.Now().UTC()}, run: d.runner()}
		q.m[ref] = e
	}
	start := !e.looping
	e.looping = true
	q.mu.Unlock()
	q.save()
	slog.Info("ceph: image moved to the trash; its objects are purged in the background",
		"image", pool+"/"+image, "trash", ref)
	if start {
		cephPurgeGo(func() { purgeLoop(ref) })
	}
}

// purgeLoop retries one purge until it is done, backing off to ten minutes.
func purgeLoop(ref string) {
	wait := 10 * time.Second
	for !attemptCephPurge(ref) {
		if !cephSleep(context.Background(), wait) {
			return
		}
		wait = min(wait*2, 10*time.Minute)
	}
}

// attemptCephPurge runs one `rbd trash rm` of a queued purge; done is true
// once it is gone from the trash (or from the queue).
func attemptCephPurge(ref string) (done bool) {
	q := cephPurges
	q.mu.Lock()
	e, ok := q.m[ref]
	var p CephPurge
	var run cmdRunner
	if ok {
		p, run = e.CephPurge, e.run
	}
	q.mu.Unlock()
	if !ok {
		return true
	}
	d := &cephDriver{opts: p.Opts, run: run}
	ctx, cancel := context.WithTimeout(context.Background(), purgeCallTimeout)
	defer cancel()
	out, err := d.rbd(ctx, d.rbdArgs("trash", "rm", "--", ref)...)
	if err == nil || (rbdErrno(err) == rbdENOENT && !d.trashHolds(ctx, p.Pool, p.ID)) {
		q.forget(ref)
		slog.Info("ceph: purged an image from the trash", "image", p.Pool+"/"+p.Image, "trash", ref)
		return true
	}
	msg := fmt.Sprintf("%v: %s", err, strings.TrimSpace(string(out)))
	q.mu.Lock()
	if e, ok := q.m[ref]; ok {
		e.Attempts++
		e.LastError = msg
	}
	q.mu.Unlock()
	q.save()
	slog.Warn("ceph: an image in the rbd trash is not purged yet; retrying",
		"image", p.Pool+"/"+p.Image, "trash", ref, "error", msg,
		"by_hand", "rbd trash rm "+ref)
	return false
}

// trashHolds reports whether pool's trash lists id; true when the trash cannot
// be read (a purge is never forgotten on a guess).
func (d *cephDriver) trashHolds(ctx context.Context, pool, id string) bool {
	entries, err := d.trashList(ctx, pool)
	if err != nil {
		return true
	}
	for _, e := range entries {
		if e.ID == id {
			return true
		}
	}
	return false
}

type trashEntry struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Source string `json:"source"`
}

// trashList lists pool's trash, every source (`--all`: an interrupted rm's
// entries are REMOVING, which the default listing leaves out).
func (d *cephDriver) trashList(ctx context.Context, pool string) ([]trashEntry, error) {
	out, err := d.rbd(ctx, d.rbdArgs("trash", "ls", "--all", "--format", "json", "--", pool)...)
	if err != nil {
		return nil, fmt.Errorf("rbd trash ls %s: %w: %s", pool, err, strings.TrimSpace(string(out)))
	}
	var entries []trashEntry
	if err := json.Unmarshal(out, &entries); err != nil {
		return nil, fmt.Errorf("rbd trash ls %s: %w", pool, err)
	}
	return entries, nil
}

func (q *cephPurgeQueue) forget(ref string) {
	q.mu.Lock()
	delete(q.m, ref)
	q.mu.Unlock()
	q.save()
}

// save writes the queue to its file (replaced whole), when it has one.
func (q *cephPurgeQueue) save() {
	q.writeMu.Lock()
	defer q.writeMu.Unlock()
	q.mu.Lock()
	dir := q.dir
	list := q.listLocked()
	q.mu.Unlock()
	if dir == "" {
		return
	}
	raw, err := json.MarshalIndent(list, "", "  ")
	if err == nil {
		err = writeFileAtomic(filepath.Join(dir, cephPurgeStateFile), raw)
	}
	if err != nil {
		slog.Warn("ceph: the trash purge queue was not saved; a restart forgets what it holds", "error", err)
	}
}

func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func (q *cephPurgeQueue) listLocked() []CephPurge {
	out := make([]CephPurge, 0, len(q.m))
	for _, e := range q.m {
		p := e.CephPurge
		p.Opts = purgeOpts(e.Opts)
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TrashRef() < out[j].TrashRef() })
	return out
}

// CephPendingPurges lists the images in a ceph pool's trash this host still
// owes a purge, oldest reference first by name.
func CephPendingPurges() []CephPurge {
	q := cephPurges
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.listLocked()
}

// ResumeCephPurges keeps the purge queue under dir from now on, and resumes
// the purges a previous run of the daemon left in it.
func ResumeCephPurges(dir string) error {
	q := cephPurges
	raw, err := os.ReadFile(filepath.Join(dir, cephPurgeStateFile))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read the ceph trash purge queue: %w", err)
	}
	var saved []CephPurge
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &saved); err != nil {
			return fmt.Errorf("read the ceph trash purge queue: %w", err)
		}
	}
	var start []string
	q.mu.Lock()
	q.dir = dir
	for _, p := range saved {
		if p.Pool == "" || p.ID == "" {
			continue
		}
		ref := p.TrashRef()
		e, ok := q.m[ref]
		if !ok {
			e = &cephPurgeEntry{CephPurge: p}
			q.m[ref] = e
		}
		if !e.looping {
			e.looping = true
			start = append(start, ref)
		}
	}
	q.mu.Unlock()
	q.save()
	for _, ref := range start {
		cephPurgeGo(func() { purgeLoop(ref) })
	}
	if len(start) > 0 {
		slog.Info("ceph: resumed purging images a previous run moved to the trash", "count", len(start))
	}
	return nil
}

// attemptCephPurges runs one attempt of every queued purge (tests).
func attemptCephPurges() {
	for _, p := range CephPendingPurges() {
		attemptCephPurge(p.TrashRef())
	}
}

// RunCephPurgesOnceForTest runs one attempt of every queued purge, for tests
// in other packages that stop the background loops (OverrideCephPurgeLoopForTest).
func RunCephPurgesOnceForTest() { attemptCephPurges() }

// OverrideCephPurgeLoopForTest stops queued purges from starting background
// loops (they run only through RunCephPurgesOnceForTest), and empties the
// queue; it returns the restore.
func OverrideCephPurgeLoopForTest() func() {
	prev := cephPurgeGo
	cephPurgeGo = func(func()) {}
	resetCephPurgeQueue()
	return func() {
		cephPurgeGo = prev
		resetCephPurgeQueue()
	}
}

func resetCephPurgeQueue() {
	q := cephPurges
	q.mu.Lock()
	q.m = map[string]*cephPurgeEntry{}
	q.dir = ""
	q.mu.Unlock()
}

// cephInUseError is a delete refused because a client still has the image
// open: a VM somewhere still runs on it.
type cephInUseError struct {
	ref, status string
}

func (e *cephInUseError) Error() string {
	return fmt.Sprintf("ceph image %s is in use (another client still has it open; stop the VM using it first): %s", e.ref, e.status)
}

// watchers reports the clients `rbd status` lists as watching ref, with rbd's
// own output to name them.
func (d *cephDriver) watchers(ctx context.Context, ref string) (bool, string, error) {
	out, err := d.rbd(ctx, d.rbdArgs("status", "--format", "json", "--", ref)...)
	text := strings.TrimSpace(string(out))
	if err != nil {
		return false, text, fmt.Errorf("rbd status %s: %w: %s", ref, err, text)
	}
	var st struct {
		Watchers []json.RawMessage `json:"watchers"`
	}
	if jerr := json.Unmarshal(out, &st); jerr != nil {
		// Not JSON: read rbd's plain listing instead.
		return strings.Contains(text, "watcher="), text, nil
	}
	return len(st.Watchers) > 0, text, nil
}

// imageID is the id rbd keeps ref under: what its trash entry is named by.
// An image with snapshots is refused, as `rbd rm` refuses it: a clone may
// hang off one, and the trash must not take its parent from under it.
func (d *cephDriver) imageID(ctx context.Context, ref string) (string, error) {
	out, err := d.rbd(ctx, d.rbdArgs("info", "--format", "json", "--", ref)...)
	if err != nil {
		return "", fmt.Errorf("rbd info %s: %w: %s", ref, err, strings.TrimSpace(string(out)))
	}
	var info struct {
		ID        string `json:"id"`
		Snapshots int    `json:"snapshot_count"`
	}
	if err := json.Unmarshal(out, &info); err != nil {
		return "", fmt.Errorf("rbd info %s: %w", ref, err)
	}
	if info.Snapshots > 0 {
		return "", fmt.Errorf("ceph image %s has %d snapshot(s); not removing it (remove them first)", ref, info.Snapshots)
	}
	return info.ID, nil
}

// removeImage removes ref: moved to its pool's trash once no client watches
// it (waiting up to busyBudget for the watchers to go), then purged in the
// background. An image a client still watches after that is refused as in
// use (*cephInUseError), and stays where it is. Errors keep rbd's exit status
// (rbdErrno), so a caller can tell an image that is gone (ENOENT).
func (d *cephDriver) removeImage(ctx context.Context, ref string, busyBudget time.Duration) error {
	pool, image, ok := cutLast(ref, "/")
	if !ok {
		return fmt.Errorf("ceph image %q names no pool", ref)
	}
	wait, spent := time.Second, time.Duration(0)
	for {
		watched, text, err := d.watchers(ctx, ref)
		if err != nil {
			return err
		}
		if !watched {
			id, err := d.imageID(ctx, ref)
			if err != nil {
				return err
			}
			if id == "" {
				// An image with no id (format 1) cannot go to the trash; rbd
				// rm it, with no short cap.
				return d.rmNoCap(ctx, ref)
			}
			mctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), trashMoveTimeout)
			out, err := d.rbd(mctx, d.rbdArgs("trash", "mv", "--", ref)...)
			cancel()
			if err == nil {
				d.queuePurge(pool, id, image)
				return nil
			}
			if rbdErrno(err) != rbdEBUSY {
				return fmt.Errorf("rbd trash mv %s: %w: %s", ref, err, strings.TrimSpace(string(out)))
			}
			// A client opened it in between: wait, as for a watcher.
			text = strings.TrimSpace(string(out))
		}
		if spent >= busyBudget {
			return &cephInUseError{ref: ref, status: text}
		}
		if !cephSleep(ctx, wait) {
			return fmt.Errorf("ceph image %s is still watched (%s): %w", ref, text, ctx.Err())
		}
		spent += wait
		wait = min(wait*2, 10*time.Second)
	}
}

// rmNoCap is `rbd rm` of an image that has no trash form, detached from the
// caller and with no short cap.
func (d *cephDriver) rmNoCap(ctx context.Context, ref string) error {
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), purgeCallTimeout)
	defer cancel()
	if out, err := d.rbd(cctx, d.rbdArgs("rm", "--", ref)...); err != nil {
		return fmt.Errorf("rbd rm %s: %w: %s", ref, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// claimTrashLeftovers queues the purge of what an interrupted `rbd rm` of
// pool/image left in the trash (source REMOVING); an entry of that name
// someone moved there by hand is named in the log and left alone.
func (d *cephDriver) claimTrashLeftovers(ctx context.Context, pool, image string) {
	entries, err := d.trashList(ctx, pool)
	if err != nil {
		slog.Warn("ceph: the trash could not be checked for a leftover of a deleted image", "image", pool+"/"+image, "error", err)
		return
	}
	queued := map[string]bool{}
	for _, p := range CephPendingPurges() {
		queued[p.TrashRef()] = true
	}
	for _, e := range entries {
		if e.Name != image || queued[pool+"/"+e.ID] {
			continue
		}
		if strings.EqualFold(e.Source, "REMOVING") {
			slog.Warn("ceph: an interrupted rbd rm left the image in the trash; purging it", "image", pool+"/"+image, "trash", pool+"/"+e.ID)
			d.queuePurge(pool, e.ID, image)
			continue
		}
		slog.Warn("ceph: the rbd trash holds an image of this name that litevirt did not put there; left for its owner",
			"image", pool+"/"+image, "trash", pool+"/"+e.ID, "source", e.Source, "by_hand", "rbd trash rm "+pool+"/"+e.ID)
	}
}

// cutLast splits s around the last sep.
func cutLast(s, sep string) (before, after string, found bool) {
	if i := strings.LastIndex(s, sep); i >= 0 {
		return s[:i], s[i+len(sep):], true
	}
	return s, "", false
}
