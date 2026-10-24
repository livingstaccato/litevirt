package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/safename"
	"github.com/litevirt/litevirt/internal/storage"
)

// The operator's release of the disks VM deletes kept on a host
// (`lv host kept-disks <host> --release <vm|path>`).
//
// A kept disk is named by this host's kept-disk note of its VM
// (health.KeptNotes) or by an entry of this host's kept-disks.json
// (disk_kept.go), or both, and every path that removes disk files here
// refuses it (keptHolds). Nothing else ever removes one, so without this an
// operator who no longer needs it deletes the files and the records by hand.
//
// A release works on whole chains (keptUnit): a kept file, the files of the
// same deleted VM its qcow2 chain backs on, and every other kept file of that
// VM that shares one of them. It removes the files every overlay before what
// it backs on, so no overlay is ever left over a removed file, then the note
// and record entries, then judges disk_leftover again. Before anything is
// removed it is refused while anything references a file it would remove
// (keptUnitHeld), and while a note, the record or a chain cannot be read.

// keptReleaseAudit is the audit action of a release.
const keptReleaseAudit = "host.kept_disks.release"

// keptUnitFile is a file of a kept chain.
type keptUnitFile struct {
	path     string
	size     int64
	under    bool   // a file of the unit backs on it
	gone     bool   // named, and not there
	named    bool   // a note or record of the VM names it
	dev, ino uint64 // the file the plan saw: a removal finding another refuses
}

// keptUnit is one releasable kept chain: the files of a deleted VM's kept
// disks that back on each other, with the note and record entries naming
// them.
type keptUnit struct {
	vm       string
	host     string // where its files are: this host, or (a record of another host's disk) that host
	files    []keptUnitFile
	standsOn []string // the files below it that are not the VM's own, left by a release
	missing  string   // a backing file its chain names that does not exist
	keptAt   time.Time
	reasons  []string
	note     string           // the note naming some of its files, "" when none
	notePath []string         // the files of the note this unit releases
	regs     []diskKeptRecord // the kept-disks.json entries this unit releases
	layers   [][]string       // every chain walked, top first, for the reference checks
	notFile  string           // why a file of it is no regular file a release may remove
	// dotdotNoted: files the note names as ones a kept disk backs on that
	// this unit's chains reach through a ".." reference, as a build before
	// the delete stopped noting them wrote it. Listed only; a release of
	// the unit forgets them with its top, so none is ever a top of its own.
	dotdotNoted []string
}

func (u *keptUnit) has(p string) bool {
	return slices.ContainsFunc(u.files, func(f keptUnitFile) bool { return f.path == p })
}

// keptChainOf is the walk of one kept file: its layers, the prefix of them
// that is the VM's own, and the missing backing file.
type keptChainOf struct {
	top     string
	layers  []string
	own     int // layers[:own] are the VM's own
	missing string
	dotdot  int // the first layer reached through "..", -1 when none
}

// keptOwnSet is what makes a layer below a kept top the deleted VM's own,
// resolved through symlinks: a file its note or record names, or one of the
// files a create of exactly that name clears (image.Store.VMDiskCandidates:
// <vm>-<disk>.qcow2 with no dash in the disk part, so never VM <vm>-1's, and
// the legacy <disks>/<vm>/ directory). Nothing else is: not a file named like
// the VM elsewhere, not an image, not another VM's disk a kept clone backs
// on. Those stay, as what the chain stands on. A path whose resolution does
// not answer is an error: what it is cannot be told.
//
// A path that is a symlink counts as itself only, never as its target: a
// create's sweep of a <vm>-<disk>.qcow2 link unlinks the link and never
// touches what it points at, so the target is no file of the VM's own (the
// link itself, as a layer, is held as no regular file). Only a regular file
// counts by its resolved form too, so a disk directory reached through a
// symlinked prefix still matches.
func (s *Server) keptOwnSet(vm string, named map[string]bool) (map[string]bool, error) {
	own := map[string]bool{}
	add := func(p string) error {
		p = filepath.Clean(p)
		own[p] = true
		fi, err := storage.Bounded("stat", p, func() (os.FileInfo, error) { return os.Lstat(p) })
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("%s cannot be read (%w)", p, err)
		}
		if !fi.Mode().IsRegular() {
			return nil
		}
		r, err := resolvedStrict(p)
		if err != nil {
			return fmt.Errorf("%s cannot be resolved (%w)", p, err)
		}
		own[r] = true
		return nil
	}
	for p := range named {
		if err := add(p); err != nil {
			return nil, err
		}
	}
	if s.images != nil {
		cands, err := s.images.VMDiskCandidates(vm)
		if err != nil {
			return nil, fmt.Errorf("the disk files of VM %s cannot be listed (%w)", vm, err)
		}
		for _, c := range cands {
			if err := add(c); err != nil {
				return nil, err
			}
		}
	}
	return own, nil
}

// keptSharedStoreOf tells whether a directory is on shared storage; a test
// replaces it.
var keptSharedStoreOf = sharedStoreOfErr

// keptReleaseBeforeRemove runs just before a release looks at a file it is
// about to remove; a test replaces it.
var keptReleaseBeforeRemove = func(string) {}

// keptReleaseBeforeSnapshotDrop runs once the files are gone, just before a
// release checks the snapshot records it drops again; a test replaces it.
var keptReleaseBeforeSnapshotDrop = func() {}

// keptReleaseBeforeSnapshotWrite runs after a record's check and before its
// guarded drop; a test replaces it.
var keptReleaseBeforeSnapshotWrite = func(string) {}

// keptUnits is every kept chain on this host, by VM, then by top. A note,
// kept-disks.json, or a chain that cannot be read is an error: what a release
// would remove, and what it would leave without its base, is then unknown.
func (s *Server) keptUnits(ctx context.Context) ([]*keptUnit, error) {
	notes, err := health.KeptNotes(s.dataDir)
	if err != nil {
		return nil, fmt.Errorf("this host's notes of the disks deletes kept cannot be read (%v); repair or remove that note "+
			"(once you have checked what it names), then retry", err)
	}
	records, unreadable := s.diskKeptRecords()
	if unreadable != "" {
		return nil, fmt.Errorf("this host's record of the disks deletes kept, %s, cannot be read (%s); repair or remove that file, then retry",
			filepath.Join(s.dataDir, diskKeptFile), unreadable)
	}
	type vmKept struct {
		note    *health.KeptNote
		regs    []diskKeptRecord
		foreign []diskKeptRecord
	}
	byVM := map[string]*vmKept{}
	get := func(vm string) *vmKept {
		if byVM[vm] == nil {
			byVM[vm] = &vmKept{}
		}
		return byVM[vm]
	}
	for i := range notes {
		get(notes[i].VM).note = &notes[i]
	}
	for _, r := range records {
		if r.Path == "" {
			continue
		}
		if r.Host != s.hostName {
			get(r.VM).foreign = append(get(r.VM).foreign, r)
			continue
		}
		if !filepath.IsAbs(filepath.Clean(s.hostDiskFile(r.Path))) {
			continue
		}
		get(r.VM).regs = append(get(r.VM).regs, r)
	}
	vms := make([]string, 0, len(byVM))
	for vm := range byVM {
		vms = append(vms, vm)
	}
	sort.Strings(vms)

	var out []*keptUnit
	for _, vm := range vms {
		k := byVM[vm]
		named := map[string]bool{}
		var cands []string
		add := func(p string) {
			if !named[p] {
				named[p] = true
				cands = append(cands, p)
			}
		}
		if k.note != nil {
			for _, p := range k.note.Paths {
				add(filepath.Clean(p))
			}
		}
		regOf := map[string][]diskKeptRecord{}
		for _, r := range k.regs {
			top := filepath.Clean(s.hostDiskFile(r.Path))
			add(top)
			regOf[top] = append(regOf[top], r)
		}
		ownSet, err := s.keptOwnSet(vm, named)
		if err != nil {
			return nil, fmt.Errorf("what the delete of VM %s kept cannot be told apart from what it stands on: %v; retry once that storage answers", vm, err)
		}
		walked := map[string]keptWalked{}
		for _, c := range cands {
			w, err := storage.Bounded("read the backing chain of", c, func() (keptWalked, error) {
				l, m, dd, err := keptChainWalk(c)
				return keptWalked{layers: l, missing: m, dotdot: dd}, err
			})
			if err != nil {
				return nil, fmt.Errorf("the backing chain of %s, a disk the delete of VM %s kept, cannot be read (%v), so what a release "+
					"would leave without its base is unknown; fix that file or its storage, then retry, or move %s away, or, once "+
					"nothing needs it, remove its entry from %s or %s", c, vm, err, c,
					filepath.Join(s.dataDir, "kept-disks", vm+".json"), filepath.Join(s.dataDir, diskKeptFile))
			}
			walked[c] = w
		}
		// Every file a chain reaches through a ".." reference, by its
		// cleaned and its resolved path: listed only, even when the note
		// names it (a build before this one noted such a base at delete).
		viaDotDot := map[string]bool{}
		for _, c := range cands {
			w := walked[c]
			if w.dotdot < 0 {
				continue
			}
			for _, l := range w.layers[min(w.dotdot, len(w.layers)):] {
				r, err := resolvedStrict(l)
				if err != nil {
					return nil, fmt.Errorf("%s, under a disk the delete of VM %s kept, cannot be resolved (%v); retry once that storage answers",
						l, vm, err)
				}
				viaDotDot[filepath.Clean(l)], viaDotDot[r] = true, true
			}
		}
		reachedViaDotDot := func(p string) (bool, error) {
			if len(viaDotDot) == 0 {
				return false, nil
			}
			if viaDotDot[filepath.Clean(p)] {
				return true, nil
			}
			r, err := resolvedStrict(p)
			return err == nil && viaDotDot[r], err
		}
		walks := map[string]keptChainOf{}
		for _, c := range cands {
			w := walked[c]
			own := 0
			for own < len(w.layers) {
				// A layer reached through a ".." reference is listed only:
				// where it is depends on symlinked directories, and a
				// release removes nothing it found that way.
				if own > 0 && w.dotdot >= 0 && own >= w.dotdot {
					break
				}
				if own > 0 {
					dd, err := reachedViaDotDot(w.layers[own])
					if err != nil {
						return nil, fmt.Errorf("%s, under a disk the delete of VM %s kept, cannot be resolved (%v); retry once that storage answers",
							w.layers[own], vm, err)
					}
					if dd {
						break
					}
				}
				if own > 0 {
					r, err := resolvedStrict(w.layers[own])
					if err != nil {
						return nil, fmt.Errorf("%s, under a disk the delete of VM %s kept, cannot be resolved (%v); retry once that storage answers",
							w.layers[own], vm, err)
					}
					if !ownSet[filepath.Clean(w.layers[own])] && !ownSet[r] {
						break
					}
				}
				own++
			}
			walks[c] = keptChainOf{top: c, layers: w.layers, own: own, missing: w.missing, dotdot: w.dotdot}
		}
		// The files the note names as ones a kept disk backs on, to match a
		// layer reached through "..".
		noteUnder := map[string]string{}
		if k.note != nil {
			for _, p := range k.note.Under {
				p = filepath.Clean(p)
				noteUnder[p] = p
				r, err := resolvedStrict(p)
				if err != nil {
					return nil, fmt.Errorf("%s, noted for the deleted VM %s, cannot be resolved (%v); retry once that storage answers", p, vm, err)
				}
				noteUnder[r] = p
			}
		}
		// A candidate another candidate's own layers reach is not a top.
		below := map[string]bool{}
		for _, w := range walks {
			for _, l := range w.layers[min(1, w.own):w.own] {
				below[l] = true
			}
		}
		// Units: the tops' own layers, merged where they share a file.
		var units []*keptUnit
		unitOf := map[string]*keptUnit{}
		for _, c := range cands {
			w := walks[c]
			if below[c] {
				continue
			}
			// A file a chain reaches through "..", even one the note names,
			// is never a top: it is listed under what that chain stands on.
			if dd, err := reachedViaDotDot(c); err != nil {
				return nil, fmt.Errorf("%s, a disk the delete of VM %s kept, cannot be resolved (%v); retry once that storage answers", c, vm, err)
			} else if dd {
				continue
			}
			files := []string{c}
			if len(w.layers) > 0 {
				files = w.layers[:w.own]
			}
			var u *keptUnit
			for _, f := range files {
				if v := unitOf[f]; v != nil && u == nil {
					u = v
				} else if v != nil && v != u {
					// Merge v into u.
					for _, g := range v.files {
						unitOf[g.path] = u
					}
					u.files = append(u.files, v.files...)
					u.layers = append(u.layers, v.layers...)
					units = slices.DeleteFunc(units, func(x *keptUnit) bool { return x == v })
				}
			}
			if u == nil {
				u = &keptUnit{vm: vm, host: s.hostName}
				units = append(units, u)
			}
			u.layers = append(u.layers, w.layers)
			for i, f := range files {
				if !u.has(f) {
					u.files = append(u.files, keptUnitFile{path: f, under: i > 0, gone: len(w.layers) == 0})
				} else if i > 0 {
					for j := range u.files {
						if u.files[j].path == f {
							u.files[j].under = true
						}
					}
				}
				unitOf[f] = u
			}
			for _, l := range w.layers[w.own:] {
				if !slices.Contains(u.standsOn, l) {
					u.standsOn = append(u.standsOn, l)
				}
			}
			if w.missing != "" && w.own == len(w.layers) {
				u.missing = w.missing
			}
			if w.dotdot >= 0 && len(noteUnder) > 0 {
				for _, l := range w.layers[min(w.dotdot, len(w.layers)):] {
					p, ok := noteUnder[filepath.Clean(l)]
					if !ok {
						r, err := resolvedStrict(l)
						if err != nil {
							return nil, fmt.Errorf("%s, under a disk the delete of VM %s kept, cannot be resolved (%v); retry once that storage answers",
								l, vm, err)
						}
						p, ok = noteUnder[r]
					}
					if ok && !slices.Contains(u.dotdotNoted, p) {
						u.dotdotNoted = append(u.dotdotNoted, p)
					}
				}
			}
		}
		for _, u := range units {
			u.files = orderOverlaysFirst(u.files, u.layers)
			for i := range u.files {
				f := &u.files[i]
				f.named = named[f.path]
				if f.gone {
					continue
				}
				fi, err := storage.Bounded("stat", f.path, func() (os.FileInfo, error) { return os.Lstat(f.path) })
				if errors.Is(err, fs.ErrNotExist) {
					f.gone = true
					continue
				}
				if err != nil {
					return nil, fmt.Errorf("%s, a disk the delete of VM %s kept, cannot be read (%v); retry once its storage answers", f.path, vm, err)
				}
				if !fi.Mode().IsRegular() || strings.HasPrefix(f.path, "/dev/") {
					u.notFile = fmt.Sprintf("%s is no regular file (%v): a volume of a storage driver, or a link to one, which a release "+
						"does not remove, since unlinking it would leave the volume and its data unnamed; remove it with its storage "+
						"driver, then its entry from %s", f.path, fi.Mode().Type(), filepath.Join(s.dataDir, diskKeptFile))
					continue
				}
				f.size = fi.Size()
				f.dev, _ = fileDevice(fi)
				f.ino, _ = fileInode(fi)
			}
			if k.note != nil {
				for _, p := range k.note.Paths {
					if u.has(filepath.Clean(p)) {
						u.note = k.note.File
						u.notePath = append(u.notePath, filepath.Clean(p))
						u.keptAt = k.note.ModTime
					}
				}
			}
			for _, f := range u.files {
				for _, r := range regOf[f.path] {
					u.regs = append(u.regs, r)
					if at, err := time.Parse(time.RFC3339, r.Since); err == nil && (u.keptAt.IsZero() || at.Before(u.keptAt)) {
						u.keptAt = at
					}
					if r.Reason != "" && !slices.Contains(u.reasons, r.Reason) {
						u.reasons = append(u.reasons, r.Reason)
					}
				}
			}
			if u.note != "" && len(u.regs) == 0 {
				u.reasons = append(u.reasons, "kept by its delete (lv rm --keep-disks, a disk recorded delete_with_vm=false, or a delete that could not prove it unused)")
			}
		}
		out = append(out, units...)
		// Another host's disk this host's record names: listed only.
		for _, r := range k.foreign {
			u := &keptUnit{vm: vm, host: r.Host, files: []keptUnitFile{{path: r.Path}}, regs: []diskKeptRecord{r}}
			if at, err := time.Parse(time.RFC3339, r.Since); err == nil {
				u.keptAt = at
			}
			if r.Reason != "" {
				u.reasons = []string{r.Reason}
			}
			out = append(out, u)
		}
	}
	return out, nil
}

// orderOverlaysFirst orders files so that no file comes after a file it
// backs on: removing them in this order never leaves an overlay over a
// removed file.
func orderOverlaysFirst(files []keptUnitFile, chains [][]string) []keptUnitFile {
	in := map[string]bool{}
	for _, f := range files {
		in[f.path] = true
	}
	// backedOnBy[b] counts the files of the unit that back on b.
	backedOnBy := map[string]int{}
	backs := map[string]string{}
	for _, c := range chains {
		for i := 0; i+1 < len(c); i++ {
			if in[c[i]] && in[c[i+1]] && backs[c[i]] == "" {
				backs[c[i]] = c[i+1]
				backedOnBy[c[i+1]]++
			}
		}
	}
	var out []keptUnitFile
	left := slices.Clone(files)
	for len(left) > 0 {
		next := -1
		for i, f := range left {
			if backedOnBy[f.path] == 0 {
				next = i
				break
			}
		}
		if next < 0 { // a cycle cannot be walked; kept as found
			return append(out, left...)
		}
		f := left[next]
		out = append(out, f)
		left = slices.Delete(left, next, next+1)
		if b := backs[f.path]; b != "" {
			backedOnBy[b]--
		}
	}
	return out
}

// keptResolver resolves paths through symlinks for one check, bounded
// (resolvedStrict) and remembered: a path whose resolution does not answer
// is an error, never the path as given.
type keptResolver map[string]string

func (r keptResolver) of(p string) (string, error) {
	p = filepath.Clean(p)
	if v, ok := r[p]; ok {
		return v, nil
	}
	v, err := resolvedStrict(p)
	if err != nil {
		return "", err
	}
	r[p] = v
	return v, nil
}

// keptUnitHeld is why u may not be released now: something other than u
// references a file it would remove. "" when nothing does. A check that
// cannot be made refuses too (it is the answer: what it would have found is
// unknown). snaps is the deleted VM's snapshot records on this host that a
// release of the VM drops with its files (keptSnapshotsDroppable).
func (s *Server) keptUnitHeld(ctx context.Context, u *keptUnit, all []*keptUnit) (held string, snaps []string) {
	if u.host != s.hostName {
		return fmt.Sprintf("the file is on %s, not on %s, where this record was written; check it there, then remove its entry from %s on %s",
			u.host, s.hostName, filepath.Join(s.dataDir, diskKeptFile), s.hostName), nil
	}
	if u.notFile != "" {
		return u.notFile, nil
	}
	var files []string
	for _, f := range u.files {
		if !f.gone {
			files = append(files, f.path)
		}
	}
	recs, held := s.keptSnapshotsDroppable(ctx, u, all)
	for _, r := range recs {
		snaps = append(snaps, r.Name)
	}
	if held != "" || len(files) == 0 {
		return held, snaps
	}
	// Shared storage: what other hosts hold on the file (a domain, a copy, a
	// replica, a note) cannot be checked from here, nor a create there locked
	// out between this check and the removal. Listed only.
	for _, f := range files {
		st, err := keptSharedStoreOf(filepath.Dir(f))
		if err != nil {
			return fmt.Sprintf("cannot tell whether %s is on shared storage (%v); retry", f, err), snaps
		}
		if st.Shared {
			return fmt.Sprintf("%s is on shared storage: what other hosts hold on it cannot be checked, nor a create there locked out, "+
				"from %s, so a release does not remove it; check on every host that nothing uses it, then remove the file and its "+
				"entries (%s, %s) by hand", f, s.hostName, filepath.Join(s.dataDir, "kept-disks", u.vm+".json"),
				filepath.Join(s.dataDir, diskKeptFile)), snaps
		}
	}
	res := keptResolver{}
	mine := map[string]bool{}
	for _, f := range files {
		r, err := res.of(f)
		if err != nil {
			return fmt.Sprintf("cannot tell what %s is (%v); retry once its storage answers", f, err), snaps
		}
		mine[filepath.Clean(f)], mine[r] = true, true
	}
	isMine := func(p string) (bool, error) {
		if mine[filepath.Clean(p)] {
			return true, nil
		}
		r, err := res.of(p)
		return err == nil && mine[r], err
	}

	// Another deleted VM's note, or another kept chain, holds or backs on it.
	noted, err := health.KeptNotedFiles(s.dataDir)
	if err != nil {
		return fmt.Sprintf("cannot tell: this host's notes of the disks deletes kept cannot be read (%v)", err), snaps
	}
	for p, vm := range noted {
		if vm == u.vm {
			continue
		}
		hit, err := isMine(p)
		if err != nil {
			return fmt.Sprintf("cannot tell what %s, kept for the deleted VM %s, is (%v); retry", p, vm, err), snaps
		}
		if hit {
			return fmt.Sprintf("%s is also kept for the deleted VM %s (%s)", p, vm, filepath.Join(s.dataDir, "kept-disks", vm+".json")), snaps
		}
	}
	for _, o := range all {
		if o == u || o.host != s.hostName {
			continue
		}
		for _, c := range o.layers {
			for _, l := range c {
				hit, err := isMine(l)
				if err != nil {
					return fmt.Sprintf("cannot tell what %s, under a disk the delete of VM %s kept, is (%v); retry", l, o.vm, err), snaps
				}
				if hit {
					return fmt.Sprintf("%s backs on %s: it is a disk the delete of VM %s kept; release that first", c[0], l, o.vm), snaps
				}
			}
		}
	}

	// A live disk row of this host (the file is not on shared storage).
	for _, f := range files {
		for _, p := range uniq(f, s.recordPath(f)) {
			rows, err := s.liveDiskOwners(ctx, s.hostName, p)
			if err != nil {
				return fmt.Sprintf("cannot tell whether a VM's disk uses %s (%v); retry", f, err), snaps
			}
			if len(rows) > 0 {
				d := rows[0]
				return fmt.Sprintf("%s is in use by VM %s disk %s (as %s)", f, d.VMName, d.DiskName, referenceKind(&d, p)), snaps
			}
		}
	}

	// Another VM's disk whose backing chain reaches it.
	users, err := s.snapshotFileUsers(ctx, "", files)
	if err != nil {
		return fmt.Sprintf("cannot tell whether another VM's disk backs on it (%v); retry", err), snaps
	}
	if len(users) > 0 {
		return fmt.Sprintf("the disk of VM %s backs on a file of it", strings.Join(users, ", ")), snaps
	}

	// Any snapshot record whose memory image is one of them.
	for _, f := range files {
		for _, p := range uniq(f, s.recordPath(f)) {
			rows, err := s.db.Query(ctx, `SELECT vm_name, name FROM snapshots WHERE vmstate_path = ? AND deleted_at IS NULL`, p)
			if err != nil {
				return fmt.Sprintf("cannot tell whether a snapshot record names %s (%v); retry", f, err), snaps
			}
			for _, r := range rows {
				if r.String("vm_name") != u.vm || !slices.Contains(snaps, r.String("name")) {
					return fmt.Sprintf("%s is the memory image of snapshot %s of VM %s", f, r.String("name"), r.String("vm_name")), snaps
				}
			}
		}
	}

	// A replica, or a set-aside copy layered on it.
	for _, f := range files {
		if r, ok := replicaRecordFor(f); ok {
			return fmt.Sprintf("%s is a recorded replica of VM %s disk %s", f, r.VM, r.Disk), snaps
		}
	}
	backing, err := s.supersededBacking(ctx)
	if err != nil {
		return fmt.Sprintf("cannot tell whether a superseded disk copy backs on it (%v); retry", err), snaps
	}
	for _, f := range files {
		if backing.has(f) {
			return fmt.Sprintf("a superseded disk copy backs on %s (lv host superseded-disks %s)", f, s.hostName), snaps
		}
	}
	keptCopies, err := health.ListKeptDisks(ctx, s.db, s.dataDir)
	if err != nil {
		return fmt.Sprintf("cannot tell whether a .kept- copy backs on it (%v); retry", err), snaps
	}
	for _, k := range keptCopies {
		if k.Seed {
			continue
		}
		var nerr error
		reached, err := chainReaches(k.Path, "", func(p string) bool {
			hit, herr := isMine(p)
			if herr != nil && nerr == nil {
				nerr = herr
			}
			return hit || herr != nil
		})
		if err == nil {
			err = nerr
		}
		if err != nil {
			return fmt.Sprintf("cannot tell whether %s backs on it (%v); retry", k.Path, err), snaps
		}
		if reached {
			return fmt.Sprintf("%s, a disk a deleted VM was kept with that a create moved aside, backs on it", k.Path), snaps
		}
	}

	// A domain on this host: one of the deleted VM's name, or one whose disk
	// is, or backs on, a file of it.
	if s.virt != nil {
		doms, err := s.virt.ListDomains()
		if err != nil {
			return fmt.Sprintf("cannot tell whether a domain on %s uses it: libvirt does not answer (%v); retry", s.hostName, err), snaps
		}
		for _, d := range doms {
			if d == u.vm {
				what := "defined"
				if active, err := s.virt.DomainIsActive(d); err != nil || active {
					what = "running"
				}
				return fmt.Sprintf("a domain %s is %s on %s; a domain of the deleted VM's name may use these files", d, what, s.hostName), snaps
			}
			srcs, err := s.virt.DomainDiskFormats(d)
			if err != nil {
				if lv.IsNoDomain(err) {
					continue
				}
				return fmt.Sprintf("cannot tell whether the domain %s uses it (%v); retry", d, err), snaps
			}
			for src, format := range srcs {
				var nerr error
				hit := func(p string) bool {
					h, herr := isMine(s.hostDiskFile(p))
					if !h && herr == nil {
						h, herr = isMine(p)
					}
					if herr != nil && nerr == nil {
						nerr = herr
					}
					return h || herr != nil
				}
				reached := hit(src)
				if !reached {
					var rerr error
					reached, rerr = chainReaches(s.hostDiskFile(src), format, hit)
					if rerr != nil {
						return fmt.Sprintf("cannot tell whether the domain %s uses it (%v); retry", d, rerr), snaps
					}
				}
				if nerr != nil {
					return fmt.Sprintf("cannot tell whether the domain %s uses it (%v); retry", d, nerr), snaps
				}
				if reached {
					return fmt.Sprintf("the domain %s on %s uses it (its disk %s)", d, s.hostName, src), snaps
				}
			}
		}
	}
	return "", snaps
}

// keptSnapshotsDroppable is the deleted VM's snapshot records on this host,
// which a release of the VM drops with its files, or why they hold it.
// They are taken over the kept files (a disk snapshot's overlays are layers
// of the chain; an internal one lives in the qcow2 removed), and once the VM
// is gone `lv snapshot rm` cannot reach them, so without this nothing could
// release the chain. They are dropped only when:
//
//   - no VM of the name exists on any host (one that does may own them);
//   - each memory image is unrecorded, gone, or a file of the deleted VM's
//     chains on this host, which the release removes too;
//   - the release takes every chain of the VM (a release of one chain leaves
//     files the records are taken over);
//   - the caller confirmed them (expect_snapshots), as the dry run lists them.
func (s *Server) keptSnapshotsDroppable(ctx context.Context, u *keptUnit, all []*keptUnit) ([]corrosion.SnapshotRecord, string) {
	recs, err := corrosion.ListSnapshots(ctx, s.db, u.vm)
	if err != nil {
		return nil, fmt.Sprintf("cannot tell whether a snapshot record names it (%v); retry", err)
	}
	var mine []corrosion.SnapshotRecord
	for _, sn := range recs {
		if sn.HostName == "" || sn.HostName == s.hostName {
			mine = append(mine, sn)
		}
	}
	if len(mine) == 0 {
		return nil, ""
	}
	names := make([]string, 0, len(mine))
	for _, sn := range mine {
		names = append(names, sn.Name)
	}
	list := strings.Join(names, ", ")
	vm, err := corrosion.GetVM(ctx, s.db, u.vm)
	if err != nil {
		return nil, fmt.Sprintf("the snapshot records %s of VM %s on %s are taken over these files, and whether a VM of that name exists cannot be read (%v); retry",
			list, u.vm, s.hostName, err)
	}
	if vm != nil {
		return nil, fmt.Sprintf("the snapshot records %s of VM %s on %s are taken over these files, and a VM %s exists (on %s), whose records they may be; "+
			"remove them with `lv snapshot rm %s <snapshot>` if they are not its own", list, u.vm, s.hostName, u.vm, vm.HostName, u.vm)
	}
	released := map[string]bool{}
	for _, o := range all {
		if o.vm != u.vm || o.host != s.hostName {
			continue
		}
		for _, f := range o.files {
			released[f.path] = true
			released[s.recordPath(f.path)] = true
		}
	}
	for _, sn := range mine {
		p := sn.VMStatePath
		if p == "" || released[filepath.Clean(p)] {
			continue
		}
		_, err := storage.Bounded("stat", p, func() (os.FileInfo, error) { return os.Lstat(s.hostDiskFile(p)) })
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Sprintf("the snapshot record %s of the deleted VM %s keeps its memory image %s, which cannot be read (%v); retry",
				sn.Name, u.vm, p, err)
		}
		return nil, fmt.Sprintf("the snapshot records %s of VM %s on %s are taken over these files, and the memory image %s of %s is no file a release "+
			"removes; remove that image by hand once nothing needs it, then release again", list, u.vm, s.hostName, p, sn.Name)
	}
	return mine, ""
}

func uniq(a, b string) []string {
	if a == b {
		return []string{a}
	}
	return []string{a, b}
}

// keptUnitsFor is the units release names: every unit of the deleted VM of
// that name, or the one unit with a file at that path. None is NotFound.
func (s *Server) keptUnitsFor(units []*keptUnit, release string) ([]*keptUnit, error) {
	var out []*keptUnit
	if filepath.IsAbs(release) {
		p := filepath.Clean(release)
		for _, u := range units {
			for _, f := range u.files {
				if f.path == p || s.recordPath(f.path) == p || filepath.Clean(s.hostDiskFile(p)) == f.path {
					out = append(out, u)
					break
				}
			}
		}
		if len(out) == 0 {
			return nil, status.Errorf(codes.NotFound, "%s is not a file of a disk chain a delete kept on %s (lv host kept-disks %s lists them)",
				release, s.hostName, s.hostName)
		}
		return out[:1], nil
	}
	if err := safename.ValidateVMName(release); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "release: %q is neither a VM name nor an absolute path (%v)", release, err)
	}
	for _, u := range units {
		if u.vm == release {
			out = append(out, u)
		}
	}
	if len(out) == 0 {
		return nil, status.Errorf(codes.NotFound, "no disk a delete of VM %s kept is recorded on %s (lv host kept-disks %s lists them)",
			release, s.hostName, s.hostName)
	}
	return out, nil
}

func (u *keptUnit) toPB(s *Server, held string, snaps []string, released bool) *pb.KeptDiskChain {
	c := &pb.KeptDiskChain{VmName: u.vm, StandsOn: u.standsOn, MissingBase: u.missing, Held: held, Released: released,
		Reason: strings.Join(u.reasons, "; "), Snapshots: snaps}
	if !u.keptAt.IsZero() {
		c.KeptAt = u.keptAt.UTC().Format(time.RFC3339)
	}
	if u.host != s.hostName {
		c.Host = u.host
	}
	for _, f := range u.files {
		c.Files = append(c.Files, &pb.KeptDiskFile{Path: f.path, SizeBytes: f.size, Under: f.under, Gone: f.gone})
	}
	if u.note != "" {
		c.Records = append(c.Records, u.note)
	}
	if len(u.regs) > 0 {
		c.Records = append(c.Records, filepath.Join(s.dataDir, diskKeptFile))
	}
	return c
}

// KeptDisks is `lv host kept-disks <host>`: the disk chains VM deletes kept
// on a host, each with why it may not be released now; with release, the
// removal of the named ones (admin). The files are that host's, so the
// request is answered there.
func (s *Server) KeptDisks(ctx context.Context, req *pb.KeptDisksRequest) (*pb.KeptDisksResponse, error) {
	role := "viewer"
	if req.Release != "" && !req.DryRun {
		role = "admin" // it deletes disk data
	}
	if err := RequireRole(ctx, role); err != nil {
		return nil, err
	}
	actor := s.repairActor(ctx)
	if req.Host != "" && req.Host != s.hostName {
		client, conn, err := s.peerClient(ctx, req.Host)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "cannot reach host %s: %v", req.Host, err)
		}
		defer conn.Close()
		resp, err := client.KeptDisks(metadata.AppendToOutgoingContext(ctx, repairActorMDKey, actor), req)
		if status.Code(err) == codes.Unimplemented {
			return nil, status.Errorf(codes.Unimplemented, "host %s runs a build without lv host kept-disks; nothing was removed there", req.Host)
		}
		return resp, err
	}
	if req.Release == "" {
		if req.DryRun || len(req.ExpectPaths) > 0 || len(req.ExpectSnapshots) > 0 {
			return nil, status.Error(codes.InvalidArgument, "dry_run, expect_paths and expect_snapshots go with release")
		}
		units, err := s.keptUnits(ctx)
		if err != nil {
			return nil, status.Errorf(codes.FailedPrecondition, "list the disks deletes kept on %s: %v", s.hostName, err)
		}
		resp := &pb.KeptDisksResponse{Host: s.hostName}
		for _, u := range units {
			held, snaps := s.keptUnitHeld(ctx, u, units)
			resp.Chains = append(resp.Chains, u.toPB(s, held, snaps, false))
		}
		return resp, nil
	}
	return s.releaseKept(ctx, req, actor)
}

// sameStrings reports whether a and b hold the same strings, cleaned as
// paths when paths is set, in any order.
func sameStrings(a, b []string, paths bool) bool {
	norm := func(l []string) []string {
		out := slices.Clone(l)
		for i := range out {
			if paths {
				out[i] = filepath.Clean(out[i])
			}
		}
		slices.Sort(out)
		return slices.Compact(out)
	}
	return slices.Equal(norm(a), norm(b))
}

// releaseKept is the release half of KeptDisks, on the host the files are
// on. A release (not a dry run) runs under the deleted VM's lock: a create
// or delete of the name, which reads and writes the same notes and records,
// waits.
func (s *Server) releaseKept(ctx context.Context, req *pb.KeptDisksRequest, actor string) (*pb.KeptDisksResponse, error) {
	audit := func(err error) error {
		if !req.DryRun {
			s.auditAs(ctx, actor, keptReleaseAudit, s.hostName, fmt.Sprintf("release %s on %s: %s; nothing was removed",
				req.Release, s.hostName, status.Convert(err).Message()), "error")
		}
		return err
	}
	refuse := func(code codes.Code, format string, a ...any) error {
		return audit(status.Errorf(code, "release %s on %s: "+format, append([]any{req.Release, s.hostName}, a...)...))
	}
	if !req.DryRun {
		if len(req.ExpectPaths) == 0 {
			return nil, refuse(codes.InvalidArgument, "expect_paths is required: name the files you confirmed (a dry run lists them)")
		}
		// What references a file is read from the replica: one that has not
		// caught up may not hold the disk row that does.
		if err := s.requireReplicaCaughtUp(ctx, "KeptDisks release"); err != nil {
			return nil, err
		}
	}
	units, err := s.keptUnits(ctx)
	if err != nil {
		return nil, refuse(codes.FailedPrecondition, "%v; nothing was removed", err)
	}
	targets, err := s.keptUnitsFor(units, req.Release)
	if err != nil {
		return nil, audit(err)
	}
	vm := targets[0].vm
	if !req.DryRun {
		defer s.lockVMAs(vm, "kept-disk release")()
		// Read again under the lock: a create or delete of the name may have
		// changed the notes and records meanwhile.
		if units, err = s.keptUnits(ctx); err != nil {
			return nil, refuse(codes.FailedPrecondition, "%v; nothing was removed", err)
		}
		if targets, err = s.keptUnitsFor(units, req.Release); err != nil {
			return nil, audit(err)
		}
		if targets[0].vm != vm {
			return nil, refuse(codes.Aborted, "it now names the disks of VM %s, not of VM %s; run it again to see what it removes", targets[0].vm, vm)
		}
	}
	resp := &pb.KeptDisksResponse{Host: s.hostName, DryRun: req.DryRun}
	var helds, paths, snaps []string
	whole := true
	for _, o := range units {
		if o.vm == vm && o.host == s.hostName && !slices.Contains(targets, o) {
			whole = false
		}
	}
	for _, u := range targets {
		held, us := s.keptUnitHeld(ctx, u, units)
		if held == "" && len(us) > 0 && !whole {
			held = fmt.Sprintf("the snapshot records %s of the deleted VM %s are taken over all its kept chains; release them together "+
				"(--release %s)", strings.Join(us, ", "), vm, vm)
		}
		resp.Chains = append(resp.Chains, u.toPB(s, held, us, held == "" && req.DryRun))
		if held != "" {
			helds = append(helds, held)
		}
		for _, n := range us {
			if !slices.Contains(snaps, n) {
				snaps = append(snaps, n)
			}
		}
		for _, f := range u.files {
			paths = append(paths, f.path)
		}
	}
	if req.DryRun {
		return resp, nil
	}
	if len(helds) > 0 {
		return nil, refuse(codes.FailedPrecondition, "%s; nothing was removed", strings.Join(helds, "; "))
	}
	if !sameStrings(req.ExpectPaths, paths, true) {
		return nil, refuse(codes.Aborted, "it would now remove %s, not the files confirmed (%s); run it again to see what it removes",
			strings.Join(paths, ", "), strings.Join(req.ExpectPaths, ", "))
	}
	if !sameStrings(req.ExpectSnapshots, snaps, false) {
		return nil, refuse(codes.Aborted, "it would now drop the snapshot records [%s] of VM %s, not the ones confirmed [%s]; run it again to see what it drops",
			strings.Join(snaps, ", "), vm, strings.Join(req.ExpectSnapshots, ", "))
	}
	// The records themselves, as this plan sees them: each is dropped only
	// while it is still that record (keptSnapshotStill).
	var planSnaps []corrosion.SnapshotRecord
	if len(snaps) > 0 {
		recs, h := s.keptSnapshotsDroppable(ctx, targets[0], units)
		var names []string
		for _, r := range recs {
			names = append(names, r.Name)
		}
		if h != "" || !sameStrings(names, snaps, false) {
			return nil, refuse(codes.Aborted, "the snapshot records of VM %s changed while the release was planned; run it again to see what it drops", vm)
		}
		planSnaps = recs
	}
	// Every file a release removes is named in the note first, so a failure
	// part way leaves the rest named (a base the VM owned only by its name,
	// under an overlay now gone, would otherwise be named nowhere).
	for _, u := range targets {
		var unnamed []string
		for _, f := range u.files {
			if !f.named && !f.gone {
				unnamed = append(unnamed, f.path)
			}
		}
		if len(unnamed) > 0 {
			if err := health.NoteKeptBackingFiles(s.dataDir, u.vm, unnamed); err != nil {
				return nil, refuse(codes.FailedPrecondition, "the files it removes could not be noted first (%v); nothing was removed", err)
			}
			u.note = filepath.Join(s.dataDir, "kept-disks", u.vm+".json")
			u.notePath = append(u.notePath, unnamed...)
		}
	}

	var removed []string
	var bytes int64
	var failed error
	var released []*keptUnit
	resp.Chains = nil
	for _, u := range targets {
		var gone []string
		for _, f := range u.files {
			if failed != nil {
				break
			}
			if !f.gone {
				// The file the plan saw, still: a create elsewhere in the
				// path's life (a set-aside, a new disk written there) is
				// never removed in its place.
				keptReleaseBeforeRemove(f.path)
				fi, err := storage.Bounded("stat", f.path, func() (os.FileInfo, error) { return os.Lstat(f.path) })
				switch {
				case errors.Is(err, fs.ErrNotExist):
				case err != nil:
					failed = fmt.Errorf("stat %s: %w", f.path, err)
				default:
					dev, _ := fileDevice(fi)
					ino, _ := fileInode(fi)
					if !fi.Mode().IsRegular() || dev != f.dev || ino != f.ino {
						failed = fmt.Errorf("%s is no longer the file the release checked (device %d inode %d, now %d %d); it was left", f.path, f.dev, f.ino, dev, ino)
						break
					}
					_, rerr := storage.Bounded("remove", f.path, func() (struct{}, error) { return struct{}{}, os.Remove(f.path) })
					switch {
					case errors.Is(rerr, fs.ErrNotExist):
					case rerr != nil:
						failed = fmt.Errorf("remove %s: %w", f.path, rerr)
					default:
						removed = append(removed, fmt.Sprintf("%s (%d bytes)", f.path, f.size))
						bytes += f.size
					}
				}
				if failed != nil {
					break
				}
			}
			gone = append(gone, f.path)
		}
		// The records of what is gone go with it; a file a failure left
		// stays named, with the files under it.
		var nerr error
		forget := slices.DeleteFunc(slices.Clone(u.notePath), func(p string) bool { return !slices.Contains(gone, p) })
		if failed == nil {
			// Every file of the unit is gone: its entries for files it
			// reached through ".." are judged once the whole release is
			// done (below).
			released = append(released, u)
		}
		if len(forget) > 0 {
			nerr = health.ForgetKeptNoted(s.dataDir, u.vm, forget)
		}
		rerr := s.forgetKeptRecords(u.regs, gone)
		var left *keptRecordedNoteLeftError
		switch {
		case nerr == nil && errors.As(rerr, &left) && failed == nil:
			// The release itself is done: only the note's list of what
			// kept-disks.json recorded is left naming a file that is gone,
			// and nothing drops it later (judgeKeptDisks never sees the
			// entry again). Reported as what it is.
			failed = fmt.Errorf("the files are removed and their kept-disks.json entries dropped; %w", left)
		case nerr == nil:
			nerr = rerr
		}
		if nerr != nil && failed == nil {
			failed = fmt.Errorf("the files are removed, and their records could not be updated (%w); a file that is gone is forgotten on its own", nerr)
		}
		resp.Chains = append(resp.Chains, u.toPB(s, "", nil, failed == nil))
		if failed != nil {
			break
		}
	}
	// An entry an earlier build noted for a file a released chain reached
	// through ".." goes once nothing kept reaches that file any more: it
	// would otherwise read as a kept disk of its own (and hold a create of
	// the name) with nothing kept over it. While another kept chain reaches
	// it (any note's, kept-disks.json's), the entry stays and keeps holding
	// it. The file stays either way.
	for _, u := range released {
		var forget []string
		for _, p := range u.dotdotNoted {
			if s.keptStillReached(ctx, p) {
				continue
			}
			forget = append(forget, p)
		}
		if len(forget) == 0 {
			continue
		}
		if err := health.ForgetKeptNoted(s.dataDir, u.vm, forget); err != nil {
			slog.Warn("kept-disk release: could not forget a note entry for a file a released chain reached through \"..\"; it stays listed only",
				"vm", u.vm, "files", forget, "error", err)
		}
	}
	// The snapshot records go once every file they are taken over is gone,
	// and only while no VM of the name exists and each is still the record
	// the plan saw: a same-name VM on another host does not wait on this
	// host's lock, and may have taken a snapshot of the same name meanwhile.
	// The checks below explain a refusal; the drop itself re-reads both
	// inside its own transaction (corrosion.DeleteSnapshotIfStill), so a
	// record this node applies in between is never tombstoned in its place.
	// Known limit: a re-create on another host that has not replicated here
	// yet is not seen by any local check, and the drop, applied by (VM, name)
	// on every peer, wins over it: at most one record per planned name, and
	// never a file.
	var dropped []string
	if failed == nil && len(planSnaps) > 0 {
		keptReleaseBeforeSnapshotDrop()
		cur, err := corrosion.GetVM(ctx, s.db, vm)
		switch {
		case err != nil:
			failed = fmt.Errorf("the files are removed; whether a VM %s exists cannot be read now (%w), so its snapshot records %s were kept",
				vm, err, strings.Join(snaps, ", "))
		case cur != nil:
			failed = fmt.Errorf("the files are removed; a VM %s now exists (on %s), so the snapshot records %s were kept: they may be its own",
				vm, cur.HostName, strings.Join(snaps, ", "))
		}
		for _, r := range planSnaps {
			if failed != nil {
				break
			}
			if why := s.keptSnapshotStill(ctx, r); why != "" {
				failed = fmt.Errorf("the files are removed; %s, so it and the records after it were kept", why)
				break
			}
			keptReleaseBeforeSnapshotWrite(r.Name)
			applied, err := corrosion.DeleteSnapshotIfStill(ctx, s.db, r)
			if err != nil {
				failed = fmt.Errorf("the files are removed, and the snapshot record %s could not be dropped (%w)", r.Name, err)
				break
			}
			if !applied {
				why := s.keptSnapshotStill(ctx, r)
				if why == "" {
					why = fmt.Sprintf("a VM %s now exists", vm)
				}
				failed = fmt.Errorf("the files are removed; %s, so it and the records after it were kept", why)
				break
			}
			dropped = append(dropped, r.Name)
		}
		if len(resp.Chains) > 0 {
			resp.Chains[0].Snapshots = dropped
		}
	}
	detail := fmt.Sprintf("released the disks the delete of VM %s kept on %s (%s): removed %d file(s), %d bytes: %s",
		vm, s.hostName, req.Release, len(removed), bytes, strings.Join(removed, ", "))
	if len(dropped) > 0 {
		detail += fmt.Sprintf("; dropped the snapshot records %s of the deleted VM %s on %s", strings.Join(dropped, ", "), vm, s.hostName)
	}
	slog.Warn("kept disks released by an operator", "vm", vm, "release", req.Release, "removed", removed, "bytes", bytes,
		"snapshots", dropped, "actor", actor, "error", failed)
	s.judgeKeptDisks(ctx)
	if failed != nil {
		s.auditAs(ctx, actor, keptReleaseAudit, s.hostName, detail+"; then failed: "+failed.Error(), "error")
		s.recordVMEvent(ctx, vm, "vm.disk.released", "error", detail+"; then failed: "+failed.Error())
		return nil, status.Errorf(codes.Internal, "%s; then failed: %v", detail, failed)
	}
	s.auditAs(ctx, actor, keptReleaseAudit, s.hostName, detail, "ok")
	s.recordVMEvent(ctx, vm, "vm.disk.released", "ok", detail)
	return resp, nil
}

// keptSnapshotStill is why the live snapshot record of r's VM and name is no
// longer r: gone, or another record. "" when it is r. A record re-created
// under a dropped name takes the dropped row's id back
// (corrosion.InsertSnapshot), so the id alone does not tell them apart: the
// host does. (Its created_at is no help: InsertSnapshot stamps it to the
// second, and a re-create on the same host needs a VM of the name, which
// refuses the drop anyway.) corrosion.DeleteSnapshotIfStill makes the same
// comparison inside the drop's transaction; this one names what changed.
func (s *Server) keptSnapshotStill(ctx context.Context, r corrosion.SnapshotRecord) string {
	cur, err := corrosion.GetSnapshot(ctx, s.db, r.VMName, r.Name)
	switch {
	case err != nil:
		return fmt.Sprintf("the snapshot record %s of VM %s cannot be read again (%v)", r.Name, r.VMName, err)
	case cur == nil:
		return fmt.Sprintf("the snapshot record %s of VM %s is gone", r.Name, r.VMName)
	case cur.ID != r.ID || cur.HostName != r.HostName:
		return fmt.Sprintf("the snapshot record %s of VM %s is no longer the one the release checked (id %s on %s; now id %s on %s)",
			r.Name, r.VMName, r.ID, r.HostName, cur.ID, cur.HostName)
	}
	return ""
}

// forgetKeptRecords drops from kept-disks.json each of regs whose file is in
// gone, and its file from the note's recorded list (health.ForgetKeptRecorded),
// as judgeKeptDisks does for a file that is gone: a note left naming it would
// outlive the entry. An entry rewritten meanwhile (a VM of the name kept the
// path again) is left.
func (s *Server) forgetKeptRecords(regs []diskKeptRecord, gone []string) error {
	if len(regs) == 0 {
		return nil
	}
	s.diskKept.mu.Lock()
	defer s.diskKept.mu.Unlock()
	m := s.diskKeptLocked()
	if s.diskKept.unreadable != nil {
		return fmt.Errorf("%s cannot be read: %w", filepath.Join(s.dataDir, diskKeptFile), s.diskKept.unreadable)
	}
	var dropped []diskKeptRecord
	for _, r := range regs {
		if !slices.Contains(gone, filepath.Clean(s.hostDiskFile(r.Path))) {
			continue
		}
		key := diskKeptKey(r.Host, r.Path)
		if cur, ok := m[key]; ok && cur == r {
			delete(m, key)
			delete(s.diskKept.unsavedKey, key)
			dropped = append(dropped, r)
		}
	}
	if len(dropped) == 0 {
		return nil
	}
	s.saveDiskKeptLocked()
	if s.diskKept.unsaved {
		return fmt.Errorf("%s was not saved", filepath.Join(s.dataDir, diskKeptFile))
	}
	for _, r := range dropped {
		if err := health.ForgetKeptRecorded(s.dataDir, r.VM, s.keptRecordedFiles([]KeptDisk{r.KeptDisk})); err != nil {
			return &keptRecordedNoteLeftError{note: filepath.Join(s.dataDir, "kept-disks", r.VM+".json"), path: r.Path, err: err}
		}
	}
	return nil
}

// keptRecordedNoteLeftError is a forgetKeptRecords whose entries are
// dropped and saved, and whose drop of an entry's file from its note's
// recorded list failed: the note is left naming it.
type keptRecordedNoteLeftError struct {
	note, path string
	err        error
}

func (e *keptRecordedNoteLeftError) Error() string {
	return fmt.Sprintf("the note %s still lists %s as recorded (%v): it holds nothing, and nothing drops it later; "+
		"remove that path from the note's \"recorded\" list, or the note if that is all it lists", e.note, e.path, e.err)
}

func (e *keptRecordedNoteLeftError) Unwrap() error { return e.err }
