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
	path  string
	size  int64
	under bool // a file of the unit backs on it
	gone  bool // named, and not there
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
}

// ofKeptVM reports whether file is a file of the deleted VM vm's own: one
// its note or record names, or one named as its disk files are
// (<vm>-<disk>..., or in the legacy <disks>/<vm>/ directory), outside the
// image store. A file below the first that is not stays: an image, or another
// VM's disk a kept linked clone backs on.
func (s *Server) ofKeptVM(vm, file string, named map[string]bool) bool {
	if named[file] {
		return true
	}
	if s.images != nil && filepath.Dir(file) == filepath.Clean(s.images.ImageDir()) {
		return false
	}
	return strings.HasPrefix(filepath.Base(file), vm+"-") || filepath.Base(filepath.Dir(file)) == vm
}

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
		walks := map[string]keptChainOf{}
		for _, c := range cands {
			type walked struct {
				layers  []string
				missing string
			}
			w, err := storage.Bounded("read the backing chain of", c, func() (walked, error) {
				l, m, err := keptChainLayersToMissing(c)
				return walked{l, m}, err
			})
			if err != nil {
				return nil, fmt.Errorf("the backing chain of %s, a disk the delete of VM %s kept, cannot be read (%v), so what a release "+
					"would leave without its base is unknown; fix that file or its storage, then retry", c, vm, err)
			}
			own := 0
			for own < len(w.layers) && (own == 0 || s.ofKeptVM(vm, w.layers[own], named)) {
				own++
			}
			walks[c] = keptChainOf{top: c, layers: w.layers, own: own, missing: w.missing}
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
		}
		for _, u := range units {
			u.files = orderOverlaysFirst(u.files, u.layers)
			for i := range u.files {
				f := &u.files[i]
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
				f.size = fi.Size()
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

// keptUnitHeld is why u may not be released now: something other than u
// references a file it would remove. "" when nothing does. A check that
// cannot be made refuses too (it is the answer: what it would have found is
// unknown).
func (s *Server) keptUnitHeld(ctx context.Context, u *keptUnit, all []*keptUnit) string {
	if u.host != s.hostName {
		return fmt.Sprintf("the file is on %s, not on %s, where this record was written; check it there, then remove its entry from %s on %s",
			u.host, s.hostName, filepath.Join(s.dataDir, diskKeptFile), s.hostName)
	}
	var files []string
	for _, f := range u.files {
		if !f.gone {
			files = append(files, f.path)
		}
	}
	if len(files) == 0 {
		return ""
	}
	mine := map[string]bool{}
	for _, f := range files {
		mine[f] = true
		if r, err := filepath.EvalSymlinks(f); err == nil {
			mine[r] = true
		}
	}

	// Another deleted VM's note, or another kept chain, holds or backs on it.
	noted, err := health.KeptNotedFiles(s.dataDir)
	if err != nil {
		return fmt.Sprintf("cannot tell: this host's notes of the disks deletes kept cannot be read (%v)", err)
	}
	for _, f := range files {
		if vm, ok := noted[f]; ok && vm != u.vm {
			return fmt.Sprintf("%s is also kept for the deleted VM %s (%s)", f, vm, filepath.Join(s.dataDir, "kept-disks", vm+".json"))
		}
	}
	for _, o := range all {
		if o == u || o.host != s.hostName {
			continue
		}
		for _, c := range o.layers {
			for _, l := range c {
				if mine[l] {
					return fmt.Sprintf("%s backs on %s: it is a disk the delete of VM %s kept; release that first", c[0], l, o.vm)
				}
			}
		}
	}

	// A live disk row: this host's, or any host's on shared storage.
	for _, f := range files {
		for _, p := range uniq(f, s.recordPath(f)) {
			var rows []corrosion.DiskRecord
			var err error
			if sharedStoreOf(filepath.Dir(f)).Shared {
				rows, err = s.diskReferencesAnyHost(ctx, p)
			} else {
				rows, err = s.liveDiskOwners(ctx, s.hostName, p)
			}
			if err != nil {
				return fmt.Sprintf("cannot tell whether a VM's disk uses %s (%v); retry", f, err)
			}
			if len(rows) > 0 {
				d := rows[0]
				return fmt.Sprintf("%s is in use by VM %s disk %s (as %s)", f, d.VMName, d.DiskName, referenceKind(&d, p))
			}
		}
	}

	// Another VM's disk whose backing chain reaches it.
	users, err := s.snapshotFileUsers(ctx, "", files)
	if err != nil {
		return fmt.Sprintf("cannot tell whether another VM's disk backs on it (%v); retry", err)
	}
	if len(users) > 0 {
		return fmt.Sprintf("the disk of VM %s backs on a file of it", strings.Join(users, ", "))
	}

	// A snapshot record: the deleted VM's on this host (its files are this
	// chain), or any whose memory image is one of them.
	snaps, err := corrosion.ListSnapshots(ctx, s.db, u.vm)
	if err != nil {
		return fmt.Sprintf("cannot tell whether a snapshot record names it (%v); retry", err)
	}
	var names []string
	for _, sn := range snaps {
		if sn.HostName == "" || sn.HostName == s.hostName {
			names = append(names, sn.Name)
		}
	}
	if len(names) > 0 {
		return fmt.Sprintf("the snapshot records %s of VM %s on %s are taken over these files", strings.Join(names, ", "), u.vm, s.hostName)
	}
	for _, f := range files {
		for _, p := range uniq(f, s.recordPath(f)) {
			rows, err := s.db.Query(ctx, `SELECT vm_name, name FROM snapshots WHERE vmstate_path = ? AND deleted_at IS NULL`, p)
			if err != nil {
				return fmt.Sprintf("cannot tell whether a snapshot record names %s (%v); retry", f, err)
			}
			if len(rows) > 0 {
				return fmt.Sprintf("%s is the memory image of snapshot %s of VM %s", f, rows[0].String("name"), rows[0].String("vm_name"))
			}
		}
	}

	// A replica, or a set-aside copy layered on it.
	for _, f := range files {
		if r, ok := replicaRecordFor(f); ok {
			return fmt.Sprintf("%s is a recorded replica of VM %s disk %s", f, r.VM, r.Disk)
		}
	}
	backing, err := s.supersededBacking(ctx)
	if err != nil {
		return fmt.Sprintf("cannot tell whether a superseded disk copy backs on it (%v); retry", err)
	}
	for _, f := range files {
		if backing.has(f) {
			return fmt.Sprintf("a superseded disk copy backs on %s (lv host superseded-disks %s)", f, s.hostName)
		}
	}
	keptCopies, err := health.ListKeptDisks(ctx, s.db, s.dataDir)
	if err != nil {
		return fmt.Sprintf("cannot tell whether a .kept- copy backs on it (%v); retry", err)
	}
	for _, k := range keptCopies {
		if k.Seed {
			continue
		}
		if reached, err := chainReaches(k.Path, "", func(p string) bool { return mine[filepath.Clean(p)] }); err != nil {
			return fmt.Sprintf("cannot tell whether %s backs on it (%v); retry", k.Path, err)
		} else if reached {
			return fmt.Sprintf("%s, a disk a deleted VM was kept with that a create moved aside, backs on it", k.Path)
		}
	}

	// A domain on this host: one of the deleted VM's name, or one whose disk
	// is, or backs on, a file of it.
	if s.virt != nil {
		doms, err := s.virt.ListDomains()
		if err != nil {
			return fmt.Sprintf("cannot tell whether a domain on %s uses it: libvirt does not answer (%v); retry", s.hostName, err)
		}
		for _, d := range doms {
			if d == u.vm {
				what := "defined"
				if active, err := s.virt.DomainIsActive(d); err != nil || active {
					what = "running"
				}
				return fmt.Sprintf("a domain %s is %s on %s; a domain of the deleted VM's name may use these files", d, what, s.hostName)
			}
			srcs, err := s.virt.DomainDiskFormats(d)
			if err != nil {
				if lv.IsNoDomain(err) {
					continue
				}
				return fmt.Sprintf("cannot tell whether the domain %s uses it (%v); retry", d, err)
			}
			for src, format := range srcs {
				hit := func(p string) bool {
					return mine[filepath.Clean(p)] || mine[filepath.Clean(s.hostDiskFile(p))]
				}
				reached := hit(src)
				if !reached {
					var rerr error
					reached, rerr = chainReaches(s.hostDiskFile(src), format, hit)
					if rerr != nil {
						return fmt.Sprintf("cannot tell whether the domain %s uses it (%v); retry", d, rerr)
					}
				}
				if reached {
					return fmt.Sprintf("the domain %s on %s uses it (its disk %s)", d, s.hostName, src)
				}
			}
		}
	}
	return ""
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

func (u *keptUnit) toPB(s *Server, held string, released bool) *pb.KeptDiskChain {
	c := &pb.KeptDiskChain{VmName: u.vm, StandsOn: u.standsOn, MissingBase: u.missing, Held: held, Released: released,
		Reason: strings.Join(u.reasons, "; ")}
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
		if req.DryRun || len(req.ExpectPaths) > 0 {
			return nil, status.Error(codes.InvalidArgument, "dry_run and expect_paths go with release")
		}
		units, err := s.keptUnits(ctx)
		if err != nil {
			return nil, status.Errorf(codes.FailedPrecondition, "list the disks deletes kept on %s: %v", s.hostName, err)
		}
		resp := &pb.KeptDisksResponse{Host: s.hostName}
		for _, u := range units {
			resp.Chains = append(resp.Chains, u.toPB(s, s.keptUnitHeld(ctx, u, units), false))
		}
		return resp, nil
	}
	return s.releaseKept(ctx, req, actor)
}

// releaseKept is the release half of KeptDisks, on the host the files are
// on, under the deleted VM's lock (a create or delete of the name, which
// reads and writes the same notes and records, waits).
func (s *Server) releaseKept(ctx context.Context, req *pb.KeptDisksRequest, actor string) (*pb.KeptDisksResponse, error) {
	refuse := func(code codes.Code, format string, a ...any) error {
		err := status.Errorf(code, "release %s on %s: "+format, append([]any{req.Release, s.hostName}, a...)...)
		if !req.DryRun {
			s.auditAs(ctx, actor, keptReleaseAudit, s.hostName, status.Convert(err).Message()+"; nothing was removed", "error")
		}
		return err
	}
	if !req.DryRun {
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
		return nil, err
	}
	vm := targets[0].vm
	defer s.lockVMAs(vm, "kept-disk release")()
	// Read again under the lock: a create or delete of the name may have
	// changed the notes and records meanwhile.
	if units, err = s.keptUnits(ctx); err != nil {
		return nil, refuse(codes.FailedPrecondition, "%v; nothing was removed", err)
	}
	if targets, err = s.keptUnitsFor(units, req.Release); err != nil {
		return nil, err
	}
	resp := &pb.KeptDisksResponse{Host: s.hostName, DryRun: req.DryRun}
	var helds []string
	var paths []string
	for _, u := range targets {
		held := s.keptUnitHeld(ctx, u, units)
		resp.Chains = append(resp.Chains, u.toPB(s, held, held == "" && req.DryRun))
		if held != "" {
			helds = append(helds, held)
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
	if len(req.ExpectPaths) > 0 {
		want := slices.Clone(req.ExpectPaths)
		for i := range want {
			want[i] = filepath.Clean(want[i])
		}
		got := slices.Clone(paths)
		slices.Sort(want)
		slices.Sort(got)
		if !slices.Equal(slices.Compact(want), slices.Compact(got)) {
			return nil, refuse(codes.Aborted, "it would now remove %s, not the files confirmed (%s); run it again to see what it removes",
				strings.Join(got, ", "), strings.Join(want, ", "))
		}
	}

	var removed []string
	var bytes int64
	var failed error
	resp.Chains = nil
	for _, u := range targets {
		var gone []string
		for _, f := range u.files {
			if failed != nil {
				break
			}
			if !f.gone {
				_, err := storage.Bounded("remove", f.path, func() (struct{}, error) { return struct{}{}, os.Remove(f.path) })
				if err != nil && !errors.Is(err, fs.ErrNotExist) {
					failed = fmt.Errorf("remove %s: %w", f.path, err)
					break
				}
				removed = append(removed, fmt.Sprintf("%s (%d bytes)", f.path, f.size))
				bytes += f.size
			}
			gone = append(gone, f.path)
		}
		// The records of what is gone go with it; a file a failure left
		// stays named, with the files under it.
		var nerr error
		if u.note != "" {
			nerr = health.ForgetKeptNoted(s.dataDir, u.vm, slices.DeleteFunc(slices.Clone(u.notePath), func(p string) bool { return !slices.Contains(gone, p) }))
		}
		if rerr := s.forgetKeptRecords(u.regs, gone); nerr == nil {
			nerr = rerr
		}
		if nerr != nil && failed == nil {
			failed = fmt.Errorf("the files are removed, and their records could not be updated (%w); a file that is gone is forgotten on its own", nerr)
		}
		resp.Chains = append(resp.Chains, u.toPB(s, "", failed == nil))
		if failed != nil {
			break
		}
	}
	detail := fmt.Sprintf("released the disks the delete of VM %s kept on %s (%s): removed %d file(s), %d bytes: %s",
		vm, s.hostName, req.Release, len(removed), bytes, strings.Join(removed, ", "))
	slog.Warn("kept disks released by an operator", "vm", vm, "release", req.Release, "removed", removed, "bytes", bytes, "actor", actor, "error", failed)
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

// forgetKeptRecords drops from kept-disks.json each of regs whose file is in
// gone. An entry rewritten meanwhile (a VM of the name kept the path again)
// is left.
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
	changed := false
	for _, r := range regs {
		if !slices.Contains(gone, filepath.Clean(s.hostDiskFile(r.Path))) {
			continue
		}
		key := diskKeptKey(r.Host, r.Path)
		if cur, ok := m[key]; ok && cur == r {
			delete(m, key)
			delete(s.diskKept.unsavedKey, key)
			changed = true
		}
	}
	if !changed {
		return nil
	}
	s.saveDiskKeptLocked()
	if s.diskKept.unsaved {
		return fmt.Errorf("%s was not saved", filepath.Join(s.dataDir, diskKeptFile))
	}
	return nil
}
