package grpcapi

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/storage"
)

// An installer ISO (VMSpec.iso) is a file on the target host that qemu opens
// and the guest reads as a CD-ROM. Naming one is therefore reading that file:
// an ISO of <pki_dir>/host.key gives the guest the host's peer identity, which
// is admin on every node, and <data_dir>/state.db or /etc/shadow are as bad.
//
// There are two ways to name one:
//
//   - A library reference "<pool>/<file>.iso" (iso_library.go): the global
//     library "isos", open to every project, or a pool the VM's project may
//     use and the caller may read. The host resolves it to a plain file
//     directly in the pool's directory, at create and at every start.
//   - An absolute host path, which needs storage.hostpath at the cluster root
//     (only Admin holds it). An absolute path that names a .iso directly in
//     a pool's directory — what earlier specs stored — is taken as that
//     pool's reference, for a non-admin too.
//
// Either way the file must be a plain file (no symlink anywhere along the
// path the host hands qemu, a single hard link), and storage.CheckReadFile
// refuses the PKI directory, the daemon's internal state and the secret system
// directories, to everyone.

// verbISOHostPath is the RBAC verb an arbitrary host path takes. It is the
// same verb the storage-pool host-path gate uses ("storage.hostpath"); kept as
// its own name here so this file does not depend on that change's file.
const verbISOHostPath = "storage.hostpath"

// isoPoolFor returns the file-based pools on host whose directory is exactly
// iso's directory. Several pool rows can share one directory (target-less
// local pools all live in <data_dir>/disks).
func (s *Server) isoPoolFor(ctx context.Context, host, iso string) ([]corrosion.StoragePoolRecord, error) {
	pools, err := corrosion.ListStoragePoolsForHost(ctx, s.db, host)
	if err != nil {
		return nil, err
	}
	dir := filepath.Dir(iso)
	var out []corrosion.StoragePoolRecord
	for _, p := range pools {
		if !isFileBasedDriver(p.Driver) {
			continue
		}
		pd, perr := fileBasedPoolDir(s.dataDir, StoragePoolRef{Driver: p.Driver, Source: p.Source, Target: p.Target})
		if perr != nil || pd == "" {
			continue
		}
		if filepath.Clean(pd) == dir {
			out = append(out, p)
		}
	}
	return out, nil
}

// authorizeVMISO is the create-time gate for spec.Iso. It runs on the entry
// node, where the caller is the user, and again on the owner, where a
// forwarded call is a peer; both judge the replicated pool rows of host. It
// records in spec.IsoScope which kind of pool (or an Admin's host path) the
// ISO is, which every later resolution holds the VM to. On the owner, a
// peer-forwarded spec arrives with the entry's classification, which the owner
// keeps rather than re-deriving it from the peer's own (admin) authority.
//
// A non-admin's absolute path into a pool directory is judged as that pool's
// reference and stored as written, so a compose file that names it does not
// differ from what was stored.
func (s *Server) authorizeVMISO(ctx context.Context, project, host string, spec *pb.VMSpec) error {
	iso := spec.GetIso()
	trusted := spec.GetIsoScope()
	spec.IsoScope = ""
	if iso == "" {
		return nil
	}
	poolScope := func(pool, file string) error {
		kind, err := s.authorizeISORef(ctx, project, host, pool, file)
		if err != nil {
			return err
		}
		if trusted != "" && trusted != kind {
			return status.Errorf(codes.FailedPrecondition,
				"iso %s/%s is a %s pool on %s, but the entry node saw a %s one; retry once the pool rows agree", pool, file, kind, host, trusted)
		}
		spec.IsoScope = kind
		return nil
	}
	if pool, file, ok := parseISORef(iso); ok {
		return poolScope(pool, file)
	}
	if !filepath.IsAbs(iso) {
		return status.Errorf(codes.InvalidArgument,
			"iso %q must be a library reference <pool>/<file>.iso (`lv iso ls` lists them) or, for an Admin, an absolute host path", iso)
	}
	if filepath.Clean(iso) != iso {
		return status.Errorf(codes.InvalidArgument,
			"iso %q must be an absolute, clean path on the target host", iso)
	}
	if err := storage.CheckReadPathLexical(iso, s.dataDir, s.pkiDir); err != nil {
		return status.Errorf(codes.InvalidArgument, "iso: %v", err)
	}
	perr := s.RequirePerm(ctx, "/", verbISOHostPath, "admin")
	if perr == nil && (trusted == "" || trusted == isoScopeHostPath) {
		spec.IsoScope = isoScopeHostPath
		return nil
	}
	if perr != nil && status.Code(perr) != codes.PermissionDenied {
		return perr
	}
	if ref, ok := s.isoRefForPath(ctx, host, iso); ok {
		pool, file, _ := parseISORef(ref)
		return poolScope(pool, file)
	}
	return status.Errorf(codes.PermissionDenied,
		"iso %q is a host path on %s; attaching an arbitrary host file lets the guest read it, "+
			"so it needs %s at the cluster root (the Admin role on /). Name an ISO from a library instead, "+
			"as <pool>/<file>.iso (`lv iso ls` lists them)",
		iso, host, verbISOHostPath)
}

// resolveSpecISO is this host's resolution of a VM's ISO through its pool: a
// library reference, or an absolute path recorded at create as a pool's file.
// viaPool is false for an Admin's host path and for a VM created before
// iso_scope was recorded whose ISO is an absolute path; the caller judges
// that path as itself.
func (s *Server) resolveSpecISO(ctx context.Context, project string, spec *pb.VMSpec) (path string, viaPool bool, err error) {
	iso, scope := spec.GetIso(), spec.GetIsoScope()
	if iso == "" {
		return "", false, nil
	}
	if pool, file, ok := parseISORef(iso); ok {
		path, err := s.resolveISOForVM(ctx, project, scope, pool, file, true)
		return path, true, err
	}
	switch scope {
	case isoScopeGlobal, isoScopePool, isoScopeProject:
		ref, ok := s.isoRefForPath(ctx, s.hostName, iso)
		if !ok {
			return "", true, status.Errorf(codes.FailedPrecondition,
				"iso %q names a file in a %s pool, and no pool on this host (%s) has that directory", iso, scope, s.hostName)
		}
		pool, file, _ := parseISORef(ref)
		path, err := s.resolveISOForVM(ctx, project, scope, pool, file, false)
		return path, true, err
	}
	return "", false, nil
}

// resolveVMISO is the owning host's resolution of spec.Iso to the file qemu
// is handed, against its own filesystem: through its pool (resolveSpecISO),
// or an Admin's absolute path as itself. Either way the file is judged by
// checkVMISOFile.
func (s *Server) resolveVMISO(ctx context.Context, project string, spec *pb.VMSpec) (string, error) {
	path, viaPool, err := s.resolveSpecISO(ctx, project, spec)
	if err != nil || viaPool || spec.GetIso() == "" {
		return path, err
	}
	if err := s.checkVMISOFile(spec.GetIso()); err != nil {
		return "", err
	}
	return spec.GetIso(), nil
}

// checkVMISOFile is the host's judgement of the file qemu is handed, at
// create and again at every start, because qemu reopens the file each time
// and whoever controls the directory can replace it in between:
//
//   - no component of the path is a symlink (the name is the file);
//   - it is a regular file with a single link, so it is not a second name
//     for some other file;
//   - it is not in a refused directory (storage.CheckReadFile).
func (s *Server) checkVMISOFile(iso string) error {
	if iso == "" {
		return nil
	}
	if err := storage.CheckReadFile(iso, s.dataDir, s.pkiDir); err != nil {
		return status.Errorf(codes.InvalidArgument, "iso: %v", err)
	}
	if resolved, err := filepath.EvalSymlinks(iso); err != nil || resolved != iso {
		return status.Errorf(codes.InvalidArgument,
			"iso %q is reached through a symlink; an ISO must be the file itself", iso)
	}
	fi, err := os.Lstat(iso)
	if err != nil {
		return status.Errorf(codes.FailedPrecondition, "iso %q: %v", iso, err)
	}
	if !fi.Mode().IsRegular() {
		return status.Errorf(codes.InvalidArgument, "iso %q is not a regular file", iso)
	}
	if n, ok := linkCount(fi); ok && n != 1 {
		return status.Errorf(codes.InvalidArgument,
			"iso %q has %d hard links, so it is also another file; put a copy in a library instead (`lv iso pull`)", iso, n)
	}
	// The checks above name the file; this opens it the way the last moment
	// before qemu can, without following a link, and confirms the open file
	// is that same file at that same path.
	if isoBeforeOpen != nil {
		isoBeforeOpen(iso)
	}
	f, ofi, openedAs, err := openNoFollow(iso)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "iso %q could not be opened as the file itself (%v); an ISO must not be a link", iso, err)
	}
	f.Close()
	if !os.SameFile(fi, ofi) || (openedAs != "" && openedAs != iso) {
		return status.Errorf(codes.InvalidArgument, "iso %q changed while it was being checked; an ISO must be the file itself", iso)
	}
	if n, ok := linkCount(ofi); ok && n != 1 {
		return status.Errorf(codes.InvalidArgument, "iso %q has %d hard links, so it is also another file", iso, n)
	}
	return nil
}

// isoBeforeOpen is a test seam: it runs between checkVMISOFile's checks of the
// name and its no-follow open, where a swap would land.
var isoBeforeOpen func(path string)

// domainInstallerISOs returns the file sources of the CD-ROMs in a domain
// definition, other than the VM's own cloud-init seed (litevirt writes that
// one into its data directory itself).
func (s *Server) domainInstallerISOs(vmName, domXML string) []string {
	var dom struct {
		Disks []struct {
			Device string `xml:"device,attr"`
			Source struct {
				File string `xml:"file,attr"`
			} `xml:"source"`
		} `xml:"devices>disk"`
	}
	if err := xml.Unmarshal([]byte(domXML), &dom); err != nil {
		return nil
	}
	seed := filepath.Join(s.dataDir, "cloudinit", vmName+".iso")
	var out []string
	for _, d := range dom.Disks {
		if d.Device != "cdrom" || d.Source.File == "" || d.Source.File == seed {
			continue
		}
		out = append(out, d.Source.File)
	}
	return out
}

// vmSpecFor parses a VM row's spec; nil when it has none or it does not parse.
func vmSpecFor(vm *corrosion.VMRecord) *pb.VMSpec {
	if vm == nil || vm.Spec == "" {
		return nil
	}
	var spec pb.VMSpec
	if json.Unmarshal([]byte(vm.Spec), &spec) != nil {
		return nil
	}
	return &spec
}

// verifyVMISOForStart judges, on this host, every installer CD-ROM the VM's
// defined domain will hand qemu at its next start: a start, a snapshot revert
// that can start it, a replace cutover. A domain with no installer CD-ROM
// (failover, the reconciler, UpdateVM regenerate without it) starts even
// after the ISO is gone. An ISO in a pool is resolved again through this
// host's pool, held to the kind recorded at create and to the VM's project,
// and the domain is pointed at that file if it names another path (it was
// defined on another host); an Admin's host path is judged as the path it is.
// A refusal keeps the VM down, loudly.
func (s *Server) verifyVMISOForStart(vm *corrosion.VMRecord) error {
	if vm == nil || s.virt == nil {
		return nil
	}
	domXML, err := s.virt.DumpXMLInactive(vm.Name)
	if err != nil {
		return nil
	}
	cdroms := s.domainInstallerISOs(vm.Name, domXML)
	if len(cdroms) == 0 {
		return nil
	}
	ctx := context.Background()
	if spec := vmSpecFor(vm); spec != nil {
		path, viaPool, err := s.resolveSpecISO(ctx, vm.Project, spec)
		if err != nil {
			return s.refuseISO(vm.Name, spec.GetIso(), err)
		}
		if viaPool {
			updated := domXML
			for _, c := range cdroms {
				if c != path {
					updated = repointCDROM(updated, c, path)
				}
			}
			if updated != domXML {
				if err := s.virt.DefineDomain(updated); err != nil {
					return status.Errorf(codes.Internal, "point %s's installer CD-ROM at %s: %v", vm.Name, path, err)
				}
				slog.Info("installer ISO: domain repointed at this host's library file", "vm", vm.Name, "iso", spec.GetIso(), "path", path)
			}
			return nil
		}
	}
	for _, iso := range cdroms {
		if err := s.checkVMISOFile(iso); err != nil {
			return s.refuseISO(vm.Name, iso, err)
		}
	}
	return nil
}

// repointCDROM replaces a CD-ROM's file source in a domain definition.
func repointCDROM(domXML, from, to string) string {
	for _, q := range []string{"'", `"`} {
		domXML = strings.ReplaceAll(domXML, "file="+q+from+q, "file="+q+to+q)
	}
	return domXML
}

// verifyIncomingVMISO is the migration target's judgement, before a domain
// carrying the VM's installer ISO lands here. The source lists the CD-ROM
// paths its domain carries (none: nothing to judge). An ISO in a pool is
// resolved through this host's pool, held to the recorded kind and the VM's
// project — a target without the pool refuses — and for a runtime migration,
// where libvirt hands qemu here the source's path, that resolution must be
// the very same path. Any other CD-ROM is judged as the path it is, and must
// exist. A source on an older build lists nothing; then the spec decides.
func (s *Server) verifyIncomingVMISO(vm *corrosion.VMRecord, req *pb.EnsureDisksRequest) error {
	spec := vmSpecFor(vm)
	if spec == nil {
		spec = &pb.VMSpec{}
	}
	ctx := context.Background()
	if req.GetInstallerIsoListed() {
		paths := req.GetInstallerIsoPaths()
		if len(paths) == 0 {
			return nil
		}
		path, viaPool, err := s.resolveSpecISO(ctx, vm.Project, spec)
		if err != nil {
			return s.refuseISO(vm.Name, spec.GetIso(), err)
		}
		if viaPool {
			if req.GetInstallerIsoRuntime() {
				for _, p := range paths {
					if p != path {
						return s.refuseISO(vm.Name, spec.GetIso(), status.Errorf(codes.FailedPrecondition,
							"the running VM's domain opens it at %s, and on this host it is %s; a running VM's CD-ROM path cannot change in a migration, so stop the VM and migrate it stopped, or give the library the same directory on both hosts",
							p, path))
					}
				}
			}
			return nil
		}
		for _, p := range paths {
			if err := s.checkVMISOFile(p); err != nil {
				return s.refuseISO(vm.Name, p, err)
			}
		}
		return nil
	}
	if spec.GetIso() == "" {
		return nil
	}
	_, viaPool, err := s.resolveSpecISO(ctx, vm.Project, spec)
	if err != nil {
		return s.refuseISO(vm.Name, spec.GetIso(), err)
	}
	if viaPool {
		return nil
	}
	if _, err := os.Lstat(spec.Iso); os.IsNotExist(err) {
		if rerr := storage.CheckRefusedReadPath(spec.Iso, s.dataDir, s.pkiDir); rerr != nil {
			return s.refuseISO(vm.Name, spec.Iso, status.Errorf(codes.InvalidArgument, "iso: %v", rerr))
		}
		return nil
	}
	if err := s.checkVMISOFile(spec.Iso); err != nil {
		return s.refuseISO(vm.Name, spec.Iso, err)
	}
	return nil
}

func (s *Server) refuseISO(vmName, iso string, err error) error {
	reason := status.Convert(err).Message()
	slog.Error("refusing to hand a VM its installer ISO: the file is not the plain file the VM was given; "+
		"the guest would read whatever it now names",
		"vm", vmName, "host", s.hostName, "iso", iso, "reason", reason)
	return status.Errorf(codes.FailedPrecondition,
		"VM %q has installer ISO %q, which this host will not attach (%s); put the ISO in a library (`lv iso pull`) or recreate the VM without it",
		vmName, iso, reason)
}

// domainInstallerISOPaths returns the installer CD-ROM paths the VM's domain
// on THIS host (the migration source) carries, which the target would open.
func (s *Server) domainInstallerISOPaths(name string) []string {
	if s.virt == nil {
		return nil
	}
	domXML, err := s.virt.DumpXMLInactive(name)
	if err != nil {
		return nil
	}
	return s.domainInstallerISOs(name, domXML)
}

// domainCarriesInstallerISO reports whether the VM's domain on THIS host has
// an installer CD-ROM.
func (s *Server) domainCarriesInstallerISO(name string) bool {
	return len(s.domainInstallerISOPaths(name)) > 0
}

func isISOName(name string) bool {
	return !strings.HasPrefix(name, ".") && strings.EqualFold(filepath.Ext(name), ".iso")
}
