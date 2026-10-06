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
// forwarded call is a peer; both judge the replicated pool rows of host. A
// non-admin's absolute path into a pool directory is judged as that pool's
// reference and stored as written, so a compose file that names it does not
// differ from what was stored.
func (s *Server) authorizeVMISO(ctx context.Context, project, host string, spec *pb.VMSpec) error {
	iso := spec.GetIso()
	if iso == "" {
		return nil
	}
	if pool, file, ok := parseISORef(iso); ok {
		return s.authorizeISORef(ctx, project, host, pool, file)
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
	if perr == nil {
		return nil
	}
	if status.Code(perr) != codes.PermissionDenied {
		return perr
	}
	if ref, ok := s.isoRefForPath(ctx, host, iso); ok {
		pool, file, _ := parseISORef(ref)
		return s.authorizeISORef(ctx, project, host, pool, file)
	}
	return status.Errorf(codes.PermissionDenied,
		"iso %q is a host path on %s; attaching an arbitrary host file lets the guest read it, "+
			"so it needs %s at the cluster root (the Admin role on /). Name an ISO from a library instead, "+
			"as <pool>/<file>.iso (`lv iso ls` lists them)",
		iso, host, verbISOHostPath)
}

// resolveVMISO is the owning host's resolution of spec.Iso to the file qemu
// is handed, against its own filesystem: a library reference — or a path
// directly in a pool directory — through its pool, any other (admin) absolute
// path as itself. Either way the file is judged by
// checkVMISOFile.
func (s *Server) resolveVMISO(ctx context.Context, iso string) (string, error) {
	if iso == "" {
		return "", nil
	}
	if pool, file, ok := parseISORef(iso); ok {
		return s.resolveISORef(ctx, pool, file)
	}
	// A path directly in a pool directory is that pool's file, as every
	// start will take it (specISORef).
	if ref, ok := s.isoRefForPath(ctx, s.hostName, iso); ok {
		pool, file, _ := parseISORef(ref)
		return s.resolveISORef(ctx, pool, file)
	}
	if err := s.checkVMISOFile(iso); err != nil {
		return "", err
	}
	return iso, nil
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
	return nil
}

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

// specISORef returns the library reference spec.Iso stands for on this host:
// the reference itself, or — for an absolute path naming a .iso directly in a
// pool directory here, as earlier specs stored it — that pool's reference.
func (s *Server) specISORef(ctx context.Context, vm *corrosion.VMRecord) (pool, file string, ok bool) {
	if vm == nil || vm.Spec == "" {
		return "", "", false
	}
	var spec pb.VMSpec
	if json.Unmarshal([]byte(vm.Spec), &spec) != nil || spec.Iso == "" {
		return "", "", false
	}
	if pool, file, ok := parseISORef(spec.Iso); ok {
		return pool, file, true
	}
	if ref, ok := s.isoRefForPath(ctx, s.hostName, spec.Iso); ok {
		return parseISORef(ref)
	}
	return "", "", false
}

// verifyVMISOForStart judges, on this host, every installer CD-ROM the VM's
// defined domain will hand qemu at its next start: a start, a snapshot revert
// that can start it, a replace cutover. A domain with no installer CD-ROM
// (failover, the reconciler, UpdateVM regenerate without it) starts even
// after the ISO is gone. A library ISO is resolved again through its pool,
// and the domain is pointed at that file if it names another path (a pool
// directory that differs from the host the domain was defined on); any other
// CD-ROM is judged as the path it is. A refusal keeps the VM down, loudly.
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
	if pool, file, ok := s.specISORef(ctx, vm); ok {
		path, err := s.resolveISORef(ctx, pool, file)
		if err != nil {
			return s.refuseISO(vm.Name, pool+"/"+file, err)
		}
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
			slog.Info("installer ISO: domain repointed at this host's library file", "vm", vm.Name, "iso", pool+"/"+file, "path", path)
		}
		return nil
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
// carrying the VM's ISO lands here. A library ISO is resolved through this
// host's pool; an absolute path is judged as itself. A missing file (or a
// library this host lacks) is not a read, so it is left to libvirt, which
// refuses a domain whose CD-ROM path is absent.
func (s *Server) verifyIncomingVMISO(vm *corrosion.VMRecord) error {
	if vm == nil || vm.Spec == "" {
		return nil
	}
	var spec pb.VMSpec
	if err := json.Unmarshal([]byte(vm.Spec), &spec); err != nil || spec.Iso == "" {
		return nil
	}
	if pool, file, ok := s.specISORef(context.Background(), vm); ok {
		rec, found, err := corrosion.GetStoragePool(context.Background(), s.db, s.hostName, pool)
		if err != nil || !found {
			return nil
		}
		dir, err := s.poolDirResolved(rec)
		if err != nil {
			return nil
		}
		if _, err := os.Lstat(filepath.Join(dir, file)); os.IsNotExist(err) {
			return nil
		}
		if _, err := s.resolveISORef(context.Background(), pool, file); err != nil {
			return s.refuseISO(vm.Name, pool+"/"+file, err)
		}
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

// domainCarriesInstallerISO reports whether the VM's domain on THIS host
// (the migration source) has an installer CD-ROM the target would open.
func (s *Server) domainCarriesInstallerISO(name string) bool {
	if s.virt == nil {
		return false
	}
	domXML, err := s.virt.DumpXMLInactive(name)
	if err != nil {
		return false
	}
	return len(s.domainInstallerISOs(name, domXML)) > 0
}

func isISOName(name string) bool {
	return !strings.HasPrefix(name, ".") && strings.EqualFold(filepath.Ext(name), ".iso")
}
