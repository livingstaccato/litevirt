package grpcapi

import (
	"context"
	"encoding/json"
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

// An installer ISO (VMSpec.iso) is a path on the target host that qemu opens
// and the guest reads as a CD-ROM. Naming one is therefore reading that file:
// an ISO of <pki_dir>/host.key gives the guest the host's peer identity, which
// is admin on every node, and <data_dir>/state.db or /etc/shadow are as bad.
//
// There are two ways to name one:
//
//   - A file in a file-based storage pool on the target host — the ".iso"
//     files the content browser lists and uploads. The caller needs
//     storage.content.read on that pool and the VM's project must be allowed
//     to use it (the same admission a disk on that pool takes). Only a plain
//     ".iso" file directly in the pool directory qualifies, never a symlink,
//     so a pool cannot be used to reach a VM's disk or anything outside it.
//   - Any other host path, which needs storage.hostpath at the cluster root
//     (only Admin holds it) — the verb that also guards pools on host paths.
//
// Either way storage.CheckReadFile refuses the PKI directory, the daemon's
// internal state and the secret system directories, to everyone.

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
// forwarded call is a peer; the classification (pool file or host path) is a
// pure function of the path and the replicated pool rows, so both nodes agree.
// It reports whether the ISO was admitted as a pool file, which the owner's
// filesystem check (checkVMISOFile) needs.
func (s *Server) authorizeVMISO(ctx context.Context, project, host, iso string) (inPool bool, err error) {
	if iso == "" {
		return false, nil
	}
	if !filepath.IsAbs(iso) || filepath.Clean(iso) != iso {
		return false, status.Errorf(codes.InvalidArgument,
			"iso %q must be an absolute, clean path on the target host", iso)
	}
	if err := storage.CheckReadPathLexical(iso, s.dataDir, s.pkiDir); err != nil {
		return false, status.Errorf(codes.InvalidArgument, "iso: %v", err)
	}
	pools, err := s.isoPoolFor(ctx, host, iso)
	if err != nil {
		return false, status.Errorf(codes.Internal, "iso: look up storage pools on %s: %v", host, err)
	}
	if len(pools) > 0 {
		if !isISOName(filepath.Base(iso)) {
			return false, status.Errorf(codes.InvalidArgument,
				"iso %q is in storage pool %q but is not a .iso file; only .iso pool content can be attached as installer media",
				iso, pools[0].Name)
		}
		// Several pool rows can map this directory; a file in it belongs to
		// all of them, so the caller must pass on every one, not just the
		// first that admits them.
		for _, p := range pools {
			denied := s.authorizeResourceRead(ctx, p.Project, poolRBACPathFor(p.Project, p.Name), "storage.content.read")
			if denied == nil {
				denied = s.admitPoolAttach(ctx, project, host, p.Name)
			}
			if denied != nil {
				return false, status.Errorf(codes.PermissionDenied,
					"iso %q is in the directory of storage pool %q, which this caller may not read or this VM's project may not use: %v",
					iso, p.Name, status.Convert(denied).Message())
			}
		}
		return true, nil
	}
	if perr := s.RequirePerm(ctx, "/", verbISOHostPath, "admin"); perr != nil {
		if status.Code(perr) != codes.PermissionDenied {
			return false, perr
		}
		return false, status.Errorf(codes.PermissionDenied,
			"iso %q is not a file in a storage pool on %s; attaching an arbitrary host file lets the guest read it, "+
				"so it needs %s at the cluster root (the Admin role on /). Upload the ISO to a pool instead",
			iso, host, verbISOHostPath)
	}
	return false, nil
}

// checkVMISOFile is the owning host's check, against its own filesystem,
// immediately before qemu is handed the ISO: at create and again at every
// start, because qemu reopens the file each time and whoever controls the
// directory can replace it in between. It applies to every caller, forwarded
// peers included, and to pool files and admin host paths alike:
//
//   - no component of the path is a symlink (the name is the file);
//   - it is a regular file with a single link, so it is not a second name
//     for some other file;
//   - it is not in a refused directory (storage.CheckReadFile).
func (s *Server) checkVMISOFile(iso string, _ bool) error {
	if iso == "" {
		return nil
	}
	if err := storage.CheckReadFile(iso, s.dataDir, s.pkiDir); err != nil {
		return status.Errorf(codes.InvalidArgument, "iso: %v", err)
	}
	if resolved, err := filepath.EvalSymlinks(iso); err != nil || resolved != iso {
		return status.Errorf(codes.InvalidArgument,
			"iso %q is reached through a symlink; name the file itself (%s)", iso, resolved)
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
			"iso %q has %d hard links, so it is also another file; copy the ISO instead of linking it", iso, n)
	}
	return nil
}

// verifyVMISOForStart judges a VM's stored installer ISO on this host before
// anything here hands it to qemu again: a start, a snapshot revert that can
// start the domain, a replace cutover, a migration landing here. A refusal
// keeps the VM down, loudly; nothing is rewritten — the operator replaces the
// ISO with a plain file or recreates the VM without it.
func (s *Server) verifyVMISOForStart(vm *corrosion.VMRecord) error {
	if vm == nil || vm.Spec == "" {
		return nil
	}
	var spec pb.VMSpec
	if err := json.Unmarshal([]byte(vm.Spec), &spec); err != nil || spec.Iso == "" {
		return nil // an unreadable spec is the start path's own concern
	}
	err := s.checkVMISOFile(spec.Iso, false)
	if err == nil {
		return nil
	}
	reason := status.Convert(err).Message()
	slog.Error("refusing to hand a VM its installer ISO: the file is not the plain file the VM was given; "+
		"the guest would read whatever it now names",
		"vm", vm.Name, "host", s.hostName, "iso", spec.Iso, "reason", reason)
	return status.Errorf(codes.FailedPrecondition,
		"VM %q has installer ISO %q, which this host will not attach (%s); replace it with a plain .iso file or recreate the VM without it",
		vm.Name, spec.Iso, reason)
}

// vmHasInstallerISO reports whether the VM's stored spec names an installer ISO.
func (s *Server) vmHasInstallerISO(ctx context.Context, name string) bool {
	rec, err := corrosion.GetVM(ctx, s.db, name)
	if err != nil || rec == nil || rec.Spec == "" {
		return false
	}
	var spec pb.VMSpec
	return json.Unmarshal([]byte(rec.Spec), &spec) == nil && spec.Iso != ""
}

func isISOName(name string) bool {
	return !strings.HasPrefix(name, ".") && strings.EqualFold(filepath.Ext(name), ".iso")
}
