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
		var denied error
		for _, p := range pools {
			if rerr := s.authorizeResourceRead(ctx, p.Project, poolRBACPathFor(p.Project, p.Name), "storage.content.read"); rerr != nil {
				denied = rerr
				continue
			}
			if aerr := s.admitPoolAttach(ctx, project, host, p.Name); aerr != nil {
				denied = aerr
				continue
			}
			return true, nil
		}
		return false, status.Errorf(codes.PermissionDenied,
			"iso %q is in storage pool %q, which this caller may not read or this VM's project may not use: %v",
			iso, pools[0].Name, status.Convert(denied).Message())
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
// immediately before the ISO is attached. It applies to every caller,
// forwarded peers included: the refused directories after resolving symlinks,
// and, for a pool file, that the name itself is a regular file and not a
// symlink planted in the pool directory.
func (s *Server) checkVMISOFile(iso string, inPool bool) error {
	if iso == "" {
		return nil
	}
	if inPool {
		fi, err := os.Lstat(iso)
		if err != nil {
			return status.Errorf(codes.FailedPrecondition, "iso %q: %v", iso, err)
		}
		if !fi.Mode().IsRegular() {
			return status.Errorf(codes.InvalidArgument,
				"iso %q is not a regular file in its pool (a symlink or special file is never pool content)", iso)
		}
	}
	if err := storage.CheckReadFile(iso, s.dataDir, s.pkiDir); err != nil {
		return status.Errorf(codes.InvalidArgument, "iso: %v", err)
	}
	return nil
}

// refuseStoredISOAtStart is the start-time check for a VM created before
// spec.Iso was gated. Its domain already carries the CD-ROM, so a start would
// hand the guest the file again (re-reading a rotated host key, say). A stored
// ISO that no caller may name today — the PKI directory, the daemon's internal
// state, a secret system directory — refuses the start, loudly; everything else
// starts as before. Nothing is rewritten: the operator detaches or recreates.
func (s *Server) refuseStoredISOAtStart(vm *corrosion.VMRecord) error {
	if vm == nil || vm.Spec == "" {
		return nil
	}
	var spec pb.VMSpec
	if err := json.Unmarshal([]byte(vm.Spec), &spec); err != nil || spec.Iso == "" {
		return nil // an unreadable spec is the start path's own concern
	}
	err := storage.CheckRefusedReadPath(spec.Iso, s.dataDir, s.pkiDir)
	if err == nil {
		return nil
	}
	slog.Error("refusing to start a VM whose installer ISO is a protected host file; "+
		"the guest would read it. Recreate the VM without it or with a pool ISO",
		"vm", vm.Name, "host", s.hostName, "iso", spec.Iso, "reason", err)
	return status.Errorf(codes.FailedPrecondition,
		"VM %q has installer ISO %q, which no VM may read (%v); recreate it without that ISO", vm.Name, spec.Iso, err)
}

func isISOName(name string) bool {
	return !strings.HasPrefix(name, ".") && strings.EqualFold(filepath.Ext(name), ".iso")
}
