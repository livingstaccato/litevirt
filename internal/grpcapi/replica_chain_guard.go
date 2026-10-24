package grpcapi

import (
	"context"
	"fmt"
	"path/filepath"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/storage"
)

// replicaChainUser names a disk that reads the replica file at path through
// its qcow2 backing chain, as the headers on this host say: a disk of one of
// vms (the VM the replica is of) or any live disk whose file is in poolDir,
// where a promotion builds its overlay. "" when none does.
//
// A disk row names the replica under a --no-localize overlay as its
// backing_disk (DisksReferencingPath finds it), but a promotion that took a
// VM over under its own name recorded none before it did, and those rows
// survive an upgrade: what the running VM reads is the header, whatever its
// row says. So every delete or prune of a replica asks this as well as the
// rows. A row or a header that cannot be read is an error, and the caller
// keeps the file.
func (s *Server) replicaChainUser(ctx context.Context, path, poolDir string, vms ...string) (string, error) {
	target := filepath.Clean(path)
	resolved, rerr := filepath.EvalSymlinks(target)
	if rerr != nil {
		resolved = ""
	}
	same := func(layer, _ string) bool {
		if filepath.Clean(layer) == target {
			return true
		}
		if resolved == "" {
			return false
		}
		r, err := filepath.EvalSymlinks(layer)
		return err == nil && r == resolved
	}

	var rows []corrosion.DiskRecord
	seen := map[string]bool{}
	add := func(ds []corrosion.DiskRecord) {
		for _, d := range ds {
			k := d.VMName + "\x00" + d.DiskName
			if !seen[k] && d.Path != "" {
				seen[k] = true
				rows = append(rows, d)
			}
		}
	}
	for _, vm := range vms {
		if vm == "" {
			continue
		}
		ds, err := corrosion.GetVMDisks(ctx, s.db, vm)
		if err != nil {
			return "", fmt.Errorf("read the disks of VM %s: %w", vm, err)
		}
		add(ds)
	}
	if poolDir != "" {
		prefixes := map[string]bool{s.recordPath(filepath.Clean(poolDir)): true, s.recordPath(resolvedOr(poolDir)): true}
		for prefix := range prefixes {
			ds, err := corrosion.LiveVMDisksWithPathPrefix(ctx, s.db, prefix+string(filepath.Separator))
			if err != nil {
				return "", fmt.Errorf("read the disks in %s: %w", poolDir, err)
			}
			add(ds)
		}
	}
	for _, d := range rows {
		file := s.hostDiskFile(d.Path)
		reached, err := storage.Bounded("read the backing chain of", file, func() (bool, error) {
			return qcow2ChainReaches(file, target, true, same)
		})
		if err != nil {
			return "", fmt.Errorf("read the backing chain of VM %s disk %s: %w", d.VMName, d.DiskName, err)
		}
		if reached {
			return fmt.Sprintf("VM %q disk %q", d.VMName, d.DiskName), nil
		}
	}
	return "", nil
}

// refuseReplicaAChainReads is a pool content delete's refusal of the file at
// path (shown as name) when a disk reads it through its backing chain, or
// when that cannot be told (replicaChainUser).
func (s *Server) refuseReplicaAChainReads(ctx context.Context, name, path, poolDir string, vms ...string) error {
	user, err := s.replicaChainUser(ctx, path, poolDir, vms...)
	if err != nil {
		return status.Errorf(codes.FailedPrecondition,
			"cannot tell whether a disk reads %q through its backing chain, so it is kept: %v", name, err)
	}
	if user != "" {
		return status.Errorf(codes.FailedPrecondition,
			"%q is read by %s through its backing chain; it is not pool content to delete", name, user)
	}
	return nil
}
