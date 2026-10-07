package grpcapi

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// errReachedImageStore ends a start's chain walk at an image-store base.
var errReachedImageStore = errors.New("reached an image-store base")

// verifyDiskChainForStart judges, before a start, every backing of local
// disk d (its file on this host) by the rule every copy path judges it by
// (diskChainRule): qemu and libvirt's relabelling follow the chain, so a
// layer naming a file the VM's project may not read would hand the guest
// that file. A backing that is missing, or that the rule refuses, refuses
// the start, saying which.
//
// Disks from an earlier build start as they did: a pool root disk whose
// header names its image by a bare relative name finds it beside the disk,
// as qemu does, and that file — placed there with the disk, recorded by no
// one — passes (diskChain.legacyPoolBase). A file a user uploaded there under
// that name passes too, but its own header is the uploader's to write: what
// it names is judged by record, never by the directory it is in
// (diskChain.judge).
func (s *Server) verifyDiskChainForStart(ctx context.Context, vm *corrosion.VMRecord, d corrosion.DiskRecord, file string) error {
	if fi, err := os.Stat(file); err != nil || !fi.Mode().IsRegular() {
		return nil
	}
	// The chain is judged down to an image-store base; the base and the
	// images under it are judged as a base (image.Store.AssertBase, by the
	// caller), as every start has since 2e319597.
	chain := s.newDiskChain(ctx, d)
	rule := func(layer, resolved, format string) error {
		if err := chain.judge(layer, resolved, format); err != nil {
			return err
		}
		if withinAny(resolved, chain.images) {
			return errReachedImageStore
		}
		return nil
	}
	if _, err := precheckChain(file, rule); err != nil && !errors.Is(err, errReachedImageStore) {
		slog.Error("start refused: a disk's backing chain names a file the VM may not read", "vm", vm.Name, "disk", d.DiskName, "file", file, "error", err)
		return status.Errorf(codes.FailedPrecondition,
			"disk %q of %q (%s) cannot be started: its backing chain is refused: %v", d.DiskName, vm.Name, filepath.Base(file), err)
	}
	return nil
}
