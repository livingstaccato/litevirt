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
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/qcow2"
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
	// A VM booted by a live restore that is not localized yet backs on the
	// restore's NBD export, which qemu reconnects to: admitted exactly when
	// this disk's own file is the overlay that restore made and recorded,
	// naming that export (the header itself judged as every layer is). No
	// other protocol backing is.
	if info, err := qcow2.Info(file); err == nil && looksLikeProtocol(info.BackingFile) && s.liveRestoreExportOf(file, info.BackingFile) {
		if err := precheckQcow2Header(file); err != nil {
			return status.Errorf(codes.FailedPrecondition,
				"disk %q of %q (%s) cannot be started: %v", d.DiskName, vm.Name, filepath.Base(file), err)
		}
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
		if errors.Is(err, errChainTooDeep) {
			held := s.chainHolders(ctx, vm.Name, file)
			slog.Error("start refused: a disk's backing chain is too deep", "vm", vm.Name, "disk", d.DiskName, "file", file, "held_by", held, "error", err)
			return status.Errorf(codes.FailedPrecondition,
				"disk %q of %q (%s) cannot be started: its %v layers. Each snapshot deleted while another "+
					"remained, or while something else needed the disk's layers, left one in the chain. Delete the "+
					"VM's snapshots (`lv snapshot rm %s <name>`): deleting the last one merges this VM's own snapshot "+
					"layers down to its disk, running or stopped, except layers something else needs. With none left, "+
					"`lv snapshot create %s merge` then `lv snapshot rm %s merge` does it. %s",
				d.DiskName, vm.Name, filepath.Base(file), err, vm.Name, vm.Name, vm.Name, held)
		}
		slog.Error("start refused: a disk's backing chain names a file the VM may not read", "vm", vm.Name, "disk", d.DiskName, "file", file, "error", err)
		return status.Errorf(codes.FailedPrecondition,
			"disk %q of %q (%s) cannot be started: its backing chain is refused: %v", d.DiskName, vm.Name, filepath.Base(file), err)
	}
	return nil
}

// refuseMergedLayerBoot refuses a start whose persistent definition — what
// a cold boot opens — names a layer a snapshot merge committed into another
// file while the VM ran but could not repoint the definition away from
// (libvirt.MergedLayerMarker; re-review 2, I-B). That layer holds the data
// as it was at the merge; the guest's later writes are in the base. Booting
// it would run the guest on a mix of old and new blocks, so the start fails
// loudly and says how to put it right.
func (s *Server) refuseMergedLayerBoot(vm *corrosion.VMRecord) error {
	if s.virt == nil {
		return nil
	}
	x, err := s.virt.DumpXMLInactive(vm.Name)
	if err != nil {
		return nil // no definition to judge; the start reports its own error
	}
	for dev, src := range lv.DomainDiskFiles(x) {
		if into, ok := lv.MergedInto(s.hostDiskFile(src)); ok {
			slog.Error("start refused: the definition boots a layer a snapshot merge emptied of its latest data",
				"vm", vm.Name, "dev", dev, "layer", src, "merged_into", into)
			return status.Errorf(codes.FailedPrecondition,
				"disk %s of %q cannot be started: its definition names %s, whose data a snapshot delete merged into %s "+
					"while the VM ran — the definition could not be repointed, and booting %s would run the guest on stale "+
					"blocks. Repoint the disk at %s (virsh edit %s), then remove %s",
				dev, vm.Name, src, into, filepath.Base(src), into, vm.Name, lv.MergedLayerMarker(src))
		}
	}
	return nil
}
