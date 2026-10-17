package fleet

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// TestFleet_RmWhileTheOldHostIsAwayUndefinesItsSupersededDomain: lab 2,
// pakg@node-4 (2026-10-17). rv ran on home at an owner epoch, home lost power
// (its domain stays defined, shut off), rv failed over to other at a newer
// epoch, and `lv rm rv` ran while home was away. When home is back, its
// reconciler undefines the shut-off domain: the deleted record moved past
// that copy before the delete. Disks stay (at their path after --keep-disks,
// set aside for the retention otherwise), the UEFI vars are set aside whole, the
// owner-epoch marker goes, and no vm_orphan_runtime stays open.
//
// Red on b4ef9fe9: the domain stays defined, the marker stays, and
// vm_orphan_runtime is raised and stays open ("reported, NOT reaped").
func TestFleet_RmWhileTheOldHostIsAwayUndefinesItsSupersededDomain(t *testing.T) {
	for _, keepDisks := range []bool{true, false} {
		t.Run(map[bool]string{true: "keep-disks", false: "delete"}[keepDisks], func(t *testing.T) {
			ctx := context.Background()
			r := newRecoveredVM(t)
			vm, err := corrosion.GetVM(ctx, r.coord.DB, "rv")
			if err != nil || vm == nil {
				t.Fatalf("rv after the failover: %+v, %v", vm, err)
			}
			rowEpoch := vm.OwnerEpoch
			if rowEpoch < 2 {
				rowEpoch = 2
				if err := r.coord.DB.Execute(ctx, `UPDATE vms SET vm_owner_epoch = ?, updated_at = ? WHERE name = 'rv'`,
					rowEpoch, r.coord.DB.NowTS()); err != nil {
					t.Fatal(err)
				}
			}
			// home's copy, from before the failover, one generation behind.
			r.home.Virt.DefineStoppedDomain("rv", "52:54:00:00:00:01")
			if err := r.home.Virt.SetDomainOwnerEpoch("rv", rowEpoch-1, false); err != nil {
				t.Fatal(err)
			}
			if err := health.WriteVMOwnerEpochMarker(r.homeData, "rv", rowEpoch-1); err != nil {
				t.Fatal(err)
			}
			marker := filepath.Join(r.homeData, "vms", "rv", "owner_epoch")
			vars := lv.NvramPath(r.homeData, "rv")
			if err := os.MkdirAll(filepath.Dir(vars), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(vars, []byte("rv's UEFI vars"), 0o600); err != nil {
				t.Fatal(err)
			}

			r.rm(t, keepDisks)
			if !r.home.Virt.DomainExists("rv") || !present(marker) {
				t.Fatal("the delete reached home while it was away")
			}

			r.homeActive(t)
			r.homeRec.ReconcileOnce(ctx)
			r.homeRec.ReconcileOnce(ctx)

			if r.home.Virt.DomainExists("rv") {
				t.Fatal("home still holds the superseded shut-off definition of the deleted rv")
			}
			var undefines []libvirtfake.Event
			for _, e := range r.home.Virt.EventLog() {
				if e.Op == "undefine" && e.Domain == "rv" {
					undefines = append(undefines, e)
				}
				if (e.Op == "start" || e.Op == "destroy") && e.Domain == "rv" {
					t.Fatalf("home ran %s on rv's leftover", e.Op)
				}
			}
			if len(undefines) != 1 || undefines[0].Note != "keep_state=true" {
				t.Fatalf("undefines = %+v, want one keeping the UEFI vars and TPM state", undefines)
			}
			// The vars are kept, set aside off the name-keyed path.
			if present(vars) {
				t.Fatalf("rv's UEFI vars are still at %s, where a create of the name is refused for them", vars)
			}
			set, _ := filepath.Glob(vars + ".superseded-*")
			if len(set) != 1 {
				t.Fatalf("rv's UEFI vars set aside as %v, want one file", set)
			}
			if b, err := os.ReadFile(set[0]); err != nil || string(b) != "rv's UEFI vars" {
				t.Fatalf("rv's set-aside UEFI vars: %q, %v", b, err)
			}
			if present(marker) {
				t.Fatal("rv's owner-epoch marker is still on home")
			}
			// Disks untouched: the real disk is at its path (kept), or set
			// aside whole for the retention.
			if keepDisks {
				if b := readFileT(t, r.path); !bytes.Equal(b, r.realBytes) {
					t.Fatal("the kept disk at its path is not rv's real disk")
				}
			} else {
				copies := r.supersededCopies(t)
				if present(r.path) {
					copies = append(copies, r.path)
				}
				if !slices.ContainsFunc(copies, func(p string) bool { return bytes.Equal(readFileT(t, p), r.realBytes) }) {
					t.Fatalf("rv's real disk is gone from home: %v", copies)
				}
			}
			all, err := corrosion.ListHealthConditions(ctx, r.coord.DB, false)
			if err != nil {
				t.Fatal(err)
			}
			for _, c := range all {
				if c.Evaluator == health.OrphanRuntimeEvaluator && c.SubjectID == "rv@"+r.home.Name {
					t.Fatalf("vm_orphan_runtime is open: %+v", c)
				}
			}
			evs, err := corrosion.ListVMEvents(ctx, r.coord.DB, "rv", 50, "")
			if err != nil {
				t.Fatal(err)
			}
			if !slices.ContainsFunc(evs, func(e corrosion.VMEventRecord) bool {
				return e.Type == "vm.leftover.undefined" && e.HostName == r.home.Name
			}) {
				t.Fatalf("no vm.leftover.undefined event from %s: %+v", r.home.Name, evs)
			}
		})
	}
}
