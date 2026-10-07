package vmimport

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"testing"
)

// Extraction writes the archive's device data into the import directory,
// which usually shares a filesystem with state.db. What it writes must fit the
// caller's budget, and a refused extraction leaves nothing behind.
func TestParseVMA_RefusesDevicesLargerThanItsBudget(t *testing.T) {
	vma, _ := buildSyntheticVMA(t) // one 128 KiB device
	dest := t.TempDir()
	if _, err := ParseVMA(context.Background(), bytes.NewReader(vma), dest, Budget(64*1024)); err == nil {
		t.Fatal("a VMA declaring more than its budget was extracted")
	}
	if left, _ := os.ReadDir(dest); len(left) != 0 {
		t.Fatalf("a refused VMA left files behind: %v", left)
	}
}

func TestParseVMA_StopsWhenTheImportIsCancelled(t *testing.T) {
	vma, _ := buildSyntheticVMA(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ParseVMA(ctx, bytes.NewReader(vma), t.TempDir(), Budget(1<<40)); err == nil {
		t.Fatal("a cancelled import extracted the VMA anyway")
	}
}

// C-1. The device files are sparse: a thin device costs the data its extents
// carry, not its declared size. A VMA declaring a 1 GiB device that holds
// 128 KiB extracts within a 1 MiB budget (on main it needed no budget at all),
// and its file still has the declared size.
func TestParseVMA_AThinDeviceCostsItsDataNotItsDeclaredSize(t *testing.T) {
	old := vmaReserveStep
	vmaReserveStep = 64 << 10
	t.Cleanup(func() { vmaReserveStep = old })
	vma, _ := buildSyntheticVMA(t) // one device, 128 KiB of data
	// Declare it 1 GiB: dev_info[1].size.
	binary.BigEndian.PutUint64(vma[4096+1*32+8:], 1<<30)
	var asked uint64
	reserve := func(total uint64) error {
		asked = max(asked, total)
		return Budget(1 << 20)(total)
	}
	dest := t.TempDir()
	fv, err := ParseVMA(context.Background(), bytes.NewReader(vma), dest, reserve)
	if err != nil {
		t.Fatalf("a thin 1 GiB device holding 128 KiB was refused a 1 MiB budget: %v", err)
	}
	if asked > 1<<20 {
		t.Fatalf("reserved %d bytes for 128 KiB of data", asked)
	}
	fi, err := os.Stat(fv.Disks[0].LocalPath)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() != 1<<30 {
		t.Fatalf("device file is %d bytes; want the declared 1 GiB", fi.Size())
	}
}
