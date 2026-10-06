package vmimport

import (
	"bytes"
	"context"
	"os"
	"testing"
)

// A VMA declares its devices' sizes, and extraction writes up to that much
// into the import directory, which usually shares a filesystem with state.db.
// A small compressed archive can declare terabytes; the declared total must fit
// the caller's budget before anything is written.
func TestParseVMA_RefusesDevicesLargerThanItsBudget(t *testing.T) {
	vma, _ := buildSyntheticVMA(t) // one 128 KiB device
	dest := t.TempDir()
	if _, err := ParseVMA(context.Background(), bytes.NewReader(vma), dest, 64*1024); err == nil {
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
	if _, err := ParseVMA(ctx, bytes.NewReader(vma), t.TempDir(), 1<<40); err == nil {
		t.Fatal("a cancelled import extracted the VMA anyway")
	}
}
