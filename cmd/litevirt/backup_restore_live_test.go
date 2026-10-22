package main

import (
	"io"
	"strings"
	"testing"
)

// --without-devices only means something for an auto-started VM: alone it is
// refused before any daemon is dialled.
//
// Mutation: drop the check: the command dials (and fails differently): red.
func TestBackupRestoreLive_WithoutDevicesNeedsAutoStart(t *testing.T) {
	cmd := newBackupRestoreLiveCmd()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"--repo", "r", "--vm", "vm1", "--disk", "root", "--timestamp", "t", "--without-devices"})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "needs --auto-start") {
		t.Fatalf("restore-live --without-devices without --auto-start = %v, want the --auto-start refusal", err)
	}
	if f := cmd.Flags().Lookup("without-devices"); f == nil {
		t.Fatal("restore-live has no --without-devices flag")
	}
}
