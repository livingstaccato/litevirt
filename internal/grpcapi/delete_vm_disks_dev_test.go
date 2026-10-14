package grpcapi

import (
	"errors"
	"testing"
)

// m-11 / I-5: a block volume's /dev/ node that is still there keeps its
// leftover (the delete fails) and its kept entry (it is named). Round 1 read
// every /dev/ path as gone without looking. /dev/null stands for a volume's
// node: its Lstat succeeds.
//
// Mutation: read a /dev/ path as gone again — both are dropped: red.
func TestDiskPresence_ABlockDeviceNodeStillThereIsNotGone(t *testing.T) {
	left := stillLeft([]diskLeftover{{disk: "root", path: "/dev/null", target: "/dev/null", err: errors.New("lvremove failed")}})
	if len(left) != 1 {
		t.Errorf("a failed removal of a block volume whose node is there was dropped: %+v", left)
	}
	s := testServerWithLocks(t)
	kept := s.keptThere([]KeptDisk{{Path: "/dev/null", Disk: "root", Host: s.hostName, Reason: "kept"}})
	if len(kept) != 1 {
		t.Errorf("a kept block volume whose node is there went unnamed: %+v", kept)
	}
	gone := stillLeft([]diskLeftover{{disk: "root", path: "/dev/lv-test-fu3a-absent", target: "/dev/lv-test-fu3a-absent", err: errors.New("x")}})
	if len(gone) != 0 {
		t.Errorf("a leftover whose /dev/ node is positively gone was kept: %+v", gone)
	}
}
