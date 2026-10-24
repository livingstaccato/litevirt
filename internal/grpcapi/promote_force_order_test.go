package grpcapi

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// promoteErr runs an operator's direct promotion of db with --force and
// returns its error.
func promoteErr(s *Server, replica string) error {
	stream := &streamRecorder[pb.PromoteReplicaProgress]{ctx: adminCtx()}
	return s.PromoteReplica(&pb.PromoteReplicaRequest{VmName: "db", TargetPool: "dr", Force: true, NoLocalize: true, Replica: replica}, stream)
}

// A --force promotion replaces a domain already defined under the name only
// once nothing is left to refuse. Here a file is already at the root's live
// path (the random part of its name pinned to one a file has): the promotion
// refuses it (refuseExistingFile) and the running domain
// is left defined and running. It used to be destroyed and undefined first,
// leaving the VM undefined by a promotion that then refused.
//
// Mutation "destroy first" (the --force destroy and undefine back before the
// disk build) — red: the domain is gone.
func TestPromote_ForceRefusesBeforeItDestroysTheDomain(t *testing.T) {
	s := testServer(t)
	poolDir := setPromoteVMRows(t, s, "db", nil)
	run := stamp(10 * time.Minute)
	replica := seedReplica(t, poolDir, "", "db", "root", run, "raw", 1<<20)
	fake := s.virt.(*libvirtfake.Fake)
	if err := fake.DefineDomain("<domain><name>db</name></domain>"); err != nil {
		t.Fatal(err)
	}
	if err := fake.StartDomain("db"); err != nil {
		t.Fatal(err)
	}
	s.promotedDiskSuffix = func() string { return "0123456789abcdef" } // a name a file already has
	live := filepath.Join(poolDir, "db-promoted-"+strings.TrimSuffix(replica, ".raw")+"-0123456789abcdef.qcow2")
	if err := os.WriteFile(live, []byte("someone's disk"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := promoteErr(s, "")
	if status.Code(err) != codes.AlreadyExists {
		t.Fatalf("promotion over a file at the live path = %v, want AlreadyExists", err)
	}
	if !fake.DomainExists("db") {
		t.Fatal("the refused promotion undefined the domain already here")
	}
	if st, _ := fake.DomainState("db"); st != "running" {
		t.Errorf("domain state after the refused promotion = %q, want running", st)
	}
	if b, _ := os.ReadFile(live); string(b) != "someone's disk" {
		t.Errorf("the file at the live path was touched: %q", b)
	}
}

// A partial promotion (the shared data1 left unattached, its owner fenced by
// SSH only), then the owner confirmed off, then the promotion re-run with
// --force — the scenario fix round 5 found destructive. With the same replica
// it destroyed and undefined the promoted domain and then refused the root's
// live file; with a newer replica it rebuilt the disks and discarded what the
// promoted VM wrote. Now it is refused before anything is touched: the
// promoted domain stays defined and running on the same disks, its rows are
// unchanged, the root's live disk keeps its bytes, and nothing is built.
//
// Mutation "destroy first" — red on both rows (the domain is undefined).
// Mutation "no promoted-disk refusal" (refuseRebuildOverPromotedDisks returns
// nil) — red on "a newer replica" (the promotion succeeds and rebuilds).
func TestPromote_AForcedRePromotionOverAPartialOneDestroysNothing(t *testing.T) {
	for _, c := range []struct {
		name  string
		newer bool
	}{
		{"the same replica", false},
		{"a newer replica", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := testServer(t)
			nfsDisk := nfsPromoteVM(t, s, "fenced")
			recordOwnerFence(t, s, "f1", "ssh", "fenced", time.Minute)
			promoteVia(t, s, false, true)
			assertSharedUnattached(t, s, nfsDisk, "dead-host is fenced, but not proven powered off")

			fake := s.virt.(*libvirtfake.Fake)
			xmlBefore := fake.DefinedXML("db")
			rowsBefore := diskRowsOf(t, s, "db")
			root := rowsBefore["root"]
			if root.HostName != s.hostName || !strings.Contains(filepath.Base(root.Path), "db-promoted-") {
				t.Fatalf("root row after the partial promotion = %+v, want a promoted live disk here", root)
			}
			// What the promoted VM has written since.
			f, err := os.OpenFile(root.Path, os.O_WRONLY|os.O_APPEND, 0)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.WriteString("the promoted VM's writes"); err != nil {
				t.Fatal(err)
			}
			f.Close()
			rootBytes, _ := os.ReadFile(root.Path)

			// The owner is now confirmed off: what the old advice said to do.
			recordOwnerFence(t, s, "f2", "manual", "manual-confirmed", 0)
			poolDir := filepath.Dir(root.Path)
			replica := ""
			if c.newer {
				replica = seedReplica(t, poolDir, "", "db", "root", stamp(time.Minute), "raw", 1<<20)
			}
			entries := func() []string {
				ents, _ := os.ReadDir(poolDir)
				var out []string
				for _, e := range ents {
					out = append(out, e.Name())
				}
				return out
			}
			before := entries()

			err = promoteErr(s, replica)
			if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "--new-name") {
				t.Fatalf("re-promotion over the partial one = %v, want FailedPrecondition naming --new-name", err)
			}
			if !fake.DomainExists("db") {
				t.Fatal("the refused re-promotion undefined the promoted domain")
			}
			if st, _ := fake.DomainState("db"); st != "running" {
				t.Errorf("promoted domain state = %q, want running", st)
			}
			if got := fake.DefinedXML("db"); got != xmlBefore {
				t.Errorf("the promoted domain was redefined:\n%s\nwas\n%s", got, xmlBefore)
			}
			for name, r := range diskRowsOf(t, s, "db") {
				if r != rowsBefore[name] {
					t.Errorf("disk row %s = %+v, was %+v", name, r, rowsBefore[name])
				}
			}
			if b, _ := os.ReadFile(root.Path); !bytes.Equal(b, rootBytes) {
				t.Error("the promoted VM's root live disk was changed")
			}
			if after := entries(); strings.Join(after, ",") != strings.Join(before, ",") {
				t.Errorf("the refused re-promotion left files in the pool: %v, was %v", after, before)
			}
		})
	}
}
