package corrosion

import (
	"context"
	"testing"
)

const testGiB = int64(1) << 30

// m4: two projects each have a container named "web". beta's backups must
// not count toward acme's backup_gib, so beta cannot block acme's creates.
func TestSumProjectUsage_SameNameOtherProjectBackupsNotCounted(t *testing.T) {
	c := newCtTestClient(t)
	ctx := context.Background()
	for _, p := range []string{"acme", "beta"} {
		if err := UpsertContainer(ctx, c, ContainerRecord{HostName: "h-" + p, Name: "web", State: "running", Project: p}); err != nil {
			t.Fatal(err)
		}
	}
	if err := UpsertContainerBackup(ctx, c, "beta", "web", "/repo-b", 5*testGiB); err != nil {
		t.Fatal(err)
	}
	if err := UpsertContainerBackup(ctx, c, "acme", "web", "/repo-a", 1*testGiB); err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]int{"acme": 1, "beta": 5} {
		u, err := SumProjectUsage(ctx, c, p)
		if err != nil {
			t.Fatal(err)
		}
		if u.BackupGiBUsed != want {
			t.Errorf("%s BackupGiBUsed = %d, want %d (only its own web's backups)", p, u.BackupGiBUsed, want)
		}
	}
}

// A container on two hosts under one name has one index row per repo, and
// the project is charged for it once.
func TestSumProjectUsage_SameContainerOnTwoHostsCountedOnce(t *testing.T) {
	c := newCtTestClient(t)
	ctx := context.Background()
	for _, h := range []string{"h1", "h2"} {
		if err := UpsertContainer(ctx, c, ContainerRecord{HostName: h, Name: "web", State: "running", Project: "acme"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := UpsertContainerBackup(ctx, c, "acme", "web", "/repo", 3*testGiB); err != nil {
		t.Fatal(err)
	}
	if u, _ := SumProjectUsage(ctx, c, "acme"); u.BackupGiBUsed != 3 {
		t.Fatalf("BackupGiBUsed = %d, want 3 (once, though web is on two hosts)", u.BackupGiBUsed)
	}
}

// Inspect lists a container's own project-keyed rows, one entry per repo,
// never another project's same-named container's.
func TestListContainerBackups_OwnProjectOnly(t *testing.T) {
	c := newCtTestClient(t)
	ctx := context.Background()
	for _, w := range []struct {
		project, repo string
		bytes         int64
	}{{"acme", "/a1", 10}, {"acme", "/both", 30}, {"beta", "/both", 20}, {"beta", "/beta-only", 40}} {
		if err := UpsertContainerBackup(ctx, c, w.project, "web", w.repo, w.bytes); err != nil {
			t.Fatal(err)
		}
	}
	got, err := ListContainerBackups(ctx, c, "web", "acme")
	if err != nil {
		t.Fatal(err)
	}
	repos := map[string]int64{}
	for _, b := range got {
		repos[b.Repo] = b.TotalBytes
	}
	if len(repos) != 2 || repos["/a1"] != 10 || repos["/both"] != 30 {
		t.Fatalf("acme's web backups = %v, want /a1 and /both (its own rows)", repos)
	}
}
