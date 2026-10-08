package corrosion

import (
	"context"
	"testing"
)

const testGiB = int64(1) << 30

func legacyCTBackupRow(t *testing.T, c *Client, name, repo string, bytes int64) {
	t.Helper()
	if err := c.Execute(context.Background(),
		`INSERT INTO container_backups (ct_name, repo, total_bytes, updated_at) VALUES (?, ?, ?, ?)`,
		name, repo, bytes, c.NowTS()); err != nil {
		t.Fatal(err)
	}
}

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

// m4: an index row written before this release (keyed by name alone) is
// counted as it was, once — and not a second time once the same container
// writes its project-keyed row for the same repo. The honest owner is never
// charged more than before.
func TestSumProjectUsage_LegacyRowCountedOnceAndSuperseded(t *testing.T) {
	c := newCtTestClient(t)
	ctx := context.Background()
	if err := UpsertContainer(ctx, c, ContainerRecord{HostName: "h1", Name: "web", State: "running", Project: "acme"}); err != nil {
		t.Fatal(err)
	}
	if err := UpsertContainer(ctx, c, ContainerRecord{HostName: "h2", Name: "web", State: "running", Project: "acme"}); err != nil {
		t.Fatal(err)
	}
	legacyCTBackupRow(t, c, "web", "/repo", 3*testGiB)
	u, _ := SumProjectUsage(ctx, c, "acme")
	if u.BackupGiBUsed != 3 {
		t.Fatalf("legacy row: BackupGiBUsed = %d, want 3 (once, though web is on two hosts)", u.BackupGiBUsed)
	}
	if err := UpsertContainerBackup(ctx, c, "acme", "web", "/repo", 2*testGiB); err != nil {
		t.Fatal(err)
	}
	u, _ = SumProjectUsage(ctx, c, "acme")
	if u.BackupGiBUsed != 2 {
		t.Fatalf("after a project-keyed push: BackupGiBUsed = %d, want 2 (the new row supersedes the legacy one)", u.BackupGiBUsed)
	}
}

// Inspect lists a container's own project-keyed rows and the legacy rows of
// its name, one entry per repo.
func TestListContainerBackups_ProjectKeyedAndLegacy(t *testing.T) {
	c := newCtTestClient(t)
	ctx := context.Background()
	legacyCTBackupRow(t, c, "web", "/old", 10)
	legacyCTBackupRow(t, c, "web", "/both", 20)
	if err := UpsertContainerBackup(ctx, c, "acme", "web", "/both", 30); err != nil {
		t.Fatal(err)
	}
	if err := UpsertContainerBackup(ctx, c, "beta", "web", "/beta-only", 40); err != nil {
		t.Fatal(err)
	}
	got, err := ListContainerBackups(ctx, c, "web", "acme")
	if err != nil {
		t.Fatal(err)
	}
	repos := map[string]int64{}
	for _, b := range got {
		repos[b.Repo] = b.TotalBytes
	}
	if len(repos) != 2 || repos["/old"] != 10 || repos["/both"] != 30 {
		t.Fatalf("acme's web backups = %v, want /old (legacy) and /both (its own row)", repos)
	}
}
