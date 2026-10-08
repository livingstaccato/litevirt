package corrosion

import "context"

// ContainerBackupRecord is one container_backups index entry: the latest
// backup size of a container in one repo.
type ContainerBackupRecord struct {
	CtName     string
	Repo       string
	TotalBytes int64
	UpdatedAt  string
	legacy     bool // keyed by the bare name (written before project keys)
}

// ListContainerBackups returns a container's backup index entries, one per
// repo: its own project-keyed rows, and the rows written before project keys
// (keyed by the bare name, so possibly another project's) for repos it has no
// row of its own in. Read-only: the index is never pruned here, even for a
// repo that no longer exists — callers decide availability and attribution.
func ListContainerBackups(ctx context.Context, c *Client, ctName, project string) ([]ContainerBackupRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT ct_name, repo, total_bytes, updated_at FROM container_backups
		 WHERE ct_name = ? OR ct_name = ? ORDER BY repo`, ContainerBackupKey(project, ctName), ctName)
	if err != nil {
		return nil, err
	}
	byRepo := map[string]ContainerBackupRecord{}
	var order []string
	for _, r := range rows {
		_, _, keyed := splitContainerBackupKey(r.String("ct_name"))
		rec := ContainerBackupRecord{
			CtName: ctName, Repo: r.String("repo"),
			TotalBytes: r.Int64("total_bytes"), UpdatedAt: r.String("updated_at"),
		}
		prev, seen := byRepo[rec.Repo]
		if !seen {
			order = append(order, rec.Repo)
		}
		if !seen || (keyed && prev.legacy) {
			rec.legacy = !keyed
			byRepo[rec.Repo] = rec
		}
	}
	out := make([]ContainerBackupRecord, 0, len(order))
	for _, repo := range order {
		out = append(out, byRepo[repo])
	}
	return out, nil
}

// normalizeProject maps "" to DefaultProject, as container rows store it.
func normalizeProject(p string) string {
	if p == "" {
		return DefaultProject
	}
	return p
}

// ContainerProjectAnyState returns the project of the container row at
// (host, name) whether live or tombstoned, and whether one exists.
func ContainerProjectAnyState(ctx context.Context, c *Client, host, name string) (string, bool, error) {
	rows, err := c.Query(ctx, `SELECT project FROM containers WHERE host_name = ? AND name = ?`, host, name)
	if err != nil || len(rows) == 0 {
		return "", false, err
	}
	return normalizeProject(rows[0].String("project")), true, nil
}
