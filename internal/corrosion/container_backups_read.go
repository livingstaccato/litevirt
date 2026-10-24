package corrosion

import "context"

// ContainerBackupRecord is one container_backups index entry: the latest
// backup size of a container in one repo.
type ContainerBackupRecord struct {
	CtName     string
	Repo       string
	TotalBytes int64
	UpdatedAt  string
}

// ListContainerBackups returns a container's backup index entries, one per
// repo. Read-only: the index is never pruned here, even for a repo that no
// longer exists — callers decide availability and attribution.
func ListContainerBackups(ctx context.Context, c *Client, ctName, project string) ([]ContainerBackupRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT repo, total_bytes, updated_at FROM container_backups
		 WHERE ct_name = ? ORDER BY repo`, ContainerBackupKey(project, ctName))
	if err != nil {
		return nil, err
	}
	out := make([]ContainerBackupRecord, 0, len(rows))
	for _, r := range rows {
		out = append(out, ContainerBackupRecord{
			CtName: ctName, Repo: r.String("repo"),
			TotalBytes: r.Int64("total_bytes"), UpdatedAt: r.String("updated_at"),
		})
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
