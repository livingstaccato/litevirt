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

// ListContainerBackups returns a container's backup index entries, by repo.
// Read-only: the index is never pruned here, even for a repo that no longer
// exists — callers decide availability at read time.
func ListContainerBackups(ctx context.Context, c *Client, ctName string) ([]ContainerBackupRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT ct_name, repo, total_bytes, updated_at FROM container_backups
		 WHERE ct_name = ? ORDER BY repo`, ctName)
	if err != nil {
		return nil, err
	}
	out := make([]ContainerBackupRecord, 0, len(rows))
	for _, r := range rows {
		out = append(out, ContainerBackupRecord{
			CtName: r.String("ct_name"), Repo: r.String("repo"),
			TotalBytes: r.Int64("total_bytes"), UpdatedAt: r.String("updated_at"),
		})
	}
	return out, nil
}
