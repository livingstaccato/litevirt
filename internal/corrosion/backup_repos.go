package corrosion

import (
	"context"
	"log/slog"
)

// GetBackupRepo returns the live registration of name, or nil if there is
// none.
func GetBackupRepo(ctx context.Context, c *Client, name string) (*BackupRepo, error) {
	rows, err := c.Query(ctx,
		`SELECT name, path, stack_name FROM backup_repos WHERE name = ? AND deleted_at IS NULL`, name)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	r := rows[0]
	return &BackupRepo{Name: r.String("name"), Path: r.String("path"), StackName: r.String("stack_name")}, nil
}

// BackupRepo is a logical backup-repo name → on-disk path mapping, registered
// at runtime (e.g. from a compose `backup-repos:` block) and CRDT-replicated so
// every host can resolve the name. Daemon config `backup_repos:` is the static
// alternative and takes precedence in the resolver.
type BackupRepo struct {
	Name      string
	Path      string
	StackName string
}

// UpsertBackupRepo registers (or updates) a named repo path.
func UpsertBackupRepo(ctx context.Context, c *Client, r BackupRepo) error {
	now := c.NowTS()
	return c.Execute(ctx,
		`INSERT INTO backup_repos (name, path, stack_name, created_at, updated_at, deleted_at)
		 VALUES (?, ?, ?, ?, ?, NULL)
		 ON CONFLICT(name) DO UPDATE SET path = excluded.path,
		   stack_name = excluded.stack_name, updated_at = excluded.updated_at, deleted_at = NULL`,
		r.Name, r.Path, r.StackName, nowRFC3339(), now,
	)
}

// GetBackupRepoPath resolves a repo name to its path, or "" if unregistered.
func GetBackupRepoPath(ctx context.Context, c *Client, name string) (string, error) {
	rows, err := c.Query(ctx,
		`SELECT path FROM backup_repos WHERE name = ? AND deleted_at IS NULL`, name)
	if err != nil {
		return "", err
	}
	if len(rows) == 0 {
		return "", nil
	}
	return rows[0].String("path"), nil
}

// ListBackupRepos returns every live registered repo.
func ListBackupRepos(ctx context.Context, c *Client) ([]BackupRepo, error) {
	rows, err := c.Query(ctx,
		`SELECT name, path, stack_name FROM backup_repos WHERE deleted_at IS NULL ORDER BY name`)
	if err != nil {
		return nil, err
	}
	out := make([]BackupRepo, len(rows))
	for i, r := range rows {
		out[i] = BackupRepo{Name: r.String("name"), Path: r.String("path"), StackName: r.String("stack_name")}
	}
	return out, nil
}

// DeleteStackBackupRepos tombstones the repos a compose stack registered.
// A repo another live stack's file also uses (defines, or backs a workload up
// to) is handed to that stack (the first by name), at the path it has,
// instead: a deploy never takes a repo over from its owner. While another
// live stack's file cannot be read, a repo no readable file uses is kept, as
// that stack may use it. Only registrations go; no path is touched.
func DeleteStackBackupRepos(ctx context.Context, c *Client, stack string, read StackFileWants) error {
	if stack == "" {
		return nil
	}
	repos, err := ListBackupRepos(ctx, c)
	if err != nil {
		return err
	}
	var others []stackWants
	var unreadable []string
	loaded, kept := false, false
	for _, r := range repos {
		if r.StackName != stack {
			continue
		}
		if !loaded {
			if others, unreadable, err = otherStackWants(ctx, c, stack, read); err != nil {
				return err
			}
			loaded = true
		}
		handed := false
		for _, o := range others {
			if o.repos[r.Name] {
				if err := UpsertBackupRepo(ctx, c, BackupRepo{Name: r.Name, Path: r.Path, StackName: o.name}); err != nil {
					return err
				}
				handed = true
				break
			}
		}
		if !handed && len(unreadable) > 0 {
			kept = true
		}
	}
	if kept {
		slog.Warn("stack teardown: the stack's backup repos stay registered: the compose files of other stacks cannot be read, and one may use them",
			"stack", stack, "unreadable", unreadable)
		return nil
	}
	now := c.NowTS()
	return c.Execute(ctx,
		`UPDATE backup_repos SET deleted_at = ?, updated_at = ? WHERE stack_name = ? AND deleted_at IS NULL`,
		nowRFC3339(), now, stack)
}
