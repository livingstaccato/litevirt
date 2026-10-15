package corrosion

import (
	"context"
	"log/slog"
	"strings"
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
	var scheduled map[string]bool
	var keptScheduled, gone []string
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
		var heirs []string
		for _, o := range others {
			if o.repos[r.Name] {
				heirs = append(heirs, o.name)
			}
		}
		handed, err := handOff(ctx, c, stack, heirs, func(owner string) error {
			return UpsertBackupRepo(ctx, c, BackupRepo{Name: r.Name, Path: r.Path, StackName: owner})
		})
		if err != nil {
			return err
		}
		if handed {
			continue
		}
		if len(unreadable) > 0 {
			kept = true
		}
		if scheduled == nil {
			if scheduled, err = scheduledBackupRepos(ctx, c); err != nil {
				return err
			}
		}
		if scheduled[r.Name] {
			keptScheduled = append(keptScheduled, r.Name)
		} else {
			gone = append(gone, r.Name)
		}
	}
	if kept || len(keptScheduled) > 0 {
		warnOnChange("backup-repos/"+stack, strings.Join(append(append([]string{}, unreadable...), keptScheduled...), ","),
			"stack teardown: the stack's backup repos stay registered: a backup schedule names one, or another stack's compose file cannot be read and may use them",
			"stack", stack, "scheduled", keptScheduled, "unreadable", unreadable)
		return nil
	}
	now := c.NowTS()
	if err := c.Execute(ctx,
		`UPDATE backup_repos SET deleted_at = ?, updated_at = ? WHERE stack_name = ? AND deleted_at IS NULL`,
		nowRFC3339(), now, stack); err != nil {
		return err
	}
	if len(gone) > 0 {
		slog.Info("stack teardown: backup repo registrations removed; the data at their paths is untouched", "stack", stack, "repos", gone)
	}
	return nil
}

// scheduledBackupRepos is the set of repo names a live backup schedule names.
func scheduledBackupRepos(ctx context.Context, c *Client) (map[string]bool, error) {
	rows, err := c.Query(ctx, `SELECT DISTINCT repo FROM backup_schedules WHERE deleted_at IS NULL`)
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(rows))
	for _, r := range rows {
		out[r.String("repo")] = true
	}
	return out, nil
}
