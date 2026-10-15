package corrosion

import (
	"context"
)

// StackFileWants reads, from a live stack's deployed compose YAML, whether
// it asks for the cluster default-deny and which backup repos it uses
// (compose.StoredStackWants). The data layer takes it from its caller rather
// than parsing compose files itself.
type StackFileWants func(composeYAML string) (defaultDeny bool, repos map[string]bool, err error)

// stackWants is what one other live stack's file asks for.
type stackWants struct {
	name        string
	updatedAt   string // the stack record's LWW key
	defaultDeny bool
	repos       map[string]bool
}

// otherStackWants returns what every live stack other than stack asks for,
// in name order, for handing a row stack owns to another stack whose file
// asks for it too. A stack being deleted asks for nothing. unreadable names
// the stacks whose stored file cannot be read, which may ask for anything.
func otherStackWants(ctx context.Context, c *Client, stack string, read StackFileWants) (out []stackWants, unreadable []string, err error) {
	stacks, err := ListStacks(ctx, c)
	if err != nil {
		return nil, nil, err
	}
	for _, st := range stacks {
		if st.Name == stack || st.State == "deleting" {
			continue
		}
		if read == nil {
			unreadable = append(unreadable, st.Name)
			continue
		}
		deny, repos, rerr := read(st.ComposeYAML)
		if rerr != nil {
			unreadable = append(unreadable, st.Name)
			continue
		}
		out = append(out, stackWants{name: st.Name, updatedAt: st.UpdatedAt, defaultDeny: deny, repos: repos})
	}
	return out, unreadable, nil
}

// handOff gives a row stack owns to the first of heirs (in order) that is
// still live, and not being deleted, once it holds the row: set writes the
// row for an owner. Teardowns are not serialised, so an heir read as live
// may have gone down since; it is passed over. When no heir holds it, a row
// that was moved is set back to stack, so stack's own tombstone removes it
// rather than leaving it with a gone owner. It reports whether an heir took
// the row.
func handOff(ctx context.Context, c *Client, stack string, heirs []string, set func(owner string) error) (bool, error) {
	moved := false
	for _, name := range heirs {
		if err := set(name); err != nil {
			return false, err
		}
		moved = true
		st, err := GetStack(ctx, c, name)
		if err != nil {
			return false, err
		}
		if st != nil && st.State != "deleting" {
			return true, nil
		}
	}
	if moved {
		if err := set(stack); err != nil {
			return false, err
		}
	}
	return false, nil
}

// SweepOrphanStackRows finds the cluster default-deny row and the backup repo
// registrations owned by a stack that was torn down (its record is a
// tombstone) and that its teardown left behind, e.g. handed to it by a
// concurrent teardown that read it as live. Each such owner's rows are handed
// to a live stack that asks for them, or removed, as that stack's teardown
// would (DeleteStackFirewallDefaults, DeleteStackBackupRepos). Only a row
// last written no later than the owner's tombstone counts: a row written
// after it belongs to a new deploy of that name, which has no record until
// it ends. A row with no stack name (an operator's) is never touched, and no
// repo path is.
func SweepOrphanStackRows(ctx context.Context, c *Client, read StackFileWants) error {
	type owned struct {
		deny, repos bool
		newest      string
	}
	owners := map[string]*owned{}
	note := func(stack, updatedAt string) *owned {
		o := owners[stack]
		if o == nil {
			o = &owned{}
			owners[stack] = o
		}
		if o.newest == "" || lwwOrder(o.newest, updatedAt) < 0 {
			o.newest = updatedAt
		}
		return o
	}
	rows, err := c.Query(ctx, `SELECT stack_name, updated_at FROM firewall_defaults
		WHERE scope = 'cluster' AND deleted_at IS NULL AND default_deny = 1 AND stack_name IS NOT NULL AND stack_name != ''`)
	if err != nil {
		return err
	}
	for _, r := range rows {
		note(r.String("stack_name"), r.String("updated_at")).deny = true
	}
	rows, err = c.Query(ctx, `SELECT stack_name, updated_at FROM backup_repos
		WHERE deleted_at IS NULL AND stack_name IS NOT NULL AND stack_name != ''`)
	if err != nil {
		return err
	}
	for _, r := range rows {
		note(r.String("stack_name"), r.String("updated_at")).repos = true
	}
	for stack, o := range owners {
		rec, err := c.Query(ctx, `SELECT updated_at, deleted_at FROM stacks WHERE name = ?`, stack)
		if err != nil {
			return err
		}
		if len(rec) == 0 || rec[0].String("deleted_at") == "" {
			continue // live, or never recorded (a first deploy, in flight or failed)
		}
		if lwwOrder(o.newest, rec[0].String("updated_at")) > 0 {
			continue // written after the teardown: a new deploy of the name
		}
		if o.deny {
			if err := DeleteStackFirewallDefaults(ctx, c, stack, read); err != nil {
				return err
			}
		}
		if o.repos {
			if err := DeleteStackBackupRepos(ctx, c, stack, read); err != nil {
				return err
			}
		}
	}
	return nil
}
