package corrosion

import (
	"context"
	"log/slog"
	"sort"
	"sync"
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
	// recorded is set when a caller with sg.write recorded the stack's
	// firewall intent, which then arbitrates its ask (otherStackWants).
	recorded bool
}

// otherStackWants returns what every live stack other than stack asks for,
// in name order, for handing a row stack owns to another stack whose file
// asks for it too. A stack being deleted asks for nothing by its file.
// unreadable names the stacks whose stored file cannot be read, which may
// ask for anything.
//
// A live stack's file asks unless an intent recorded after its record says
// otherwise.
//
// A stack whose standing firewall intent asks for the default-deny
// (StackFirewallIntent) asks for it whatever its state: live, being torn
// down, or torn down by a teardown without sg.write at the root, which a
// node whose replica held an older file (or none of the intent) may have
// begun. Those not live are listed after the live ones, by name, with
// nothing else asked for.
func otherStackWants(ctx context.Context, c *Client, stack string, read StackFileWants) (out []stackWants, unreadable []string, err error) {
	stacks, err := ListStacks(ctx, c)
	if err != nil {
		return nil, nil, err
	}
	// A stack asks for the default-deny when its file does, or when its last
	// deploy by a caller with sg.write at the root did (StackFirewallIntent):
	// a deploy without it, from a node holding an older file, does not
	// withdraw the ask.
	intents, err := StackFirewallIntents(ctx, c)
	if err != nil {
		return nil, nil, err
	}
	stamped, err := stackFirewallIntentStamps(ctx, c)
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
		// An intent recorded after the stack's record is an Admin's later
		// word than its file: a redeploy dropping the deny records it before
		// it removes the row, and its old file, still in the record until
		// the deploy ends, does not ask for the deny back. Otherwise the
		// file asks too.
		in, recorded := stamped[st.Name]
		if recorded && lwwOrder(st.UpdatedAt, in.at) < 0 {
			deny = false
		}
		deny = deny || intents[st.Name].DefaultDeny
		out = append(out, stackWants{name: st.Name, updatedAt: st.UpdatedAt, defaultDeny: deny, repos: repos, recorded: recorded})
	}
	listed := make(map[string]bool, len(out)+len(unreadable))
	for _, w := range out {
		listed[w.name] = true
	}
	for _, n := range unreadable {
		listed[n] = true
	}
	var standing []string
	for name, in := range intents {
		if in.DefaultDeny && name != stack && !listed[name] {
			standing = append(standing, name)
		}
	}
	sort.Strings(standing)
	for _, name := range standing {
		rec, err := c.Query(ctx, `SELECT updated_at FROM stacks WHERE name = ?`, name)
		if err != nil {
			return nil, nil, err
		}
		at := ""
		if len(rec) > 0 {
			at = rec[0].String("updated_at")
		}
		out = append(out, stackWants{name: name, updatedAt: at, defaultDeny: true, recorded: true})
	}
	return out, unreadable, nil
}

// handOff gives a row stack owns to the first of heirs (in order) that is
// still live, and not being deleted, once it holds the row: set writes the
// row for an owner. Teardowns are not serialised, so an heir read as live
// may have gone down since; it is passed over. When no heir holds it, a row
// that was moved is set back to stack, so stack's own tombstone removes it
// rather than leaving it with a gone owner. It reports whether an heir took
// the row. standing, when not nil, also accepts an heir that is not live
// (standingDenyAsk).
func handOff(ctx context.Context, c *Client, stack string, heirs []string, set func(owner string) error,
	standing func(context.Context, *Client, string) (bool, error)) (bool, error) {
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
		if standing != nil {
			if ok, err := standing(ctx, c, name); err != nil {
				return false, err
			} else if ok {
				return true, nil
			}
		}
	}
	if moved {
		if err := set(stack); err != nil {
			return false, err
		}
	}
	return false, nil
}

// SweepOrphanStackRows looks after the cluster default-deny row and the
// backup repo registrations still owned by a stack that was torn down (its
// record is a tombstone), e.g. handed to it by a concurrent teardown that read
// it as live, or left by an older build's teardown.
//
// The deny is handed to a live stack that asks for it, and is otherwise KEPT:
// the sweep runs unattended, and removing an in-force deny would open the
// cluster with no one having asked. Its owner is returned as orphanDeny so the
// caller can say so; `lv firewall default-deny off` removes it.
//
// A repo registration is handed on or removed as the owner's teardown would
// (DeleteStackBackupRepos), but only when no row of that owner was written
// after its tombstone: such a row belongs to a new deploy of the name, which
// has no record until it ends. No repo path is touched.
//
// A row with no stack name (an operator's), and a row of a stack never
// recorded (a first deploy, in flight or failed), are never touched.
func SweepOrphanStackRows(ctx context.Context, c *Client, read StackFileWants) (orphanDeny string, err error) {
	// tombstoned reports whether stack has a tombstoned record and no live
	// one, and the tombstone's LWW key.
	tombstoned := func(stack string) (bool, string, error) {
		rec, err := c.Query(ctx, `SELECT updated_at, deleted_at FROM stacks WHERE name = ?`, stack)
		if err != nil {
			return false, "", err
		}
		if len(rec) == 0 || rec[0].String("deleted_at") == "" {
			return false, "", nil // live, or never recorded
		}
		return true, rec[0].String("updated_at"), nil
	}

	cur, err := GetFirewallDefault(ctx, c, "cluster")
	if err != nil {
		return "", err
	}
	if cur != nil && cur.DefaultDeny && cur.StackName != "" {
		gone, _, err := tombstoned(cur.StackName)
		if err != nil {
			return "", err
		}
		// A torn-down owner whose standing intent asks for the deny keeps it
		// (stack.firewall_teardown_held names it): handing it to another
		// such stack would hand it back on that one's pass.
		standing := false
		if gone {
			if standing, err = standingDenyAsk(ctx, c, cur.StackName); err != nil {
				return "", err
			}
		}
		if gone && !standing {
			others, _, err := otherStackWants(ctx, c, cur.StackName, read)
			if err != nil {
				return "", err
			}
			var heirs []string
			for _, o := range others {
				if o.defaultDeny {
					heirs = append(heirs, o.name)
				}
			}
			handed, err := handOff(ctx, c, cur.StackName, heirs, func(owner string) error {
				return SetFirewallDefault(ctx, c, "cluster", true, owner)
			}, standingDenyAsk)
			if err != nil {
				return "", err
			}
			if !handed {
				orphanDeny = cur.StackName
			}
		}
	}

	rows, err := c.Query(ctx, `SELECT stack_name, updated_at FROM backup_repos
		WHERE deleted_at IS NULL AND stack_name IS NOT NULL AND stack_name != ''`)
	if err != nil {
		return orphanDeny, err
	}
	newest := map[string]string{}
	for _, r := range rows {
		st, at := r.String("stack_name"), r.String("updated_at")
		if n, ok := newest[st]; !ok || lwwOrder(n, at) < 0 {
			newest[st] = at
		}
	}
	for stack, at := range newest {
		gone, tomb, err := tombstoned(stack)
		if err != nil {
			return orphanDeny, err
		}
		if !gone || lwwOrder(at, tomb) > 0 {
			continue // live, never recorded, or a new deploy of the name
		}
		if err := DeleteStackBackupRepos(ctx, c, stack, read); err != nil {
			return orphanDeny, err
		}
	}
	return orphanDeny, nil
}

// changeLog logs a warning for key only when what it says changed since the
// last one for key, so a condition a loop meets on every pass is said once.
var changeLog = struct {
	sync.Mutex
	last map[string]string
}{last: map[string]string{}}

func warnOnChange(key, state, msg string, args ...any) {
	changeLog.Lock()
	same := changeLog.last[key] == state
	changeLog.last[key] = state
	changeLog.Unlock()
	if !same {
		slog.Warn(msg, args...)
	}
}
