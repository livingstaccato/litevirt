package corrosion

import "context"

// FirewallTagWorkload binds a tag operation to the live owner/incarnation it
// routed to. It grants no permission: the feature and sg.write checks remain
// separate. Private fields prevent callers from assembling partial predicates.
type FirewallTagWorkload struct {
	kind, host, name, created    string
	expectedID                   string
	epoch                        int64
	tagsBound                    bool
	tagsVersion, tagsRaw, tagsBy string
}

// ReadFirewallTagWorkload captures the current live row only if owner is still
// its owner. The caller retains this value across gate/lock waits and every
// irreversible clear, mint and tags write.
func ReadFirewallTagWorkload(ctx context.Context, c *Client, kind, host, name, owner string) (FirewallTagWorkload, error) {
	w, _, err := readFirewallTagWorkload(ctx, c, kind, host, name)
	if err != nil {
		return FirewallTagWorkload{}, err
	}
	if w.host != owner {
		return FirewallTagWorkload{}, ErrFirewallIDNotMinted
	}
	return w, nil
}

func readFirewallTagWorkload(ctx context.Context, r rowQuerier, kind, host, name string) (FirewallTagWorkload, string, error) {
	var rows []Row
	var err error
	switch kind {
	case TagMemberVM:
		rows, err = r.Query(ctx, `SELECT host_name, created_at, vm_owner_epoch AS epoch, active_operation_id, spec AS doc FROM vms WHERE name = ? AND deleted_at IS NULL`, name)
	case TagMemberCT:
		rows, err = r.Query(ctx, `SELECT host_name, created_at, owner_epoch AS epoch, COALESCE(active_operation_id, '') AS active_operation_id, COALESCE(create_spec, '') AS doc FROM containers WHERE host_name = ? AND name = ? AND deleted_at IS NULL`, host, name)
	default:
		return FirewallTagWorkload{}, "", ErrFirewallIDNotMinted
	}
	if err != nil {
		return FirewallTagWorkload{}, "", err
	}
	if len(rows) != 1 || rows[0].String("active_operation_id") != "" {
		return FirewallTagWorkload{}, "", ErrFirewallIDNotMinted
	}
	row := rows[0]
	return FirewallTagWorkload{kind: kind, host: row.String("host_name"), name: name, created: row.String("created_at"), epoch: row.Int64("epoch")}, row.String("doc"), nil
}

func (w FirewallTagWorkload) check(ctx context.Context, r rowQuerier) (string, error) {
	now, doc, err := readFirewallTagWorkload(ctx, r, w.kind, w.host, w.name)
	if err != nil {
		return "", err
	}
	if now.kind != w.kind || now.host != w.host || now.name != w.name || now.created != w.created || now.epoch != w.epoch {
		return "", ErrFirewallIDNotMinted
	}
	return doc, nil
}

func checkFirewallTagWorkloads(ctx context.Context, r rowQuerier, owners []FirewallTagWorkload) error {
	for _, w := range owners {
		if _, err := w.check(ctx, r); err != nil {
			return err
		}
	}
	return nil
}

// WithTagsRecord binds the later RMW to the exact row the RPC merged.
func (w FirewallTagWorkload) WithTagsRecord(r FirewallTagsRecord) FirewallTagWorkload {
	w.tagsBound = true
	w.tagsVersion, w.tagsRaw, w.tagsBy = r.UpdatedAt, r.rawValue, r.SetBy
	return w
}

// WithFirewallID binds a copied-identity clear to the workload identity observed
// before the clear, or to the replacement identity the mint just committed.
func (w FirewallTagWorkload) WithFirewallID(id string) FirewallTagWorkload {
	w.expectedID = id
	return w
}
