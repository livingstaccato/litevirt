package network

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// ReserveContainerIP claims (network, ip) for a container WITHOUT stealing it.
// It succeeds (reserved=true) only when the address is FREE, TOMBSTONED (a
// released lease — resurrected), or already held by THIS exact owner
// (ct, host, ctName) — an idempotent re-reserve. It deliberately does NOT
// "transfer" a live lease held by a same-named container on ANOTHER host: v36
// makes CT names per-host, so that may be a different workload — we can't prove
// it's ours, so we never overwrite it (the read-back returns reserved=false and
// the caller degrades to a blank IP). Cross-host lease MOVES are done explicitly
// by the mover, which knows the full prior owner.
//
// The lease is keyed on the bare host address (LeaseAddr): "10.0.0.5/24" and
// "10.0.0.5" are one address, so they are one lease. Live rows written before
// that normalisation can still be keyed with a prefix, so they are checked here
// at read time — a live lease on the same host address held by anyone else
// refuses the reserve — rather than rewritten.
func ReserveContainerIP(ctx context.Context, db *corrosion.Client, network, ip, mac, host, ctName string) (bool, error) {
	ip = LeaseAddr(ip)
	if others, err := hostAddrHoldersOther(ctx, db, network, ip, "ct", host, ctName); err != nil || len(others) > 0 {
		return false, err
	}
	return reserveContainerLease(ctx, db, network, ip, mac, host, ctName)
}

// ReserveContainerIPForRebuild re-reserves an address a container ALREADY had
// (its own create spec or interface row): a restore, a relocation.
//
// It refuses everything a rebuild was refused before this release — the same
// address text held live by another owner — and, beyond that, tolerates
// exactly one thing: an alias that release allowed and that THIS container was
// already part of. Before this release leases were keyed on the operator's
// text, so "x/24" and "x" could be held by two workloads at once, and each
// kept its address on every rebuild. Refusing that now would strip a static
// address from a workload on its next restore or failover.
//
// "Already part of it" is proved from the lease table, never assumed from the
// spelling:
//   - a row keyed with this exact text must exist for this container (any
//     host, live or tombstoned) — a copy restored elsewhere, or a container
//     that never held the address, has none — and the container row on that
//     row's host must be in this container's project (LeaseProof), so a
//     same-named container of another project is not mistaken for it;
//   - no other live holder may be a same-named container (the original of a
//     copy being restored beside it);
//   - if that row was released, every other live holder must have acquired
//     its lease BEFORE the release (its updated_at is not newer) — an address
//     reallocated after this container let it go belongs to the new holder.
//
// The kept lease is written under the canonical key when no other holder has
// it, otherwise under this container's own prior key. The duplicate is logged
// as a WARN naming both owners so an operator can reassign one. A NEW
// allocation (ReserveContainerIP) is always refused.
func ReserveContainerIPForRebuild(ctx context.Context, db *corrosion.Client, network, ip, mac, host, ctName string, proof LeaseProof) (bool, error) {
	raw := strings.TrimSpace(ip)
	norm := LeaseAddr(raw)
	others, err := hostAddrHoldersOther(ctx, db, network, norm, "ct", host, ctName)
	if err != nil {
		return false, err
	}
	if len(others) == 0 {
		return reserveContainerLease(ctx, db, network, norm, mac, host, ctName)
	}
	normTaken := false
	for _, o := range others {
		if o.IP == raw {
			// The same text held by another owner: refused before this
			// release too, and not a duplicate this rebuild keeps.
			return false, nil
		}
		if o.Kind == "ct" && o.Name == ctName {
			return false, nil // the original of a copy restored beside it
		}
		if o.IP == norm {
			normTaken = true
		}
	}
	prior, err := priorContainerLease(ctx, db, network, raw, ctName)
	if err != nil || prior == nil {
		return false, err
	}
	// The prior row names the container only by (host, name). Bind it to THIS
	// container's project through the container row on the prior row's host —
	// as it was before this rebuild wrote anything there, when that host is
	// this one — so a same-named container of another project is not "it".
	ownerProject, known := proof.HereProject, proof.HereKnown
	if prior.OwnerHost != host {
		if ownerProject, known, err = corrosion.ContainerProjectAnyState(ctx, db, prior.OwnerHost, ctName); err != nil {
			return false, err
		}
	}
	if !known || normProject(ownerProject) != normProject(proof.Project) {
		return false, nil
	}
	if prior.Deleted {
		for _, o := range others {
			if corrosion.LWWNewer(o.UpdatedAt, prior.UpdatedAt) {
				return false, nil // acquired after this container released it
			}
		}
	}
	for _, o := range others {
		slog.Warn("container IP is shared with another workload (allowed before this release); "+
			"keeping it for this rebuild — reassign one of them",
			"network", network, "ip", norm, "ct", ctName, "host", host,
			"other", o.Name, "other_kind", o.Kind, "other_host", o.Host)
	}
	key := norm
	if normTaken {
		key = raw
	}
	return reserveContainerLease(ctx, db, network, key, mac, host, ctName)
}

// LeaseProof identifies the container a rebuild is for beyond its name:
// its project, and the project of the container row on the rebuilding host
// as it was BEFORE the rebuild wrote its own row there (a restore overwrites
// a tombstoned row of the same name). HereKnown is false when there was none.
type LeaseProof struct {
	Project     string
	HereProject string
	HereKnown   bool
}

// priorLease is a container's earlier lease row on one address text.
type priorLease struct {
	Deleted   bool
	UpdatedAt string
	OwnerHost string
}

// priorContainerLease returns the row keyed exactly (network, ip) if it was
// last held by a container named ctName (on any host), live or tombstoned.
func priorContainerLease(ctx context.Context, db *corrosion.Client, network, ip, ctName string) (*priorLease, error) {
	rows, err := db.Query(ctx,
		`SELECT updated_at, deleted_at, COALESCE(owner_host, '') AS owner_host FROM ip_allocations
		 WHERE network = ? AND ip = ? AND owner_kind = 'ct' AND vm_name = ?`, network, ip, ctName)
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	return &priorLease{
		Deleted: rows[0].String("deleted_at") != "", UpdatedAt: rows[0].String("updated_at"),
		OwnerHost: rows[0].String("owner_host"),
	}, nil
}

// reserveContainerLease writes (or resurrects, or idempotently refreshes) the
// lease keyed key for (ct, host, ctName), never touching a live lease of
// another owner, and reports whether this owner holds it afterwards.
func reserveContainerLease(ctx context.Context, db *corrosion.Client, network, ip, mac, host, ctName string) (bool, error) {
	now := db.NowTS()
	allocAt := time.Now().UTC().Format(time.RFC3339)
	// Resurrect a tombstone, or idempotently refresh OUR OWN live lease; never
	// touch a live lease owned by anyone else (the guarded UPDATE no-ops, which
	// the read-back detects).
	if err := db.Execute(ctx,
		`INSERT INTO ip_allocations (network, ip, mac, vm_name, owner_kind, owner_host, allocated_at, updated_at)
		 VALUES (?, ?, ?, ?, 'ct', ?, ?, ?)
		 ON CONFLICT(network, ip) DO UPDATE SET
		   mac = excluded.mac, vm_name = excluded.vm_name, owner_kind = excluded.owner_kind,
		   owner_host = excluded.owner_host, updated_at = excluded.updated_at, deleted_at = NULL
		 WHERE ip_allocations.deleted_at IS NOT NULL
		    OR (ip_allocations.owner_kind = 'ct'
		        AND ip_allocations.vm_name = excluded.vm_name
		        AND ip_allocations.owner_host = excluded.owner_host)`,
		network, ip, mac, ctName, host, allocAt, now); err != nil {
		return false, err
	}
	return ipLeaseHeldBy(ctx, db, network, ip, "ct", host, ctName)
}

// ReleaseContainerLeases tombstones ALL of a container's IPAM leases on a host
// (across every network), without needing the interface rows. Used to roll back a
// failed create and as the delete cascade.
func ReleaseContainerLeases(ctx context.Context, db *corrosion.Client, host, ctName string) error {
	now := db.NowTS()
	return db.Execute(ctx,
		`UPDATE ip_allocations SET deleted_at = ?, updated_at = ?
		 WHERE owner_kind = 'ct' AND owner_host = ? AND vm_name = ? AND deleted_at IS NULL`,
		db.NowWall(), now, host, ctName)
}

// TransferContainerLeases re-homes ALL of a container's live IPAM leases from
// fromHost to toHost (owner_host: fromHost→toHost), keyed on the FULL prior owner
// (ct, fromHost, ctName) so it's precise — never touches a same-named container
// on a third host. The mover (migrate) uses it for an explicit cross-host handoff,
// which ReserveContainerIP deliberately won't infer. Returns the number of leases
// moved so the caller can assert the handoff was complete (every held lease).
//
// allocated_at is RESET to now on the new owner: the orphan-lease GC keys off the
// lease's age, so a transferred lease (which keeps its original, possibly old,
// timestamp) must restart its age clock on the target — otherwise the target's GC
// could immediately reclaim it in the brief window before the migrated container
// row is visible there.
func TransferContainerLeases(ctx context.Context, db *corrosion.Client, fromHost, toHost, ctName string) (int64, error) {
	now := db.NowTS()
	allocAt := time.Now().UTC().Format(time.RFC3339)
	return db.ExecuteRows(ctx,
		`UPDATE ip_allocations SET owner_host = ?, allocated_at = ?, updated_at = ?
		 WHERE owner_kind = 'ct' AND owner_host = ? AND vm_name = ? AND deleted_at IS NULL`,
		toHost, allocAt, now, fromHost, ctName)
}

// ContainerLeasesOwnedBy reports whether (ct, host, ctName) owns the live IPAM
// lease for EVERY non-empty IP among ifaces — the per-NIC handoff invariant the
// migrate finaliser checks both BEFORE and AFTER the lease transfer. A managed NIC
// whose IP has no live lease, or whose lease is held by another owner, makes it
// return false. This is stricter than counting leases: a count can't catch a
// container_interfaces / create-spec NIC whose IP was never (or is no longer)
// backed by a source lease — exactly the case where the target, skipping
// re-reservation on a verified migrate, would otherwise start an unowned/
// conflicting address.
func ContainerLeasesOwnedBy(ctx context.Context, db *corrosion.Client, host, ctName string, ifaces []corrosion.ContainerInterfaceRecord) (bool, error) {
	for _, ifc := range ifaces {
		if ifc.IP == "" {
			continue
		}
		ok, err := ipLeaseHeldBy(ctx, db, ifc.NetworkName, ifc.IP, "ct", host, ctName)
		if err != nil {
			return false, err
		}
		if !ok {
			return false, nil
		}
	}
	return true, nil
}

// ReleaseOrphanContainerLeases tombstones CT leases on host whose owner has no
// live container row AND that are older than minAge — i.e. leases stranded by a
// daemon crash between allocating a lease and persisting the container row. The
// age guard keeps it from racing an in-flight create (which holds the name lock
// and finishes in seconds). Returns how many it released.
func ReleaseOrphanContainerLeases(ctx context.Context, db *corrosion.Client, host string, live map[string]bool, minAge time.Duration) (int, error) {
	cutoff := time.Now().Add(-minAge).UTC().Format(time.RFC3339)
	rows, err := db.Query(ctx,
		`SELECT DISTINCT vm_name FROM ip_allocations
		 WHERE owner_kind = 'ct' AND owner_host = ? AND deleted_at IS NULL AND allocated_at < ?`,
		host, cutoff)
	if err != nil {
		return 0, err
	}
	released := 0
	for _, r := range rows {
		name := r.String("vm_name")
		if live[name] {
			continue
		}
		if err := ReleaseContainerLeases(ctx, db, host, name); err != nil {
			return released, err
		}
		slog.Warn("released orphan container IPAM lease (no live container row)", "host", host, "ct", name)
		released++
	}
	return released, nil
}

// ReserveContainerNICs re-reserves the IPs of a re-homed container's managed
// interface rows on this host (restore). It runs AFTER the rows are written. For
// each NIC with an IP it conditionally reserves the address; if it can't (held by
// another workload), the row's IP is BLANKED (we never assert an address we don't
// own) and it's counted as unreserved so the caller can refuse to start the
// container (its imported on-disk config still names that IP — booting it would
// cause the conflict the DB is avoiding). Best-effort on errors; returns the
// number of NICs left unreserved + the first error.
func ReserveContainerNICs(ctx context.Context, db *corrosion.Client, host, ctName string, proof LeaseProof, ifaces []corrosion.ContainerInterfaceRecord) (unreserved int, firstErr error) {
	for _, ifc := range ifaces {
		if ifc.IP == "" {
			continue
		}
		reserved, err := ReserveContainerIPForRebuild(ctx, db, ifc.NetworkName, ifc.IP, ifc.MAC, host, ctName, proof)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			unreserved++
			continue
		}
		if !reserved {
			slog.Warn("container rebuild: IP held by another workload; blanking NIC (will be re-discovered)",
				"ct", ctName, "host", host, "network", ifc.NetworkName, "ip", ifc.IP)
			unreserved++
			if e := corrosion.UpdateContainerInterfaceIP(ctx, db, host, ctName, ifc.Ordinal, ""); e != nil && firstErr == nil {
				firstErr = e
			}
		}
	}
	return unreserved, firstErr
}

// leaseHolder is one live lease's owner and its stored address text.
type leaseHolder struct {
	IP, Name, Kind, Host, UpdatedAt string
}

// hostAddrHoldersOther returns the LIVE leases on network that name the same
// host address as ip under any spelling and are owned by someone other than
// (kind, host, name). It is the read-time half of the non-aliasing guarantee:
// the (network, ip) primary key only catches an identical spelling.
func hostAddrHoldersOther(ctx context.Context, db *corrosion.Client, network, ip, ownerKind, ownerHost, name string) ([]leaseHolder, error) {
	rows, err := db.Query(ctx,
		`SELECT ip, vm_name, COALESCE(owner_kind, 'vm') AS owner_kind, COALESCE(owner_host, '') AS owner_host, updated_at
		 FROM ip_allocations WHERE network = ? AND deleted_at IS NULL`, network)
	if err != nil {
		return nil, err
	}
	want := LeaseAddr(ip)
	var out []leaseHolder
	for _, r := range rows {
		if LeaseAddr(r.String("ip")) != want {
			continue
		}
		h := leaseHolder{IP: r.String("ip"), Name: r.String("vm_name"), Kind: r.String("owner_kind"), Host: r.String("owner_host"), UpdatedAt: r.String("updated_at")}
		if h.Name == name && h.Kind == ownerKind && h.Host == ownerHost {
			continue
		}
		out = append(out, h)
	}
	return out, nil
}

func normProject(p string) string {
	if p == "" {
		return corrosion.DefaultProject
	}
	return p
}
