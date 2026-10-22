package corrosion

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/fence"
)

// HostRecord represents a host in the cluster.
type HostRecord struct {
	Name          string
	Address       string
	SSHUser       string
	SSHPort       int
	GRPCPort      int
	State         string
	CertSerial    string
	CPUTotal      int
	MemTotal      int
	DiskTotal     int
	FenceStrategy string
	// IPMI fields — optional; only used when fence_strategy = "ipmi"
	IPMIAddress string
	IPMIUser    string
	IPMIPass    string
	// IPMIPassRetired reports that the host's fence credential row is a
	// tombstone: retired by a removal or re-admission and not set since.
	// IPMIPass is then empty, never the old hosts.ipmi_pass column.
	IPMIPassRetired bool
	// Redfish — only used when fence_strategy = "redfish". Read from the
	// host's live host_fence_redfish row (host_fence_redfish.go), never from
	// the hosts row.
	Redfish     fence.RedfishConfig
	WatchdogDev string
	Labels      map[string]string // decoded from JSON column
	Version     string
	// SchemaVersion is the host's running-binary supported schema version (the
	// value its Ping returns — that binary's CurrentSchemaVersion, NOT its
	// DB-applied EffectiveDBSchema). Persisted so the self-upgrade watcher can
	// read peer (version, schema) locally instead of pinging every peer. 0 =
	// unknown (a host that hasn't written it yet) → never an upgrade source.
	SchemaVersion int
	// Role distinguishes "worker" hosts (run VMs, vote in quorum) from
	// "witness" hosts (vote only, never host workloads). Default "worker".
	// See docs/operating-model.md for guidance on even-N deployments.
	Role string
	// Region is the host's failure-domain label (DC, rack, AZ). Used
	// by ListRegions / RegionStatus / CrossRegionMigrate. Hosts in the
	// same region share fate at the network/power level; cross-region
	// migration is the multi-DC handoff. Default "default" — single-
	// region clusters are unaffected.
	Region string
	// Capacity policy overrides. Each falls back to the CLUSTER default when
	// unset, so a heterogeneous fleet can differ per host — e.g. a node with swap
	// and KSM may overcommit memory while its peers must not.
	//
	// Ratios use 0 for "inherit" — a 0 ratio is never meaningful, so it is a safe
	// sentinel. Reserves are POINTERS because 0 IS meaningful (hand guests every
	// last MiB), and a plain int cannot tell that from an unset field. That
	// distinction is not academic: with -1-means-unset, every zero-valued
	// HostRecord literal silently overrode the cluster reserve to 0 and disabled
	// the host headroom entirely. nil = inherit.
	CPUOvercommit float64 // vCPU oversubscription multiplier (0 = inherit)
	MemOvercommit float64 // memory oversubscription multiplier (0 = inherit)
	CPUReserve    *int    // vCPUs held back for the host itself (nil = inherit)
	MemReserveMiB *int    // MiB held back for the host itself (nil = inherit)
	// CapacityPolicyHash is the stable fingerprint of the admission policy this
	// host advertises. Empty means unknown/legacy.
	CapacityPolicyHash string
	CreatedAt          string
	UpdatedAt          string
}

// optInt reads an optional INTEGER override column. The stored sentinel for
// "not configured" is -1 (a real 0 is a meaningful reserve), and an absent column
// — an older SELECT, or a DB predating the migration — is also unset.
func optInt(r Row, col string) *int {
	if r.get(col) == nil {
		return nil
	}
	v := r.Int(col)
	if v < 0 {
		return nil
	}
	return &v
}

// optIntValue encodes an optional override for storage: nil → -1 ("inherit the
// cluster default"), which is distinct from a stored 0 (a real "no reserve").
func optIntValue(p *int) int {
	if p == nil {
		return -1
	}
	return *p
}

// IsWitness returns true if the host is a tiebreaker/witness, not a worker.
func (h HostRecord) IsWitness() bool { return h.Role == "witness" }

// InsertHost creates a new host record.
func InsertHost(ctx context.Context, c *Client, h HostRecord) error {
	return insertHost(ctx, c, h, false)
}

// insertHost is InsertHost; exclusive is an admission's, which applies only
// while no other host holds h's address (admissionGuard).
func insertHost(ctx context.Context, c *Client, h HostRecord, exclusive bool) error {
	// created_at is the row's incarnation, in the same fixed-width form as a
	// re-admission's stamp (host_readmit.go, THE INCARNATION): a machine
	// re-added on an empty database inserts its row after its admission, and
	// whole-second truncation would move that insert toward the stamp.
	now := time.Now().UTC().Format(nowTSLayout)
	role := h.Role
	if role == "" {
		role = "worker"
	}
	return c.withMembershipWrite(ctx, func(live bool) error {
		return c.withRuntimeWrite(ctx, func(liveRuntime bool) error {
			uts := c.NowTS()
			params := []interface{}{
				h.Name, h.Address, h.SSHUser, h.SSHPort, h.GRPCPort, h.State, h.CertSerial,
				h.CPUTotal, h.MemTotal, h.DiskTotal, h.FenceStrategy, h.Version, role,
				h.CPUOvercommit, h.MemOvercommit, optIntValue(h.CPUReserve), optIntValue(h.MemReserveMiB),
				h.CapacityPolicyHash,
				now, uts,
			}
			if !live && !liveRuntime {
				if exclusive {
					var held string
					applied, err := c.ExecuteBatchGuarded(ctx, admissionGuard(ctx, h, &held), []Statement{{SQL: insertHostSQL, Params: params}})
					return admissionResult(h, held, applied, err)
				}
				return c.Execute(ctx, insertHostSQL, params...)
			}
			// After a split the new host's membership and runtime rows are
			// written with it, under the same updated_at. The hosts row
			// still carries the initial values: it is created whole, so there
			// is no other column to lose. Its schema_version is the column
			// default, so the runtime row's is too.
			stmts := []Statement{{SQL: insertHostSQL, Params: params}}
			if live {
				stmts = append(stmts, Statement{SQL: hostMembershipUpsertSQL, Params: []interface{}{h.Name, h.State, int64(0), "", uts}})
			}
			if liveRuntime {
				stmts = append(stmts, Statement{SQL: hostRuntimeUpsertSQL, Params: runtimeParams(h.Name, runtimeVals{
					Version: h.Version, CPU: someInt(h.CPUTotal), Mem: someInt(h.MemTotal), Disk: someInt(h.DiskTotal),
					PolicyHash: h.CapacityPolicyHash,
				}, uts)})
			}
			if exclusive {
				var held string
				applied, err := c.ExecuteBatchGuarded(ctx, admissionGuard(ctx, h, &held), stmts)
				return admissionResult(h, held, applied, err)
			}
			return c.ExecuteBatch(ctx, stmts)
		})
	})
}

const insertHostSQL = `INSERT INTO hosts (name, address, ssh_user, ssh_port, grpc_port, state, cert_serial,
			cpu_total, mem_total, disk_total, fence_strategy, version, role,
			cpu_overcommit, mem_overcommit, cpu_reserve, mem_reserve_mib,
			capacity_policy_hash,
			created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

// ValidHostAddress reports whether s is a bare IPv4 literal, which is the only
// thing hosts.address is allowed to be.
//
// The column is replicated and peer-writable, and it is consumed by code that
// builds remote command lines and dial targets from it. `lv host add`
// interpolated it into an SSH exec request, which sshd runs through the login
// shell, so a row containing `$(...)` executed as root on every host added
// afterwards. That call site is quoted now; this makes the value unable to
// carry a payload at all.
//
// Requiring IPv4 costs nothing that was ever supported: cluster transport is
// IPv4-only, and the daemon already refuses to start on a hostname, a
// host:port or an IPv6 literal.
func ValidHostAddress(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() != nil
}

// AdmitHost creates a host row or replaces a tombstone after an operator has
// issued a different certificate for the same name. A daemon cannot use its old
// certificate to resurrect itself: the old serial is retained in the tombstone
// and an equal serial is refused.
func AdmitHost(ctx context.Context, c *Client, h HostRecord) error {
	if h.Name == "" || h.Address == "" || h.CertSerial == "" || h.CertSerial == "unknown" {
		return fmt.Errorf("host admission requires name, address, and certificate serial")
	}
	// The address is consumed by code that builds dial targets and remote
	// command lines from it, so it must not be able to carry anything but an
	// address. See ValidHostAddress.
	if !ValidHostAddress(h.Address) {
		return fmt.Errorf("host admission: address %q is not a bare IPv4 literal", h.Address)
	}
	rows, err := c.Query(ctx, `SELECT cert_serial, deleted_at FROM hosts WHERE name = ?`, h.Name)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return insertHost(ctx, c, h, true)
	}
	if rows[0].String("deleted_at") == "" {
		if strings.EqualFold(rows[0].String("cert_serial"), h.CertSerial) {
			// A retry of this admission writes nothing, so no guard runs:
			// the address is checked here, by the rule activation follows.
			lostTo, err := AddressLostTo(ctx, c, h.Name)
			if err != nil {
				return err
			}
			if lostTo != "" {
				return &AddressHeldError{Address: h.Address, Port: h.GRPCPort, Holder: lostTo}
			}
			return nil
		}
		return fmt.Errorf("host %q is already active", h.Name)
	}
	if strings.EqualFold(rows[0].String("cert_serial"), h.CertSerial) {
		return fmt.Errorf("host %q cannot be re-admitted with its removed certificate", h.Name)
	}
	// A tombstone of a counted incarnation is re-admitted only by
	// AdmitHostV2, never by this legacy shape (host_incarnation.go): the
	// row would keep its number, and a stale copy of it would tie.
	if n, _, _, _, _, err := HostIncarnationOf(ctx, c, h.Name); err != nil {
		return err
	} else if n >= 1 {
		return fmt.Errorf("%w: host %q was removed at incarnation %d", ErrReadmitNeedsCounter, h.Name, n)
	}
	return c.withMembershipWrite(ctx, func(live bool) error {
		uts := c.NowTS()
		params := []interface{}{h.Address, h.SSHUser, h.SSHPort, h.GRPCPort, h.State, h.CertSerial, uts,
			h.Name, h.CertSerial}
		var held string
		if !live {
			applied, err := c.ExecuteBatchGuarded(ctx, admissionGuard(ctx, h, &held), []Statement{{SQL: readmitHostSQL, Params: params}})
			return admissionResult(h, held, applied, err)
		}
		// Re-admission rewrites the identity row whole, state included, and
		// the membership state goes with it under the same updated_at. The
		// host's isolation is kept, as it is on hosts.
		epoch, reason, err := currentIsolation(ctx, c, h.Name)
		if err != nil {
			return err
		}
		applied, err := c.ExecuteBatchGuarded(ctx, admissionGuard(ctx, h, &held), []Statement{
			{SQL: readmitHostSQL, Params: params},
			{SQL: hostMembershipStateSQL, Params: []interface{}{h.Name, h.State, epoch, reason, uts}},
		})
		return admissionResult(h, held, applied, err)
	})
}

// AddressHeldError refuses an admission at an address another live or
// joining host holds at the admitted gRPC port: one machine is admitted under
// one name.
type AddressHeldError struct {
	Address string
	Port    int
	Holder  string
}

func (e *AddressHeldError) Error() string {
	return fmt.Sprintf("%s:%d is %s's address", e.Address, e.Port, e.Holder)
}

// AsAddressHeld is the host an AddressHeldError in err names.
func AsAddressHeld(err error) (holder string, ok bool) {
	var e *AddressHeldError
	if errors.As(err, &e) {
		return e.Holder, true
	}
	return "", false
}

// hostAddressHolderSQL is the live or joining host other than name at
// address and port. A port of 0 (or NULL) is not known, so it matches any,
// on either side.
const hostAddressHolderSQL = `SELECT name FROM hosts WHERE address = ? AND name <> ? AND deleted_at IS NULL
	AND (? = 0 OR grpc_port = ? OR grpc_port = 0 OR grpc_port IS NULL) ORDER BY name LIMIT 1`

// HostAddressHolder is the live or joining host other than name that holds
// address at port, "" when none does, as this replica holds the table.
func HostAddressHolder(ctx context.Context, c *Client, address, name string, port int) (string, error) {
	rows, err := c.Query(ctx, hostAddressHolderSQL, address, name, port, port)
	if err != nil || len(rows) == 0 {
		return "", err
	}
	return rows[0].String("name"), nil
}

// addressContendersSQL reads the live or joining hosts that share name's
// address at one gRPC port (a port of 0 matches any), name included: each
// one's admission stamp and its resolved state.
const addressContendersSQL = `SELECT h.name AS name, COALESCE(h.created_at, '') AS created_at,
		COALESCE(h.state, '') AS h_state, COALESCE(m.host_name, '') AS m_host, COALESCE(m.state, '') AS m_state
	FROM hosts h` + membershipJoins + ` JOIN hosts me ON me.name = ?
	WHERE me.deleted_at IS NULL AND h.deleted_at IS NULL AND h.address = me.address AND h.address <> ''
	AND (COALESCE(h.grpc_port, 0) = 0 OR COALESCE(me.grpc_port, 0) = 0 OR h.grpc_port = me.grpc_port)`

type addressContender struct{ name, createdAt, state string }

// addressLostTo decides an address held by more than one live host, the
// same way on every replica that holds the same rows: a host recorded
// 'active' keeps it, whatever its stamp, so a host is never activated
// beside one that already is; otherwise the earliest admission (created_at)
// keeps it, the lesser name on a tie. It is the host name loses to, "" when
// name keeps the address.
func addressLostTo(cs []addressContender, name string) string {
	for _, c := range cs {
		if c.name != name && c.state == "active" {
			return c.name
		}
	}
	winner, at := "", ""
	for _, c := range cs {
		if winner == "" || admittedBefore(c.createdAt, c.name, at, winner) {
			winner, at = c.name, c.createdAt
		}
	}
	if winner == name {
		return ""
	}
	return winner
}

func contenderOf(name, createdAt, hState, mHost, mState string) addressContender {
	st := hState
	if mHost != "" {
		st = mState // as membershipRow.resolve: the membership row when it exists
	}
	return addressContender{name, createdAt, st}
}

// AddressLostTo is the host that keeps name's address instead of name
// (addressLostTo), "" when name keeps it or has no live row. Only the host
// that keeps it is admitted by AdmitHost and activated (ActivateHostFrom).
func AddressLostTo(ctx context.Context, c *Client, name string) (string, error) {
	rows, err := c.Query(ctx, addressContendersSQL, name)
	if err != nil {
		return "", err
	}
	var cs []addressContender
	for _, r := range rows {
		cs = append(cs, contenderOf(r.String("name"), r.String("created_at"), r.String("h_state"),
			r.String("m_host"), r.String("m_state")))
	}
	return addressLostTo(cs, name), nil
}

// addressKeptIn is AddressLostTo read inside a write's transaction: false,
// with the holder in lostTo, when name does not keep its address.
func addressKeptIn(ctx context.Context, tx *sql.Tx, name string, lostTo *string) (bool, error) {
	rows, err := tx.QueryContext(ctx, addressContendersSQL, name)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	var cs []addressContender
	for rows.Next() {
		var n, at, hs, mh, ms string
		if err := rows.Scan(&n, &at, &hs, &mh, &ms); err != nil {
			return false, err
		}
		cs = append(cs, contenderOf(n, at, hs, mh, ms))
	}
	if err := rows.Err(); err != nil {
		return false, err
	}
	*lostTo = addressLostTo(cs, name)
	return *lostTo == "", nil
}

// admittedBefore orders two admissions by stamp, then name.
func admittedBefore(aAt, aName, bAt, bName string) bool {
	ta, ea := time.Parse(time.RFC3339Nano, aAt)
	tb, eb := time.Parse(time.RFC3339Nano, bAt)
	switch {
	case ea == nil && eb == nil && !ta.Equal(tb):
		return ta.Before(tb)
	case (ea != nil || eb != nil) && aAt != bAt:
		return aAt < bAt
	}
	return aName < bName
}

// admissionGuard is the guard of every admission write of h
// (ExecuteBatchGuarded): it applies only if, read in the same transaction,
// no other live or joining host holds h's address, which it records in held.
// Two admissions of one machine under two names on this replica cannot both
// commit, whatever read either made before.
//
// It is one replica's guard. Two admissions on two replicas, each made before
// the other's row arrived, can both commit; the lease holder names such a
// pair (grpcapi host.address_shared).
func admissionGuard(ctx context.Context, h HostRecord, held *string) func(*sql.Tx) (bool, error) {
	return func(tx *sql.Tx) (bool, error) {
		err := tx.QueryRowContext(ctx, hostAddressHolderSQL, h.Address, h.Name, h.GRPCPort, h.GRPCPort).Scan(held)
		if errors.Is(err, sql.ErrNoRows) {
			return true, nil
		}
		return false, err
	}
}

// admissionResult is an admission write's outcome: an AddressHeldError when
// admissionGuard refused it, and nothing of it was written or logged.
func admissionResult(h HostRecord, held string, applied bool, err error) error {
	if err != nil {
		return err
	}
	if !applied {
		if held == "" {
			return fmt.Errorf("admission of %s was not applied", h.Name)
		}
		return &AddressHeldError{Address: h.Address, Port: h.GRPCPort, Holder: held}
	}
	return nil
}

// ErrReadmitNeedsCounter refuses a legacy re-admission over a tombstone of a
// counted incarnation (AdmitHostV2 is the only one allowed there).
var ErrReadmitNeedsCounter = errors.New("re-admitting this host needs the host_incarnation release feature")

// AdmitHostV2 re-admits a removed host at the next incarnation: one past its
// tombstone's (host_incarnation.go). The caller decides that the counter is
// due (grpcapi.AdmitHost: always over a counted tombstone, and over a legacy
// one once the release feature is available) and holds the feature's grant.
// A missing row, a live one or the removed certificate are refused as
// AdmitHost refuses them. It returns the incarnation issued and its stamp.
func AdmitHostV2(ctx context.Context, c *Client, h HostRecord, g capabilities.FeatureGrant) (int64, string, error) {
	if err := g.Check(capabilities.FeatureHostIncarnation); err != nil {
		return 0, "", err
	}
	if h.Name == "" || h.Address == "" || h.CertSerial == "" || h.CertSerial == "unknown" {
		return 0, "", fmt.Errorf("host admission requires name, address, and certificate serial")
	}
	if !ValidHostAddress(h.Address) {
		return 0, "", fmt.Errorf("host admission: address %q is not a bare IPv4 literal", h.Address)
	}
	n, _, serial, deleted, found, err := HostIncarnationOf(ctx, c, h.Name)
	switch {
	case err != nil:
		return 0, "", err
	case !found:
		return 0, "", fmt.Errorf("host %q has no row to re-admit", h.Name)
	case !deleted:
		return 0, "", fmt.Errorf("host %q is already active", h.Name)
	case strings.EqualFold(serial, h.CertSerial):
		return 0, "", fmt.Errorf("host %q cannot be re-admitted with its removed certificate", h.Name)
	}
	next := n + 1
	var at string
	err = c.withMembershipWrite(ctx, func(live bool) error {
		// Strictly after the removal this re-admits over, as this node holds
		// it: a removal that reached this node by anti-entropy advanced no
		// clock, and an admission stamped before its retirement would leave
		// the row's created_at before the credential's retirement, so no
		// password write for the new machine would ever carry it
		// (admissionAtOrAfter).
		floor, err := readmitClockFloor(ctx, c, h.Name)
		if err != nil {
			return err
		}
		uts, err := c.nowTSAfter(floor...)
		if err != nil {
			return fmt.Errorf("re-admit %s: %w", h.Name, err)
		}
		stamp, ok := ReadmitStamp(uts)
		if !ok {
			return fmt.Errorf("re-admit %s: unreadable clock %q", h.Name, uts)
		}
		at = stamp
		params := readmitV2Params(h, next, at, uts)
		var held string
		if !live {
			applied, err := c.ExecuteBatchGuarded(ctx, admissionGuard(ctx, h, &held), []Statement{{SQL: readmitHostV2SQL, Params: params}})
			return admissionResult(h, held, applied, err)
		}
		epoch, reason, err := currentIsolation(ctx, c, h.Name)
		if err != nil {
			return err
		}
		applied, err := c.ExecuteBatchGuarded(ctx, admissionGuard(ctx, h, &held), []Statement{
			{SQL: readmitHostV2SQL, Params: params},
			{SQL: hostMembershipStateSQL, Params: []interface{}{h.Name, h.State, epoch, reason, uts}},
		})
		return admissionResult(h, held, applied, err)
	})
	if err != nil {
		return 0, "", err
	}
	return next, at, nil
}

// readmitClockFloor is what a re-admission of name must be stamped after on
// this node: its tombstone's updated_at and its fence credential's retirement.
func readmitClockFloor(ctx context.Context, c *Client, name string) ([]string, error) {
	var floor []string
	rows, err := c.Query(ctx, `SELECT updated_at FROM hosts WHERE name = ?`, name)
	if err != nil {
		return nil, err
	}
	if len(rows) == 1 && rows[0].String("updated_at") != "" {
		floor = append(floor, rows[0].String("updated_at"))
	}
	rows, err = c.Query(ctx, `SELECT COALESCE(deleted_at, '') AS d, COALESCE(after_retirement, '') AS a
		FROM host_fence_credentials WHERE host_name = ?`, name)
	if err != nil {
		return nil, err
	}
	if len(rows) == 1 {
		if r := rowRetirement(rows[0].String("d"), rows[0].String("a")); r != "" {
			floor = append(floor, r)
		}
	}
	return floor, nil
}

// WriteOwnEndpoint records this host's own address and gRPC port on its row,
// which an admission recorded as `lv host add` saw them. Only for an own row
// at incarnation ≥ 1 (host_incarnation.go); every other address correction
// keeps its previous-release statement.
func WriteOwnEndpoint(ctx context.Context, c *Client, name, address string, grpcPort int, g capabilities.FeatureGrant) error {
	if err := g.Check(capabilities.FeatureHostIncarnation); err != nil {
		return err
	}
	if name != c.hostName {
		return fmt.Errorf("WriteOwnEndpoint: %q is not this host", name)
	}
	if !ValidHostAddress(address) {
		return fmt.Errorf("WriteOwnEndpoint: address %q is not a bare IPv4 literal", address)
	}
	if err := c.ownRowWriteRefused(name); err != nil {
		return err
	}
	n, _, _, deleted, found, err := HostIncarnationOf(ctx, c, name)
	if err != nil {
		return err
	}
	if !found || deleted || n < 1 {
		return fmt.Errorf("WriteOwnEndpoint: %s's row is not a live row at a counted incarnation", name)
	}
	return c.Execute(ctx, hostOwnEndpointSQL, address, grpcPort, c.NowTS(), name)
}

const readmitHostSQL = `UPDATE hosts SET address = ?, ssh_user = ?, ssh_port = ?, grpc_port = ?,
			state = ?, cert_serial = ?, deleted_at = NULL, updated_at = ?
		 WHERE name = ? AND deleted_at IS NOT NULL AND lower(cert_serial) <> lower(?)`

// RegisterHost is the daemon startup form of host admission. Ordinary restarts
// are idempotent. A re-added machine may clear its local tombstone only when the
// certificate actually installed on disk has a different serial; peers still
// require the operator's AdmitHost mutation and the matching certificate.
//
// A LIVE row whose serial disagrees with the certificate on disk is RE-RECORDED,
// because this is the one caller entitled to do that: the daemon passes its own
// name and the serial it just read from its own PKI directory, so the write only
// ever touches the node's own row, and anyone able to change what that node
// presents already holds its private key.
//
// It used to error instead, and nothing else wrote the column — AdmitHost refuses
// a live row, no CLI sets it. So a reissued host certificate left the row stale
// forever, and since peer trust binds a live row to its recorded serial, every
// daemon refused every peer and replication stopped fleet-wide. There was no way
// back in-product: the correction has to reach the PEER, and the stale serial is
// what blocks the peer channel. Rotation now converges by ordinary replication.
func RegisterHost(ctx context.Context, c *Client, h HostRecord) error {
	if err := c.ownRowWriteRefused(h.Name); err != nil {
		return err
	}
	rows, err := c.Query(ctx, `SELECT cert_serial, deleted_at, incarnation, created_at FROM hosts WHERE name = ?`, h.Name)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return InsertHost(ctx, c, h)
	}
	// The daemon never issues an incarnation (host_incarnation.go): over its
	// own tombstone of a counted incarnation it writes nothing, and the
	// operator's re-admission reaches it by replication.
	if rows[0].String("deleted_at") != "" && rows[0].Int("incarnation") >= 1 {
		slog.Warn("this host's own row is removed at a counted incarnation; waiting for its re-admission "+
			"to replicate rather than re-admitting itself", "host", h.Name, "incarnation", rows[0].Int("incarnation"))
		return nil
	}
	if rows[0].String("deleted_at") == "" {
		recorded := rows[0].String("cert_serial")
		if recorded == "" || strings.EqualFold(recorded, h.CertSerial) {
			return nil
		}
		// The daemon substitutes "unknown" when it cannot read its own
		// certificate. Recording that would blind the pin for this host on every
		// peer — a local file-permission problem becoming a cluster-wide trust
		// downgrade — so the recorded serial stands.
		if h.CertSerial == "" || h.CertSerial == "unknown" {
			slog.Warn("could not read this host's own certificate serial; leaving the recorded one in place",
				"host", h.Name, "recorded_serial", recorded)
			return nil
		}
		if err := c.reRecordRefused(h.Name, recorded, h.CertSerial, int64(rows[0].Int("incarnation")), rows[0].String("created_at")); err != nil {
			slog.Error("not re-recording this host's serial over its own row", "host", h.Name, "error", err)
			return err
		}
		slog.Warn("this host's certificate has been reissued since it was admitted; re-recording its serial "+
			"so peers accept it (rotation converges by replication)",
			"host", h.Name, "recorded_serial", recorded, "installed_serial", h.CertSerial)
		return c.Execute(ctx, recordOwnCertSerialSQL, h.CertSerial, c.NowTS(), h.Name)
	}
	return AdmitHost(ctx, c, h)
}

// recordOwnCertSerialSQL re-records a live host's certificate serial. One
// statement shape for both callers (RegisterHost at boot, RecordOwnCertSerial at
// runtime), so the replicated shape is the one older peers already apply.
const recordOwnCertSerialSQL = `UPDATE hosts SET cert_serial = ?, updated_at = ? WHERE name = ? AND deleted_at IS NULL`

// RecordOwnCertSerial is RegisterHost's re-record for a RUNNING daemon whose
// certificate was renewed in place (`lv host renew-cert`): it writes serial to
// the host's own live row when the row names another one. Over a counted row
// (incarnation 1 or higher) only a renewal of the recorded certificate is
// re-recorded at runtime; any other certificate swapped while the daemon runs
// is refused (ErrCertSwappedAtRuntime) until the daemon restarts.
//
// The same entitlement as at boot applies — the caller passes its own name and
// the serial it is serving, so the write touches only the node's own row — and
// the same refusals: a missing or tombstoned row, or a serial the daemon could
// not read, is left alone. A missing row is not this path's business (boot
// inserts it), and a tombstone is only ever cleared by admission. It reports
// whether it wrote.
func RecordOwnCertSerial(ctx context.Context, c *Client, name, serial string) (bool, error) {
	if name == "" || serial == "" || strings.EqualFold(serial, "unknown") {
		return false, nil
	}
	if err := c.ownRowWriteRefused(name); err != nil {
		return false, err
	}
	rows, err := c.Query(ctx, `SELECT cert_serial, deleted_at, incarnation, created_at FROM hosts WHERE name = ?`, name)
	if err != nil {
		return false, err
	}
	if len(rows) == 0 || rows[0].String("deleted_at") != "" {
		return false, nil
	}
	recorded := rows[0].String("cert_serial")
	if strings.EqualFold(recorded, serial) {
		return false, nil
	}
	n := int64(rows[0].Int("incarnation"))
	if err := c.reRecordRefused(name, recorded, serial, n, rows[0].String("created_at")); err != nil {
		return false, err
	}
	renewal := c.installedRenews(serial, recorded)
	if n >= 1 && name == c.hostName && !renewal {
		return false, fmt.Errorf("%w (recorded %s, serving %s, incarnation %d)", ErrCertSwappedAtRuntime, recorded, serial, n)
	}
	if renewal {
		slog.Info("re-recording this host's renewed certificate serial so peers pin the new certificate",
			"host", name, "recorded_serial", recorded, "serving_serial", serial)
	} else {
		slog.Warn("re-recording this host's certificate serial, which is not a renewal of the recorded one, so peers pin it",
			"host", name, "recorded_serial", recorded, "serving_serial", serial)
	}
	if err := c.Execute(ctx, recordOwnCertSerialSQL, serial, c.NowTS(), name); err != nil {
		return false, err
	}
	return true, nil
}

// ListHosts returns all active hosts.
func ListHosts(ctx context.Context, c *Client) ([]HostRecord, error) {
	rows, err := c.Query(ctx, hostSelectSQL+` WHERE h.deleted_at IS NULL`)
	if err != nil {
		return nil, err
	}

	frozen := c.hostsCopyFrozen()
	hosts := make([]HostRecord, len(rows))
	for i, r := range rows {
		hosts[i] = scanHost(r, frozen)
	}
	return hosts, nil
}

// HostStateJoining is the state `lv host add` admits a host in (AdmitHost):
// its identity is recorded, its daemon has not yet started. The daemon's boot
// write (UpdateHostStartup) records it 'upgrading', and 'active' once the
// daemon serves (hostboot). Until then it is not a fence
// candidate, so a coordinator does not power off a machine part-way through its
// setup, and like every state but 'active' it is no placement target.
//
// It is deliberately left VotingEligible, as the 'active' it replaces was: a
// node on the previous release, which does not know the state, counts it as a
// voter, and the voter set must not depend on which build counts it.
const HostStateJoining = "joining"

// VotingEligible is the one definition of a voting member's state: a host
// votes iff its state is not offline, maintenance or fenced. Witnesses vote;
// draining and upgrading hosts vote. health.VotingEligible and the failover
// coordinator's quorum both come from here, so the self-count, the quorum
// denominator and the set of observers whose rows count cannot drift apart.
func VotingEligible(state string) bool {
	switch state {
	case "offline", "maintenance", "fenced":
		return false
	}
	return true
}

// VoterSet returns the names of the cluster's voting members: hosts that are
// not deleted and whose state is VotingEligible. It is both halves of every
// quorum count: its size is the denominator, and an observation counts toward
// the numerator only if its observer is a member (colonelpanik/litevirt#251).
// A read error is returned as-is; callers fail closed on it.
//
// The state is the resolved one (host_membership.go), so the voter set a node
// counts is the one its failover coordinator and health gate both read.
//
// Once this node has adopted a voter generation with members (voter_config.go,
// colonelpanik/litevirt#251 step 2), the set is THAT generation's members and
// nothing else: it no longer filters on host state, so a fenced, offline or
// maintenance member still counts in the denominator until an operator removes
// it with `lv cluster voter rm`. No flag changes this — the voter set is a fact
// the cluster decided, not a policy (docs/design/recovery-claims.md §4.5). A
// reset generation has no members, and the set is derived again.
func VoterSet(ctx context.Context, c *Client) (map[string]bool, error) {
	cfg, err := AdoptedVoterConfig(ctx, c)
	if err != nil {
		return nil, err
	}
	if cfg.Explicit() {
		voters := make(map[string]bool, len(cfg.Members))
		for _, m := range cfg.Members {
			voters[m.Name] = true
		}
		return voters, nil
	}
	return DerivedVoterSet(ctx, c)
}

// VoterSetWithUncounted is VoterSet together with the voters that must not
// count toward a quorum's LIVE numerator however healthy their probes:
// derived-set voters this node reads as HostStateUnknown. Such a host may be
// in maintenance or offline on the cluster's view — out of the voter set
// there — so counting its probes could hand a minority a majority. It stays in
// the denominator, which is the fail-closed side. With an adopted voter
// generation the set is the generation's members and nothing is excluded.
//
// Both come from ONE read of host state, so a membership row landing between
// two reads cannot make them disagree (re-review 2, N4; re-review 3, R6). It is
// the only source of the uncounted set: every quorum count takes it from here
// or from VoterRegions, which calls it.
func VoterSetWithUncounted(ctx context.Context, c *Client) (voters, uncounted map[string]bool, err error) {
	voters, uncounted, _, err = voterSetRead(ctx, c)
	return voters, uncounted, err
}

// voterSetRead is VoterSetWithUncounted, with the adopted voter generation
// the set was read from (0 when none is adopted).
func voterSetRead(ctx context.Context, c *Client) (voters, uncounted map[string]bool, gen int64, err error) {
	cfg, err := AdoptedVoterConfig(ctx, c)
	if err != nil {
		return nil, nil, 0, err
	}
	if cfg != nil {
		gen = cfg.Generation
	}
	uncounted = map[string]bool{}
	if cfg.Explicit() {
		voters = make(map[string]bool, len(cfg.Members))
		for _, m := range cfg.Members {
			voters[m.Name] = true
		}
		return voters, uncounted, gen, nil
	}
	states, err := resolvedHostStates(ctx, c)
	if err != nil {
		return nil, nil, 0, err
	}
	voters = make(map[string]bool, len(states))
	for name, state := range states {
		if VotingEligible(state) {
			voters[name] = true
		}
		if state == HostStateUnknown {
			uncounted[name] = true
		}
	}
	return voters, uncounted, gen, nil
}

// DerivedVoterSet is the voter set as it was before any explicit generation:
// every non-deleted host whose state is VotingEligible. Automatic genesis
// proposes it as generation 1's members.
func DerivedVoterSet(ctx context.Context, c *Client) (map[string]bool, error) {
	states, err := resolvedHostStates(ctx, c)
	if err != nil {
		return nil, err
	}
	voters := make(map[string]bool, len(states))
	for name, state := range states {
		if VotingEligible(state) {
			voters[name] = true
		}
	}
	return voters, nil
}

// GetHost returns a single host by name.
func GetHost(ctx context.Context, c *Client, name string) (*HostRecord, error) {
	rows, err := c.Query(ctx, hostSelectSQL+` WHERE h.name = ? AND h.deleted_at IS NULL`, name)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	h := scanHost(rows[0], c.hostsCopyFrozen())
	return &h, nil
}

// hostSelectSQL is the column list scanHost reads, joined to the host's fence
// credential row, live or retired, so IPMIPass is resolved new-first and a
// retired row reads as no password (credentials_split.go, READ RULE), to its
// live Redfish row (host_fence_redfish.go), to its membership row so State is
// too (host_membership.go), and to its runtime row so the self-reported columns
// are (host_runtime.go). Columns the tables
// share are qualified; SQLite names a qualified result column by its bare name,
// which is what scanHost looks up.
const hostSelectSQL = `SELECT h.name, h.address, h.ssh_user, h.ssh_port, h.grpc_port, h.state, h.cert_serial,
			h.cpu_total, h.mem_total, h.disk_total, h.fence_strategy,
			h.ipmi_address, h.ipmi_user, h.ipmi_pass, h.watchdog_dev,
			h.labels, h.version, h.schema_version, h.role, h.region,
			h.cpu_overcommit, h.mem_overcommit, h.cpu_reserve, h.mem_reserve_mib,
			h.capacity_policy_hash,
			h.created_at, h.updated_at,
			c.host_name AS cred_key, c.ipmi_pass AS cred_val, c.updated_at AS cred_ts,
			c.deleted_at AS cred_deleted,
			rf.endpoint AS rf_endpoint, rf.username AS rf_username, rf.password AS rf_password,
			rf.system_id AS rf_system_id, rf.auth AS rf_auth, rf.ca_pem AS rf_ca_pem,
			` + membershipCols + `,
			` + runtimeCols + `
		 FROM hosts h LEFT JOIN host_fence_credentials c ON c.host_name = h.name
		 LEFT JOIN host_fence_redfish rf ON rf.host_name = h.name AND rf.deleted_at IS NULL` +
	membershipJoins + runtimeJoins

func scanHost(r Row, hostsCopyFrozen bool) HostRecord {
	name := r.String("name")
	rt := runtimeRowFrom(r, name).resolve()
	credRetired := r.String("cred_key") != "" && r.String("cred_deleted") != ""
	ipmiPass := ""
	if !credRetired {
		ipmiPass = resolveCredential(r.String("cred_key") != "", r.String("cred_val"), r.String("ipmi_pass"))
	}
	return HostRecord{
		Name:               name,
		Address:            r.String("address"),
		SSHUser:            r.String("ssh_user"),
		SSHPort:            r.Int("ssh_port"),
		GRPCPort:           r.Int("grpc_port"),
		State:              membershipRowFrom(r, name).resolve(hostsCopyFrozen).State,
		CertSerial:         r.String("cert_serial"),
		CPUTotal:           int(rt.CPU.Int64),
		MemTotal:           int(rt.Mem.Int64),
		DiskTotal:          int(rt.Disk.Int64),
		FenceStrategy:      r.String("fence_strategy"),
		IPMIAddress:        r.String("ipmi_address"),
		IPMIUser:           r.String("ipmi_user"),
		IPMIPass:           ipmiPass,
		IPMIPassRetired:    credRetired,
		Redfish:            redfishFromRow(r, "rf_"),
		WatchdogDev:        r.String("watchdog_dev"),
		Labels:             decodeLabels(r.String("labels")),
		Version:            rt.Version,
		SchemaVersion:      int(rt.SchemaVersion),
		Role:               roleOrDefault(r.String("role")),
		Region:             regionOrDefault(r.String("region")),
		CPUOvercommit:      r.Float("cpu_overcommit"),
		MemOvercommit:      r.Float("mem_overcommit"),
		CPUReserve:         optInt(r, "cpu_reserve"),
		MemReserveMiB:      optInt(r, "mem_reserve_mib"),
		CapacityPolicyHash: rt.PolicyHash,
		CreatedAt:          r.String("created_at"),
		UpdatedAt:          r.String("updated_at"),
	}
}

func regionOrDefault(s string) string {
	if s == "" {
		return "default"
	}
	return s
}

func roleOrDefault(s string) string {
	if s == "" {
		return "worker"
	}
	return s
}

// SetHostLabel merges a single key=value into a host's labels (the hosts.labels
// JSON column that placement reads). A no-op when the value is unchanged, so a
// caller that re-asserts the same label every daemon start (e.g. LXC capability)
// doesn't churn replication. Use the empty host row gracefully — if the host
// isn't registered yet the UPDATE simply matches nothing.
func SetHostLabel(ctx context.Context, c *Client, host, key, value string) error {
	return SetHostLabels(ctx, c, host, map[string]string{key: value}, nil)
}

// SetHostLabels merges set into a host's labels and removes the keys in remove,
// in ONE write of the labels column, and none when nothing changes. A periodic
// writer of several labels (the pending-OS-update counts) therefore writes the
// column once per actual change rather than once per label per check: the column
// is replicated last-writer-wins as a whole, so each write is a chance to carry
// back a stale copy of another node's concurrent `lv host label` edit. The
// statement is SetHostLabel's (one shape, already known to every peer).
func SetHostLabels(ctx context.Context, c *Client, host string, set map[string]string, remove []string) error {
	h, err := GetHost(ctx, c, host)
	if err != nil {
		return err
	}
	labels := map[string]string{}
	if h != nil {
		for k, v := range h.Labels {
			labels[k] = v
		}
	}
	changed := false
	for k, v := range set {
		if cur, ok := labels[k]; !ok || cur != v {
			labels[k] = v
			changed = true
		}
	}
	for _, k := range remove {
		if _, ok := labels[k]; ok {
			delete(labels, k)
			changed = true
		}
	}
	if !changed {
		return nil // unchanged — avoid replication churn
	}
	b, err := json.Marshal(labels)
	if err != nil {
		return err
	}
	return c.Execute(ctx,
		`UPDATE hosts SET labels = ?, updated_at = ? WHERE name = ?`,
		string(b), c.NowTS(), host)
}

func decodeLabels(raw string) map[string]string {
	m := map[string]string{}
	if raw != "" {
		_ = json.Unmarshal([]byte(raw), &m)
	}
	return m
}

// UpdateHostState changes a host's state: hosts.state before the membership
// split, and after it hosts.state AND host_membership.state in one batch under
// one updated_at (host_membership.go) — host_membership alone once
// host_membership_retire_v1 has latched (host_membership_retire.go). The hosts half keeps a node rolled back
// one release reading the right state; the membership half is the copy that no
// longer shares a clock with the host's own reports.
func UpdateHostState(ctx context.Context, c *Client, name, state string) error {
	return c.withMembershipWrite(ctx, func(live bool) error {
		stmts, err := hostStateStatements(ctx, c, name, state, live)
		if err != nil {
			return err
		}
		return c.ExecuteBatch(ctx, stmts)
	})
}

// UpdateHostStateFrom is UpdateHostState only while host is recorded `from`,
// checked inside the write's transaction (ExecuteBatchGuarded): a state
// another writer recorded between a caller's read and this write — a fence
// landing on a host that is turning active — is not overwritten. The
// statements are UpdateHostState's; the guard is local only. applied=false,
// with no error, when the host is recorded as something else (or absent).
// UpdateHostStateFromWithCondition is UpdateHostStateFrom that commits the
// health condition cond in the same replicated entry as the state, behind the
// same guard: a peer applies both or neither, so it never holds the state
// without the condition that explains it (failover's held fence, which a
// successor reads 'offline' without its ha.fence_held as terminal).
func UpdateHostStateFromWithCondition(ctx context.Context, c *Client, name, from, to string, cond HealthCondition) (bool, error) {
	params, err := healthConditionParams(cond, c.NowTS())
	if err != nil {
		return false, err
	}
	var applied bool
	err = c.withMembershipWrite(ctx, func(live bool) error {
		stmts, err := hostStateStatements(ctx, c, name, to, live)
		if err != nil {
			return err
		}
		stmts = append(stmts, Statement{SQL: upsertHealthConditionSQL, Params: params})
		applied, err = c.ExecuteBatchGuarded(ctx, hostStateIs(ctx, c, name, from), stmts)
		return err
	})
	return applied, err
}

func UpdateHostStateFrom(ctx context.Context, c *Client, name, from, to string) (bool, error) {
	var applied bool
	err := c.withMembershipWrite(ctx, func(live bool) error {
		stmts, err := hostStateStatements(ctx, c, name, to, live)
		if err != nil {
			return err
		}
		applied, err = c.ExecuteBatchGuarded(ctx, hostStateIs(ctx, c, name, from), stmts)
		return err
	})
	return applied, err
}

// ActivateHostFrom is UpdateHostStateFrom(name, from, "active") made only
// while, read in the same transaction, name keeps its address
// (AddressLostTo): a host is never recorded active beside another host at
// its address that already is, nor while an earlier admission there stands.
// lostTo names the holder when that refused the write.
func ActivateHostFrom(ctx context.Context, c *Client, name, from string) (applied bool, lostTo string, err error) {
	err = c.withMembershipWrite(ctx, func(live bool) error {
		stmts, err := hostStateStatements(ctx, c, name, "active", live)
		if err != nil {
			return err
		}
		applied, err = c.ExecuteBatchGuarded(ctx, activationGuard(ctx, c, name, from, &lostTo), stmts)
		return err
	})
	return applied, lostTo, err
}

// ActivateHostStartupFrom is UpdateHostStartupFrom(..., "active", ...) under
// ActivateHostFrom's address rule.
func ActivateHostStartupFrom(ctx context.Context, c *Client, name, from, version string, cpu, mem, disk int, hasResources bool) (applied bool, lostTo string, err error) {
	if err := c.ownRowWriteRefused(name); err != nil {
		return false, "", err
	}
	err = c.withMembershipWrite(ctx, func(live bool) error {
		return c.withRuntimeWrite(ctx, func(liveRuntime bool) error {
			stmts, err := hostStartupStatements(ctx, c, name, "active", version, cpu, mem, disk, hasResources, live, liveRuntime)
			if err != nil || len(stmts) == 0 {
				return err
			}
			applied, err = c.ExecuteBatchGuarded(ctx, activationGuard(ctx, c, name, from, &lostTo), stmts)
			return err
		})
	})
	return applied, lostTo, err
}

// activationGuard is hostStateIs(name, from) and addressKeptIn, both read in
// the write's transaction.
func activationGuard(ctx context.Context, c *Client, name, from string, lostTo *string) func(tx *sql.Tx) (bool, error) {
	stateIs := hostStateIs(ctx, c, name, from)
	return func(tx *sql.Tx) (bool, error) {
		if ok, err := stateIs(tx); err != nil || !ok {
			return false, err
		}
		return addressKeptIn(ctx, tx, name, lostTo)
	}
}

// hostStateIs is the guard of a write made only while host is recorded
// `from`: it reads the state inside the write's transaction, as
// membershipRow.resolve does. Build it inside withMembershipWrite.
func hostStateIs(ctx context.Context, c *Client, name, from string) func(tx *sql.Tx) (bool, error) {
	frozen := c.hostsCopyFrozen()
	return func(tx *sql.Tx) (bool, error) {
		var hState string
		var mKey, mState sql.NullString
		err := tx.QueryRowContext(ctx, `SELECT h.state, m.host_name, m.state FROM hosts h`+membershipJoins+
			` WHERE h.name = ? AND h.deleted_at IS NULL`, name).Scan(&hState, &mKey, &mState)
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		// As membershipRow.resolve: the membership row when it exists.
		cur := hState
		switch {
		case mKey.Valid && mKey.String != "":
			cur = mState.String
		case frozen:
			cur = HostStateUnknown
		}
		return cur == from, nil
	}
}

// hostStateStatements is the batch that records host `state`: the hosts
// column and, after the membership split, the host_membership row.
func hostStateStatements(ctx context.Context, c *Client, name, state string, live bool) ([]Statement, error) {
	uts := c.NowTS()
	if !live {
		return []Statement{{SQL: updateHostStateSQL, Params: []interface{}{state, uts, name}}}, nil
	}
	missing, err := membershipRowMissingFrozen(ctx, c, name)
	if err != nil {
		return nil, err
	}
	if missing {
		return []Statement{{SQL: hostMembershipStateOnlySQL, Params: []interface{}{state, uts, name}}}, nil
	}
	epoch, reason, err := currentIsolation(ctx, c, name)
	if err != nil {
		return nil, err
	}
	if c.hostsCopyRetired(live) {
		return []Statement{{SQL: hostMembershipStateSQL, Params: []interface{}{name, state, epoch, reason, uts}}}, nil
	}
	return []Statement{
		{SQL: updateHostStateSQL, Params: []interface{}{state, uts, name}},
		{SQL: hostMembershipStateSQL, Params: []interface{}{name, state, epoch, reason, uts}},
	}, nil
}

const updateHostStateSQL = `UPDATE hosts SET state = ?, updated_at = ? WHERE name = ?`

// UpdateHostRole flips a host between "worker" and "witness". Use this to
// promote a worker to tiebreaker (must drain VMs first) or to demote a
// witness back to a worker.
func UpdateHostRole(ctx context.Context, c *Client, name, role string) error {
	if role != "worker" && role != "witness" {
		return fmt.Errorf("invalid host role %q (want worker|witness)", role)
	}
	return c.Execute(ctx,
		`UPDATE hosts SET role = ?, updated_at = ? WHERE name = ?`,
		role, c.NowTS(), name,
	)
}

// UpdateHostRegion sets a host's region label. federation —
// the region is a failure-domain tag (DC, rack, AZ) used by ListRegions
// / RegionStatus / CrossRegionMigrate. Empty region is normalised to
// "default" so existing single-region clusters never accidentally end
// up with an empty-string region.
func UpdateHostRegion(ctx context.Context, c *Client, name, region string) error {
	if region == "" {
		region = "default"
	}
	return c.Execute(ctx,
		`UPDATE hosts SET region = ?, updated_at = ? WHERE name = ?`,
		region, c.NowTS(), name,
	)
}

// DeleteHost soft-deletes a host and cleans up related records.
func DeleteHost(ctx context.Context, c *Client, name string) error {
	return c.ExecuteBatch(ctx, deleteHostStatements(c, name))
}

// DeleteHostIf is DeleteHost only while name's live row is still the
// admission a caller checked: its whole ordering key (incarnation and
// admission stamp, host_incarnation.go) and its certificate serial (compared
// without case), read in the same transaction as the delete. A row that
// changed since — removed, re-admitted under a new certificate, incarnation
// or stamp (a later duplicate admission at the same incarnation, even of the
// same certificate), its certificate renewed — is not deleted, and applied is
// false. The statements are DeleteHost's.
func DeleteHostIf(ctx context.Context, c *Client, name, serial string, key HostIncarnation) (applied bool, err error) {
	return c.ExecuteBatchGuarded(ctx, admissionStillIs(ctx, name, serial, key), deleteHostStatements(c, name))
}

// DeleteHostAdmissionIf is DeleteHostIf whose removal names the certificate
// serial of the admission it ends (deleteHostAdmissionSQL): a receiver ends
// the row only while it holds that serial, and a row it holds under another
// serial (a re-admission, even one that kept the created_at) is not this
// removal's to end (host_removal_stands.go). A previous-release receiver does
// not know the shape (latchGatedShapes), so a caller writes it only once the
// release token has latched (grpcapi.Server.ReleaseTokenLatched), and
// DeleteHostIf before.
func DeleteHostAdmissionIf(ctx context.Context, c *Client, name, serial string, key HostIncarnation) (applied bool, err error) {
	if serial == "" {
		return false, fmt.Errorf("removal of %s names no certificate serial", name)
	}
	return c.ExecuteBatchGuarded(ctx, admissionStillIs(ctx, name, serial, key), deleteHostStatementsOf(c, name, serial))
}

// admissionStillIs is DeleteHostIf's guard: name's live row is still the
// admission with this key and serial, read in the write's transaction.
func admissionStillIs(ctx context.Context, name, serial string, key HostIncarnation) func(tx *sql.Tx) (bool, error) {
	return func(tx *sql.Tx) (bool, error) {
		var curSerial, curAt string
		var curInc int64
		err := tx.QueryRowContext(ctx,
			`SELECT COALESCE(cert_serial, ''), COALESCE(incarnation, 0), COALESCE(created_at, '') FROM hosts WHERE name = ? AND deleted_at IS NULL`,
			name).Scan(&curSerial, &curInc, &curAt)
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return strings.EqualFold(curSerial, serial) && curInc == key.N && curAt == key.At, nil
	}
}

func deleteHostStatements(c *Client, name string) []Statement {
	return deleteHostStatementsOf(c, name, "")
}

// deleteHostStatementsOf is DeleteHost's batch; with a serial, its removal
// names the admission it ends (deleteHostAdmissionSQL).
func deleteHostStatementsOf(c *Client, name, serial string) []Statement {
	now := time.Now().UTC().Format(time.RFC3339) // deleted_at marker (bare)
	removal := Statement{SQL: deleteHostSQL, Params: []interface{}{now, c.NowTS(), name}}
	if serial != "" {
		removal = Statement{SQL: deleteHostAdmissionSQL, Params: []interface{}{now, c.NowTS(), name, serial}}
	}
	return []Statement{
		removal,
		{SQL: `UPDATE host_health SET deleted_at = ?, updated_at = ? WHERE observer = ? OR target = ?`,
			Params: []interface{}{now, c.NowTS(), name, name}},
		{SQL: `UPDATE network_vteps SET deleted_at = ?, updated_at = ? WHERE host_name = ?`,
			Params: []interface{}{now, c.NowTS(), name}},
	}
}

// deleteHostSQL tombstones a host row. Every node that applies it, the origin
// included, also retires the host's fence credential row (host_readmit.go).
const deleteHostSQL = `UPDATE hosts SET deleted_at = ?, updated_at = ? WHERE name = ?`

// deleteHostAdmissionSQL is deleteHostSQL bound to the certificate serial of
// the admission it ends (DeleteHostAdmissionIf). Params: deleted_at,
// updated_at, name, cert_serial.
const deleteHostAdmissionSQL = `UPDATE hosts SET deleted_at = ?, updated_at = ? WHERE name = ? AND lower(cert_serial) = lower(?)`

// UpdateHostVersion updates a host's reported version: hosts.version, and
// after the runtime split host_runtime.version too, in one batch under one
// updated_at (host_runtime.go).
func UpdateHostVersion(ctx context.Context, c *Client, name, version string) error {
	return c.withRuntimeWrite(ctx, func(live bool) error {
		uts := c.NowTS()
		hostsStmt := Statement{SQL: updateHostVersionSQL, Params: []interface{}{version, uts, name}}
		if !live {
			return c.ExecuteBatch(ctx, []Statement{hostsStmt})
		}
		rt, ok, err := runtimeStatement(ctx, c, name, reportVersion, func(v *runtimeVals) { v.Version = version }, uts)
		if err != nil {
			return err
		}
		if !ok {
			return c.ExecuteBatch(ctx, []Statement{hostsStmt})
		}
		if c.hostsRuntimeRetired(live) {
			// host_runtime_retire_v1: the report no longer moves the hosts
			// row's clock (host_runtime_retire.go).
			return c.ExecuteBatch(ctx, []Statement{rt})
		}
		return c.ExecuteBatch(ctx, []Statement{hostsStmt, rt})
	})
}

const updateHostVersionSQL = `UPDATE hosts SET version = ?, updated_at = ? WHERE name = ?`

// UpdateHostStartup writes a host's boot-time state in a SINGLE batched mutation:
// always state + version + updated_at (one HLC, one NowTS), and the resource
// counts only when hasResources is true (a failed NodeInfo() probe must not split
// the write into separate same-second mutations — that is exactly the race that
// strands the version on peers). version is written from the running daemon
// whenever available, including the fresh-insert case, so startup state is
// single-source rather than relying on a later write.
func UpdateHostStartup(ctx context.Context, c *Client, name, state, version string, cpu, mem, disk int, hasResources bool) error {
	if err := c.ownRowWriteRefused(name); err != nil {
		return err
	}
	return c.withMembershipWrite(ctx, func(live bool) error {
		return c.withRuntimeWrite(ctx, func(liveRuntime bool) error {
			stmts, err := hostStartupStatements(ctx, c, name, state, version, cpu, mem, disk, hasResources, live, liveRuntime)
			if err != nil || len(stmts) == 0 {
				return err // none: no live hosts row, nothing a previous release would have written either
			}
			return c.ExecuteBatch(ctx, stmts)
		})
	})
}

// UpdateHostStartupFrom is UpdateHostStartup only while host is recorded
// `from`, checked inside the write's transaction (ExecuteBatchGuarded), as
// UpdateHostStateFrom is: a boot report deferred until the daemon serves does
// not overwrite a fence, drain or maintenance recorded meanwhile. The
// statements are UpdateHostStartup's; the guard is local only. applied=false,
// with no error, when the host is recorded as something else (or absent).
func UpdateHostStartupFrom(ctx context.Context, c *Client, name, from, state, version string, cpu, mem, disk int, hasResources bool) (bool, error) {
	if err := c.ownRowWriteRefused(name); err != nil {
		return false, err
	}
	var applied bool
	err := c.withMembershipWrite(ctx, func(live bool) error {
		return c.withRuntimeWrite(ctx, func(liveRuntime bool) error {
			stmts, err := hostStartupStatements(ctx, c, name, state, version, cpu, mem, disk, hasResources, live, liveRuntime)
			if err != nil || len(stmts) == 0 {
				return err
			}
			applied, err = c.ExecuteBatchGuarded(ctx, hostStateIs(ctx, c, name, from), stmts)
			return err
		})
	})
	return applied, err
}

// hostStartupStatements is the boot report's batch: build it inside
// withMembershipWrite and withRuntimeWrite, whose live flags it takes.
func hostStartupStatements(ctx context.Context, c *Client, name, state, version string, cpu, mem, disk int, hasResources, live, liveRuntime bool) ([]Statement, error) {
	// COALESCE(NULLIF(?, ''), version) keeps the existing version when the daemon
	// reports an empty one (dev builds), so a blank version can't clobber a good one.
	// schema_version is this running binary's supported schema (CurrentSchemaVersion),
	// matching what Ping advertises — the self-upgrade watcher reads it from here.
	sv := CurrentSchemaVersion
	uts := c.NowTS()
	// The hosts statement carries the runtime columns until
	// host_runtime_retire_v1 has latched, and the boot state until
	// host_membership_retire_v1 has. With only the runtime copy
	// retired it is the plain state write; with both, there is none
	// (host_runtime_retire.go).
	runtimeRetired := c.hostsRuntimeRetired(liveRuntime)
	var stmts []Statement
	switch {
	case runtimeRetired && c.hostsCopyRetired(live):
	case runtimeRetired:
		stmts = append(stmts, Statement{SQL: updateHostStateSQL, Params: []interface{}{state, uts, name}})
	case hasResources:
		stmts = append(stmts, Statement{SQL: hostStartupResourcesSQL, Params: []interface{}{state, version, sv, cpu, mem, disk, uts, name}})
	default:
		stmts = append(stmts, Statement{SQL: hostStartupSQL, Params: []interface{}{state, version, sv, uts, name}})
	}
	if live {
		// After the membership split the boot state is also written
		// to host_membership, in the same batch under the same
		// updated_at: the hosts statement is the previous release's,
		// unchanged, so a node rolled back one release still reads it.
		missing, err := membershipRowMissingFrozen(ctx, c, name)
		if err != nil {
			return nil, err
		}
		if missing {
			stmts = append(stmts, Statement{SQL: hostMembershipStateOnlySQL, Params: []interface{}{state, uts, name}})
		} else {
			epoch, reason, err := currentIsolation(ctx, c, name)
			if err != nil {
				return nil, err
			}
			stmts = append(stmts, Statement{SQL: hostMembershipStateSQL, Params: []interface{}{name, state, epoch, reason, uts}})
		}
	}
	if liveRuntime {
		// And after the runtime split the report goes to host_runtime
		// too (host_runtime.go). An empty version keeps the one the
		// host already has, as the hosts statement's COALESCE does.
		rt, ok, err := runtimeStatement(ctx, c, name, reportBoot, func(v *runtimeVals) {
			if version != "" {
				v.Version = version
			}
			v.SchemaVersion = int64(sv)
			if hasResources {
				v.CPU, v.Mem, v.Disk = someInt(cpu), someInt(mem), someInt(disk)
			}
		}, uts)
		if err != nil {
			return nil, err
		}
		if ok {
			stmts = append(stmts, rt)
		}
	}
	return stmts, nil
}

// The boot report's hosts statements, in their previous-release shapes.
const (
	hostStartupResourcesSQL = `UPDATE hosts SET state = ?, version = COALESCE(NULLIF(?, ''), version), schema_version = ?,
				cpu_total = ?, mem_total = ?, disk_total = ?, updated_at = ? WHERE name = ?`
	hostStartupSQL = `UPDATE hosts SET state = ?, version = COALESCE(NULLIF(?, ''), version), schema_version = ?, updated_at = ? WHERE name = ?`
)

// UpdateHostResources updates a host's resource counts: the hosts columns,
// and after the runtime split host_runtime's too, in one batch under one
// updated_at (host_runtime.go).
func UpdateHostResources(ctx context.Context, c *Client, name string, cpu, mem, disk int) error {
	return c.withRuntimeWrite(ctx, func(live bool) error {
		uts := c.NowTS()
		hostsStmt := Statement{SQL: updateHostResourcesSQL, Params: []interface{}{cpu, mem, disk, uts, name}}
		if !live {
			return c.ExecuteBatch(ctx, []Statement{hostsStmt})
		}
		rt, ok, err := runtimeStatement(ctx, c, name, reportResources, func(v *runtimeVals) {
			v.CPU, v.Mem, v.Disk = someInt(cpu), someInt(mem), someInt(disk)
		}, uts)
		if err != nil {
			return err
		}
		if !ok {
			return c.ExecuteBatch(ctx, []Statement{hostsStmt})
		}
		if c.hostsRuntimeRetired(live) {
			return c.ExecuteBatch(ctx, []Statement{rt})
		}
		return c.ExecuteBatch(ctx, []Statement{hostsStmt, rt})
	})
}

const updateHostResourcesSQL = `UPDATE hosts SET cpu_total = ?, mem_total = ?, disk_total = ?, updated_at = ?
		 WHERE name = ?`
