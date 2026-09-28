package corrosion

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// The explicit voter set (colonelpanik/litevirt#251 step 2,
// docs/design/recovery-claims.md §4).
//
// voter_configs holds one immutable row per generation: the decided value of
// the claim at key (voter_config, "", generation-1, 0) plus its certificate. A
// node ADOPTS a generation — records it in node-local local_voter_adoption —
// only once that certificate verifies against the generation before it, and,
// if it is a member of the new generation, only after importing claim state
// from a sealed majority of the old one (§4.4). The adoption loop that does
// both lives in grpcapi, because importing dials peers; this file is storage.
//
// Once a member generation is adopted, VoterSet returns its members and
// nothing else: operational state no longer changes the voting population,
// whatever any enforcement flag says (§4.5, §9 Q4).

// VoterConfig is one voter_configs row.
type VoterConfig struct {
	VoterConfigValue
	MembersHash string
	Certificate string // JSON ClaimCertificate; "" only in a hand-built test row
}

// Explicit reports whether the generation has members. A reset generation has
// none, and VoterSet is derived again while it is the adopted one.
func (v *VoterConfig) Explicit() bool { return v != nil && len(v.Members) > 0 }

// Member returns name's entry.
func (v *VoterConfig) Member(name string) (VoterMember, bool) {
	if v == nil {
		return VoterMember{}, false
	}
	for _, m := range v.Members {
		if m.Name == name {
			return m, true
		}
	}
	return VoterMember{}, false
}

// Names returns the member names, sorted.
func (v *VoterConfig) Names() []string {
	if v == nil {
		return nil
	}
	out := make([]string, 0, len(v.Members))
	for _, m := range v.Members {
		out = append(out, m.Name)
	}
	sort.Strings(out)
	return out
}

// SetVoterConfigGate injects the predicate that permits WRITING voter_configs,
// wired at daemon start to DurablyLatched(voter_config_v1). Unset, it fails
// CLOSED: voter_configs' statement shapes are the first that table ever had,
// and a previous-release peer cannot decode them (its apply fails closed and
// its stream stalls). The latch is ReplicationGated, so it cannot form while
// any replication recipient is on such a build.
func (c *Client) SetVoterConfigGate(fn func() bool) { c.voterConfigGate.Store(&fn) }

// MayWriteVoterConfigs reports whether voter_configs may be written.
func (c *Client) MayWriteVoterConfigs() bool {
	fn := c.voterConfigGate.Load()
	return fn != nil && *fn != nil && (*fn)()
}

// ErrVoterConfigGateClosed is returned by a voter_configs write before
// voter_config_v1 has durably latched.
var ErrVoterConfigGateClosed = fmt.Errorf("voter_config_v1 has not durably latched; no voter configuration " +
	"can be written until every host replicating from this one runs a build that decodes it")

// insertVoterConfigSQL is the one statement that writes voter_configs. INSERT
// OR IGNORE: the row for a generation is immutable, and a second writer of the
// same decision (a proposer that learned it) writes the identical value.
const insertVoterConfigSQL = `INSERT OR IGNORE INTO voter_configs
	(generation, members_json, members_hash, change, certificate, created_by, created_at, updated_at)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?)`

// WriteVoterConfig records a decided generation. The caller holds its
// certificate; the row's updated_at is the value's created_at, so every writer
// of one decision writes the same row but for the certificate column.
func WriteVoterConfig(ctx context.Context, c *Client, v VoterConfigValue, cert ClaimCertificate) error {
	if !c.MayWriteVoterConfigs() {
		return ErrVoterConfigGateClosed
	}
	members := SortMembers(v.Members)
	mj, err := json.Marshal(members)
	if err != nil {
		return err
	}
	cj, err := cert.Encode()
	if err != nil {
		return err
	}
	return c.Execute(ctx, insertVoterConfigSQL,
		v.Generation, string(mj), MembersHash(members), v.Change, cj, v.CreatedBy, v.CreatedAt, v.CreatedAt)
}

func scanVoterConfig(r Row) (*VoterConfig, error) {
	var members []VoterMember
	if s := r.String("members_json"); s != "" {
		if err := json.Unmarshal([]byte(s), &members); err != nil {
			return nil, fmt.Errorf("voter_configs generation %d: members_json: %w", r.Int64("generation"), err)
		}
	}
	return &VoterConfig{
		VoterConfigValue: VoterConfigValue{
			Generation: r.Int64("generation"),
			Members:    SortMembers(members),
			Change:     r.String("change"),
			CreatedBy:  r.String("created_by"),
			CreatedAt:  r.String("created_at"),
		},
		MembersHash: r.String("members_hash"),
		Certificate: r.String("certificate"),
	}, nil
}

const voterConfigCols = `generation, members_json, members_hash, change, certificate, created_by, created_at`

// GetVoterConfig reads one generation's row; nil when absent.
func GetVoterConfig(ctx context.Context, c *Client, generation int64) (*VoterConfig, error) {
	rows, err := c.Query(ctx, `SELECT `+voterConfigCols+` FROM voter_configs
		WHERE generation = ? AND deleted_at IS NULL`, generation)
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	return scanVoterConfig(rows[0])
}

// ListVoterConfigs reads every row, oldest generation first.
func ListVoterConfigs(ctx context.Context, c *Client) ([]*VoterConfig, error) {
	rows, err := c.Query(ctx, `SELECT `+voterConfigCols+` FROM voter_configs
		WHERE deleted_at IS NULL ORDER BY generation`)
	if err != nil {
		return nil, err
	}
	out := make([]*VoterConfig, 0, len(rows))
	for _, r := range rows {
		v, err := scanVoterConfig(r)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// VoterConfigsEmpty reports whether no generation has ever been written here.
// Automatic genesis runs only while it is true, which is what makes a reset
// sticky (§4.2).
func VoterConfigsEmpty(ctx context.Context, c *Client) (bool, error) {
	rows, err := c.Query(ctx, `SELECT COUNT(*) AS n FROM voter_configs`)
	if err != nil {
		return false, err
	}
	return len(rows) == 0 || rows[0].Int("n") == 0, nil
}

// AdoptedVoterGeneration is the highest generation this node has adopted, 0 if
// none.
func AdoptedVoterGeneration(ctx context.Context, c *Client) (int64, error) {
	rows, err := c.Query(ctx, `SELECT COALESCE(MAX(generation), 0) AS g FROM local_voter_adoption`)
	if err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 0, nil
	}
	return rows[0].Int64("g"), nil
}

// AdoptedVoterConfig returns the generation this node has adopted, nil when it
// has adopted none. An adoption record whose row has gone missing is an error,
// never "none": the caller would otherwise fall back to the derived set on one
// node only, which is the disagreement the voter set exists to prevent.
func AdoptedVoterConfig(ctx context.Context, c *Client) (*VoterConfig, error) {
	g, err := AdoptedVoterGeneration(ctx, c)
	if err != nil || g == 0 {
		return nil, err
	}
	v, err := GetVoterConfig(ctx, c, g)
	if err != nil {
		return nil, err
	}
	if v == nil {
		return nil, fmt.Errorf("adopted voter generation %d has no voter_configs row", g)
	}
	return v, nil
}

// RecordVoterAdoption records that this node adopted generation g without
// importing anything (a node that is not a member of g, or a generation that
// follows an empty one). Idempotent.
func RecordVoterAdoption(ctx context.Context, c *Client, g int64) error {
	return c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		return recordAdoptionTx(ctx, tx, g, nil)
	})
}

const recordAdoptionSQL = `INSERT OR IGNORE INTO local_voter_adoption (generation, imported_from, adopted_at)
	VALUES (?, ?, ?)`

func recordAdoptionTx(ctx context.Context, tx *LocalTx, g int64, from []string) error {
	src := append([]string(nil), from...)
	sort.Strings(src)
	_, err := tx.Exec(ctx, recordAdoptionSQL, g, strings.Join(src, ","), time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

// VoterAdoption is one local_voter_adoption row.
type VoterAdoption struct {
	Generation   int64
	ImportedFrom []string
	AdoptedAt    string
}

// ListVoterAdoptions reads this node's adoption history, oldest first.
func ListVoterAdoptions(ctx context.Context, c *Client) ([]VoterAdoption, error) {
	rows, err := c.Query(ctx, `SELECT generation, imported_from, adopted_at FROM local_voter_adoption ORDER BY generation`)
	if err != nil {
		return nil, err
	}
	out := make([]VoterAdoption, 0, len(rows))
	for _, r := range rows {
		a := VoterAdoption{Generation: r.Int64("generation"), AdoptedAt: r.String("adopted_at")}
		if s := r.String("imported_from"); s != "" {
			a.ImportedFrom = strings.Split(s, ",")
		}
		out = append(out, a)
	}
	return out, nil
}

// ExpectedVoterConfigCertificate is what the certificate deciding next must
// certify, given the generation it replaces (prev, nil for the first
// generation). A generation that follows an empty one — genesis, or the first
// after a reset — is decided unanimously by its own members, because no
// earlier config has a majority that could decide it (§4.2). Every other is
// decided by a majority of prev (§4.3).
func ExpectedVoterConfigCertificate(prev *VoterConfig, next VoterConfigValue) (CertExpectation, error) {
	prevGen := int64(0)
	if prev != nil {
		prevGen = prev.Generation
	}
	if next.Generation != prevGen+1 {
		return CertExpectation{}, fmt.Errorf("generation %d does not follow %d", next.Generation, prevGen)
	}
	digest, err := ClaimValue{Config: &next}.Digest()
	if err != nil {
		return CertExpectation{}, err
	}
	want := CertExpectation{
		Key:              ClaimKey{TargetKind: ClaimKindVoterConfig, OwnerEpoch: prevGen},
		ValueDigest:      digest,
		ConfigGeneration: prevGen,
	}
	if prev.Explicit() {
		want.Electorate = prev.Members
		want.Quorum = MajorityOf(len(prev.Members))
	} else {
		if len(next.Members) == 0 {
			return CertExpectation{}, fmt.Errorf("an empty generation cannot follow an empty one")
		}
		want.Electorate = next.Members
		want.Quorum = len(next.Members)
	}
	return want, nil
}

// ValidateVoterChange checks that next is a change voters may decide from prev:
// exactly one member added or removed with every other member's entry
// unchanged, a reset to no members, or — after an empty generation — a
// genesis. It is checked by every voter before it accepts, and by every node
// before it adopts.
func ValidateVoterChange(prev *VoterConfig, next VoterConfigValue) error {
	prevGen := int64(0)
	if prev != nil {
		prevGen = prev.Generation
	}
	if next.Generation != prevGen+1 {
		return fmt.Errorf("generation %d does not follow %d", next.Generation, prevGen)
	}
	seen := map[string]bool{}
	for _, m := range next.Members {
		if m.Name == "" || m.Incarnation == "" {
			return fmt.Errorf("member entry %+v lacks a name or an incarnation", m)
		}
		if seen[m.Name] {
			return fmt.Errorf("member %s listed twice", m.Name)
		}
		seen[m.Name] = true
	}
	if !prev.Explicit() {
		if next.Change != VoterChangeGenesis || len(next.Members) == 0 {
			return fmt.Errorf("after an empty generation only a genesis with members may follow, got %q", next.Change)
		}
		return nil
	}
	if next.Change == VoterChangeReset {
		if len(next.Members) != 0 {
			return fmt.Errorf("a reset has no members")
		}
		return nil
	}
	old := map[string]string{}
	for _, m := range prev.Members {
		old[m.Name] = m.Incarnation
	}
	var added, removed []string
	for _, m := range next.Members {
		inc, was := old[m.Name]
		if !was {
			added = append(added, m.Name)
			continue
		}
		if inc != m.Incarnation {
			return fmt.Errorf("member %s's incarnation changed; that is a remove then an add, two generations", m.Name)
		}
	}
	for name := range old {
		if !seen[name] {
			removed = append(removed, name)
		}
	}
	switch {
	case len(added) == 1 && len(removed) == 0:
		if next.Change != VoterChangeAdd(added[0]) {
			return fmt.Errorf("change %q does not describe adding %s", next.Change, added[0])
		}
	case len(removed) == 1 && len(added) == 0:
		if len(next.Members) == 0 {
			return fmt.Errorf("removing the last voter empties the set; use a reset")
		}
		if next.Change != VoterChangeRm(removed[0]) {
			return fmt.Errorf("change %q does not describe removing %s", next.Change, removed[0])
		}
	default:
		return fmt.Errorf("a generation changes exactly one member (added %v, removed %v)", added, removed)
	}
	return nil
}
