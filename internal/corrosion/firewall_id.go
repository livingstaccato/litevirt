package corrosion

// The firewall identity, fw_id (firewall extras spec §4.3): a 32-hex random id
// naming one logical workload for its whole life. A VM holds it in the
// server-owned VMSpec.firewall_id, a container in the create_spec key fw_id.
// Only the server mints it (MintFirewallID), and membership in a tag group is
// decided by it alone.
//
// Every writer of vms.spec and containers.create_spec runs its new value
// through keepFirewallID, so a client cannot set an identity and an ordinary
// write cannot drop or change one:
//
//   - a row-INSERT for a new workload stores none, unless the caller passes a
//     FirewallIDCarry token naming the workload it replaces;
//   - an update stores the current row's value;
//   - a carry insert (container re-key and relocation) stores the source row's;
//   - ReplaceVM stores the replacement VM's own.
//
// firewall_id_guard_test.go finds these writers by the parsed statement
// columns and fails on one that does not call keepFirewallID.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
)

const (
	// vmFirewallIDKey and ctFirewallIDKey are the canonical keys of the
	// identity in vms.spec and containers.create_spec. A reader matches the key
	// exactly (jsonExactString).
	vmFirewallIDKey = "firewall_id"
	ctFirewallIDKey = "fw_id"
)

// ErrFirewallIDNotMinted is MintFirewallID's refusal when the workload is gone,
// an operation holds it, or it changed under the write. The caller retries.
var ErrFirewallIDNotMinted = errors.New("firewall identity not minted: the workload is gone, busy or changed; retry")

// ErrFirewallIDNoCreateSpec refuses to mint for a container an earlier build
// created, whose row has no create spec: a peer move reads an empty create
// spec as "keep the archive's bridge NICs", which an identity-only spec would
// change into "no NICs".
var ErrFirewallIDNoCreateSpec = errors.New("the container has no create spec (an earlier build created it), so it cannot hold a firewall identity")

// errFirewallIDSpec refuses to keep an identity in a value that is not a JSON
// object, which nothing could read it from.
var errFirewallIDSpec = errors.New("cannot keep a firewall identity in a spec that is not a JSON object")

// FirewallIDCarry is a token that lets a row-INSERT keep the identity of the
// workload it re-creates. Only CarryFirewallID makes a non-zero one, and
// firewall_id_guard_test.go lists the callers allowed to call it. The zero value
// carries nothing.
type FirewallIDCarry struct {
	kind, id string
}

// CarryFirewallID returns a token carrying the identity that source holds:
// a VM's stored spec (kind TagMemberVM) or a container's stored create_spec
// (TagMemberCT). source must be read from a LIVE row, or from the tombstone the
// carrying operation's own delete wrote (spec §4.3); the carry guard checks
// where each call obtains it. A source with no valid identity gives the zero
// token.
func CarryFirewallID(kind, source string) FirewallIDCarry {
	id := firewallIDOf(kind, source)
	if id == "" {
		return FirewallIDCarry{}
	}
	return FirewallIDCarry{kind: kind, id: id}
}

// idFor is the identity the token carries for a workload of kind ("" if none).
func (t FirewallIDCarry) idFor(kind string) string {
	if t.kind != kind {
		return ""
	}
	return t.id
}

// firewallIDKey is kind's canonical identity key.
func firewallIDKey(kind string) string {
	switch kind {
	case TagMemberVM:
		return vmFirewallIDKey
	case TagMemberCT:
		return ctFirewallIDKey
	}
	panic("corrosion: unknown firewall identity kind " + kind)
}

// firewallIDOf is the identity doc holds, read as ListTagGroupMembers reads it:
// the canonical key matched exactly, and a well-formed id. "" otherwise.
func firewallIDOf(kind, doc string) string {
	id := jsonExactString(doc, firewallIDKey(kind))
	if !ValidFirewallID(id) {
		return ""
	}
	return id
}

// identityKeyCache memoises isFirewallIDKey per kind and key.
var identityKeyCache sync.Map

// isFirewallIDKey reports whether a top-level member named key would be READ
// as the identity by a decoder the tree uses on that column: encoding/json into
// pb.VMSpec (which folds case, including Unicode folds) and protojson (which
// also takes the JSON name firewallId) for a VM spec; encoding/json for a
// container create_spec. It asks the decoders, never compares spellings.
func isFirewallIDKey(kind, key string) bool {
	ck := kind + "\x00" + key
	if v, ok := identityKeyCache.Load(ck); ok {
		return v.(bool)
	}
	probe, err := json.Marshal(map[string]string{key: "x"})
	hit := false
	if err == nil {
		switch kind {
		case TagMemberVM:
			var s pb.VMSpec
			_ = json.Unmarshal(probe, &s)
			hit = s.FirewallId == "x"
			if !hit {
				var p pb.VMSpec
				if (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(probe, &p) == nil {
					hit = p.FirewallId == "x"
				}
			}
		case TagMemberCT:
			var s struct {
				FWID string `json:"fw_id"`
			}
			_ = json.Unmarshal(probe, &s)
			hit = s.FWID == "x"
		default:
			panic("corrosion: unknown firewall identity kind " + kind)
		}
	}
	identityKeyCache.Store(ck, hit)
	return hit
}

// topLevelMembers returns doc's top-level object members in order, duplicates
// included. ok is false when doc is not a JSON object.
func topLevelMembers(doc string) (keys []string, values []json.RawMessage, ok bool) {
	dec := json.NewDecoder(bytes.NewReader([]byte(doc)))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, nil, false
	}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, nil, false
		}
		k, isStr := kt.(string)
		if !isStr {
			return nil, nil, false
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, nil, false
		}
		keys, values = append(keys, k), append(values, v)
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return nil, nil, false
	}
	if _, err := dec.Token(); err == nil {
		return nil, nil, false // trailing content
	}
	return keys, values, true
}

// keepFirewallID returns next, the value a writer is about to store in
// vms.spec (kind TagMemberVM) or containers.create_spec (TagMemberCT), holding
// exactly the identity keep: every top-level member a decoder would read as the
// identity is removed (whatever its spelling: case and Unicode folds, JSON
// escapes, protojson's firewallId, duplicates), and keep, when not "", is set
// under the canonical key. next is returned byte-identical when it already
// holds exactly keep, and when keep is "" and nothing reads an identity from
// it. Other members are kept verbatim, including ones this build does not know.
func keepFirewallID(kind, next, keep string) (string, error) {
	key := firewallIDKey(kind)
	if keep != "" && !ValidFirewallID(keep) {
		return "", fmt.Errorf("corrosion: %q is not a firewall identity", keep)
	}
	if next == "" || next == "null" {
		if keep == "" {
			return next, nil
		}
		b, err := json.Marshal(map[string]string{key: keep})
		return string(b), err
	}
	keys, values, ok := topLevelMembers(next)
	if !ok {
		// Not a JSON object: no reader takes an identity from it.
		if keep == "" {
			return next, nil
		}
		return "", errFirewallIDSpec
	}
	var hits []int
	for i, k := range keys {
		if isFirewallIDKey(kind, k) {
			hits = append(hits, i)
		}
	}
	switch {
	case keep == "" && len(hits) == 0:
		return next, nil
	case keep != "" && len(hits) == 1 && keys[hits[0]] == key:
		var s string
		if json.Unmarshal(values[hits[0]], &s) == nil && s == keep {
			return next, nil
		}
	}
	m := make(map[string]json.RawMessage, len(keys)+1)
	for i, k := range keys {
		m[k] = values[i]
	}
	for _, i := range hits {
		delete(m, keys[i])
	}
	if keep != "" {
		m[key], _ = json.Marshal(keep)
	}
	b, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// newFirewallID mints a fresh identity.
func newFirewallID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("corrosion: no randomness for a firewall identity: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}

// MintFirewallID gives the live workload (kind TagMemberVM: name; TagMemberCT:
// host and name) a firewall identity and returns it. It keeps the identity the
// row holds unless another row of the kind, live or tombstoned, holds the same
// one: such an id was copied, not minted (a value stored verbatim before the
// writers kept the identity), and a copy must never inherit membership. Then,
// and when the row holds none, it mints a fresh one.
//
// Only `lv firewall tag set` calls it, with the firewall_tag_groups grant. A VM
// mints through the desired-spec writer, under its operation barrier; a
// container through the compare-and-set on its create_spec, refused while an
// operation holds it. ErrFirewallIDNotMinted means the caller retries; a
// container with no create spec is refused (ErrFirewallIDNoCreateSpec).
func MintFirewallID(ctx context.Context, c *Client, g capabilities.FeatureGrant, kind, host, name string) (string, error) {
	if err := g.Check(capabilities.FeatureFirewallTagGroups); err != nil {
		return "", err
	}
	switch kind {
	case TagMemberVM:
		var minted string
		applied, _, err := mutateDesiredSpec(ctx, c, name,
			func(old string) (string, error) { return old, nil },
			func(old string) (string, error) {
				id, err := uniqueFirewallID(ctx, c, kind, "", name, firewallIDOf(kind, old))
				minted = id
				return id, err
			})
		if err != nil {
			return "", err
		}
		if !applied {
			return "", ErrFirewallIDNotMinted
		}
		return minted, nil
	case TagMemberCT:
		return mintContainerFirewallID(ctx, c, host, name)
	}
	return "", fmt.Errorf("corrosion: unknown firewall identity kind %q", kind)
}

// uniqueFirewallID returns cur when no other row of kind holds it, and a fresh
// identity otherwise (or when cur is "").
func uniqueFirewallID(ctx context.Context, c *Client, kind, host, name, cur string) (string, error) {
	if cur == "" {
		return newFirewallID(), nil
	}
	var rows []Row
	var err error
	if kind == TagMemberVM {
		rows, err = c.Query(ctx, `SELECT '' AS host_name, name, spec AS doc FROM vms WHERE name != ?`, name)
	} else {
		rows, err = c.Query(ctx,
			`SELECT host_name, name, COALESCE(create_spec, '') AS doc FROM containers
			 WHERE NOT (host_name = ? AND name = ?)`, host, name)
	}
	if err != nil {
		return "", err
	}
	for _, r := range rows {
		if firewallIDOf(kind, r.String("doc")) == cur {
			return newFirewallID(), nil
		}
	}
	return cur, nil
}

// mintContainerFirewallID is MintFirewallID for a container: the
// create_spec compare-and-set MintContainerPlacement uses, so a concurrent
// change of the row's create_spec makes it write nothing.
func mintContainerFirewallID(ctx context.Context, c *Client, host, name string) (string, error) {
	if !c.RepointReady(ctx) {
		return "", fmt.Errorf("%w: the release token has not latched", ErrFirewallIDNotMinted)
	}
	rows, err := c.Query(ctx,
		`SELECT COALESCE(create_spec, '') AS create_spec, COALESCE(active_operation_id, '') AS active_operation_id
		 FROM containers WHERE host_name = ? AND name = ? AND deleted_at IS NULL`, host, name)
	if err != nil {
		return "", err
	}
	if len(rows) == 0 || rows[0].String("active_operation_id") != "" {
		return "", ErrFirewallIDNotMinted
	}
	current := rows[0].String("create_spec")
	if current == "" {
		return "", ErrFirewallIDNoCreateSpec
	}
	id, err := uniqueFirewallID(ctx, c, TagMemberCT, host, name, firewallIDOf(TagMemberCT, current))
	if err != nil {
		return "", err
	}
	next, err := keepFirewallID(TagMemberCT, current, id)
	if err != nil {
		return "", err
	}
	if next == current {
		return id, nil
	}
	n, err := c.ExecuteRowsStrict(ctx, containerPlacementMintSQL, next, c.NowTS(), host, name, current)
	if errors.Is(err, ErrNoRowsAffected) || err == nil && n == 0 {
		return "", ErrFirewallIDNotMinted
	}
	if err != nil {
		return "", err
	}
	return id, nil
}
