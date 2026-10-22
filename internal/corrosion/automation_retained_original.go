package corrosion

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
)

const retainedHeaderDomain = "litevirt/automation-original-aggregate/v1"
const maxRetainedHeaderBytes = 512 << 10

type retainedAggregateHeader struct {
	Version              int
	Purpose              string
	LayoutDigest         string
	Attempt              string
	Job                  string
	Revision             int64
	Host                 string
	Incarnation          string
	BindingObject        int64
	BindingDigest        string
	LocalRowsObject      int64
	LocalInventoryDigest string
	LocalID              string
	LocalDependency      string
	LocalCoverage        string
	Head                 AutomationPrefix
	Roster               []aggregateRosterEntry
	Coverage             string
}

// The admitted local layout is the compiled literal C table/column/key/shape
// inventory, including private observations and stage distinctions. Incoming
// metadata cannot supply SQL or register a compatible layout.
func retainedLocalLayoutDigest() string { return retainedLocalLayoutDigestFor(aggregateLocalTables()) }
func retainedLocalLayout83Digest() string {
	return retainedLocalLayoutDigestFor(aggregateLocalTables83())
}
func retainedLocalLayout85Digest() string {
	return retainedLocalLayoutDigestFor(aggregateLocalTables85())
}

func retainedLocalLayout87Digest() string {
	return retainedLocalLayoutDigestFor(aggregateLocalTables87())
}

func retainedLocalLayout88Digest() string {
	return retainedLocalLayoutDigestFor(aggregateLocalTables88())
}

func retainedLocalTablesForDigest(digest string) ([]aggregateLocalTable, error) {
	switch digest {
	case retainedLocalLayoutDigest():
		return aggregateLocalTables(), nil
	case retainedLocalLayout88Digest():
		return aggregateLocalTables88(), nil
	case retainedLocalLayout87Digest():
		return aggregateLocalTables87(), nil
	case retainedLocalLayout83Digest():
		return aggregateLocalTables83(), nil
	case retainedLocalLayout85Digest():
		return aggregateLocalTables85(), nil
	default:
		return nil, errors.New("unsupported retained local layout")
	}
}

func retainedLocalLayoutDigestFor(tables []aggregateLocalTable) string {
	h := sha256.New()
	sourceHash(h, []byte("litevirt/retained-local-layout/v1"))
	for _, d := range tables {
		stage := byte(0)
		if d.stage {
			stage = 1
		}
		sourceHash(h, []byte(d.table), []byte(d.columns), []byte(d.keys), []byte(d.shape), []byte{stage})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func decodeRetainedHeader(raw []byte) (retainedAggregateHeader, error) {
	var h retainedAggregateHeader
	if err := retainedCanonical(raw, maxRetainedHeaderBytes, &h); err != nil {
		return h, err
	}
	_, layoutErr := retainedLocalTablesForDigest(h.LayoutDigest)
	if h.Version != 1 || h.Purpose != "automation-original-aggregate" || layoutErr != nil ||
		!retainedField(h.Job, 128) || !retainedField(h.Host, 253) || !retainedField(h.Incarnation, 128) || h.Revision <= 0 ||
		h.BindingObject <= 0 || h.LocalRowsObject <= 0 || h.BindingObject == h.LocalRowsObject {
		return h, errors.New("invalid retained original header")
	}
	for _, d := range []string{h.Attempt, h.BindingDigest, h.LocalInventoryDigest, h.LocalID, h.LocalDependency, h.LocalCoverage, h.Coverage} {
		if !receiverDigest(d) {
			return h, errors.New("invalid retained original header digest")
		}
	}
	head, _ := json.Marshal(h.Head)
	roster, _ := json.Marshal(h.Roster)
	if len(head) > maxAutomationCutMetadataBytes || len(roster) > maxAutomationCutMetadataBytes ||
		h.Head.Sequence > math.MaxInt64 || (h.Head.Sequence == 0 && (h.Head.ClusterUID != "" || h.Head.Digest != "")) ||
		(h.Head.Sequence > 0 && (!retainedField(h.Head.ClusterUID, maxSourceFieldBytes) || !receiverDigest(h.Head.Digest))) ||
		len(h.Roster) == 0 || len(h.Roster) > MaxAutomationVoters {
		return h, errors.New("invalid retained original head or roster")
	}
	for i, r := range h.Roster {
		if !retainedField(r.Source, 253) || !retainedField(r.Incarnation, 128) || !retainedNativeIdentity(r.Cut) || (i > 0 && h.Roster[i-1].Source >= r.Source) {
			return h, errors.New("invalid retained original roster identity")
		}
		for _, d := range []string{r.Audit, r.Publication, r.Root, r.Coverage} {
			if !receiverDigest(d) {
				return h, errors.New("invalid retained original roster digest")
			}
		}
	}
	return h, nil
}

func (h retainedAggregateHeader) originalBinding(raw []byte) (*receiverPredecessor, string, error) {
	p, err := decodeReceiverBinding(h.Attempt, h.Job, h.Revision, raw)
	if err != nil {
		return nil, "", err
	}
	if h.BindingDigest != sourceDigest(raw) || p.value.Intent.Target != h.Host || p.value.Facts.Incarnation != h.Incarnation ||
		len(h.Roster) != len(p.value.Intent.Sources) || len(h.Roster) < MajorityOf(len(p.value.Facts.Old.Members)) {
		return nil, "", errors.New("retained original binding or whole electorate differs")
	}
	for i, r := range h.Roster {
		member := p.value.Intent.Sources[i]
		if r.Source != member.Name || r.Incarnation != member.Incarnation || r.Audit != sourceDigest([]byte("litevirt/receiver-source-audit/v1"), []byte(h.Attempt), []byte(r.Source), []byte(r.Publication), []byte(r.Root)) {
			return nil, "", errors.New("retained original audit identity differs")
		}
	}
	roster, _ := json.Marshal(h.Roster)
	head, _ := json.Marshal(h.Head)
	if h.LocalID != sourceDigest([]byte("litevirt/local-audit/v1"), []byte(h.Attempt), []byte(h.LocalDependency)) ||
		h.Coverage != sourceDigest([]byte("litevirt/aggregate-coverage/v1"), []byte(h.LocalCoverage), roster) {
		return nil, "", errors.New("retained original local or coverage identity differs")
	}
	id := sourceDigest([]byte("litevirt/receiver-aggregate/v1"), []byte(h.Attempt), raw, []byte(h.LocalID), []byte(h.LocalDependency), head, []byte(h.Coverage), roster)
	return p, id, nil
}
