package corrosion

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/litevirt/litevirt/internal/pki"
)

func (a retainedFrameAddress) publication(ctx context.Context, tx *LocalTx, d retainedObjectDescriptor, original *receiverPredecessor, roster aggregateRosterEntry, view *pki.HostTrust) (receiverPublication, error) {
	var out receiverPublication
	root := view.RootDigest()
	if view == nil || original == nil || original.value.Root != hex.EncodeToString(root[:]) {
		return out, errors.New("retained original trust root differs from current receiver")
	}
	if original == nil || original.value.Facts.Old == nil || original.value.Facts.Next == nil || d.Kind != "source" || d.Source != roster.Source || d.Incarnation != roster.Incarnation || d.OriginalIdentity != roster.Publication || roster.Audit != sourceDigest([]byte("litevirt/receiver-source-audit/v1"), []byte(original.id), []byte(roster.Source), []byte(roster.Publication), []byte(roster.Root)) {
		return out, errors.New("retained publication original identity differs")
	}
	var raw [3][]byte
	if err := a.walk(ctx, tx, d, func(component int, n int64, body []byte) error {
		if component < 3 {
			if int64(len(body)) > receiverMetadataLimits[component]-int64(len(raw[component])) {
				return errors.New("retained publication metadata exceeds bound")
			}
			raw[component] = append(raw[component], body...)
		}
		return nil
	}); err != nil {
		return out, err
	}
	p, err := decodeSourcePublication(roster.Publication, raw[0], raw[1], raw[2])
	if err != nil {
		return out, err
	}
	m := p.manifest
	facts := original.value.Facts
	member, ok := facts.Old.Member(m.Source)
	if !ok || member.Incarnation != m.Incarnation || m.Source != roster.Source || m.Incarnation != roster.Incarnation || m.Cut.ID != roster.Cut || m.Root != roster.Root || !sameSourceRequest(m.Request, original.value.Intent) || m.Target.Host != original.value.Intent.Target || m.Target.Incarnation != facts.Incarnation || m.OldValue != sourceConfigDigest(facts.Old) || m.NextValue != sourceConfigDigest(facts.Next) || m.OldMembers != facts.Old.MembersHash || m.NextMembers != facts.Next.MembersHash || m.Cut.MembersHash != facts.Old.MembersHash || m.TrustDomain != original.value.Root {
		return out, errors.New("retained publication original context differs")
	}
	cut, _ := json.Marshal(m.Cut.Inventory)
	descriptor, _ := json.Marshal(d.ComponentInventories[3:])
	if !bytes.Equal(cut, descriptor) {
		return out, errors.New("retained publication cut inventory differs")
	}
	var signed sourceSignedArtifact
	if err = json.Unmarshal(raw[0], &signed); err != nil {
		return out, err
	}
	// Recorded source authorization and signature/whole-context checks above
	// precede this pure current-path check. Later original leaf retirement does
	// not revoke transferred provenance; current holder authorization stays strict.
	if out.notBefore, out.notAfter, err = view.VerifyOriginalHostProvenance(signed.Chain, m.Source); err != nil {
		return out, err
	}
	out.id, out.manifest, out.chain = p.id, m, signed.Chain
	for i, b := range raw {
		out.metadataBytes[i] = int64(len(b))
		out.metadataDigests[i] = sha256.Sum256(b)
	}
	// This is immutable original evidence only. Current holder authorization and
	// its actual consumed receipt remain separate prerequisites for completion.
	return out, nil
}
