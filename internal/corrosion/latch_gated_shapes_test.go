package corrosion

import (
	"slices"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
)

// frozenLatchGatedShapes pins, per release token, the fingerprints of the
// statements written only once that token has latched (latchGatedShapes).
// Every build that advertises a token must know every one of its shapes, so a
// shipped token's list is frozen exactly as frozenReleaseFeatures freezes its
// features: editing an existing entry is a release-engineering decision, right
// only before that release ships, made here and in latchGatedShapes together.
// A shape added later is gated on the next release token, pinned as a new
// entry.
var frozenLatchGatedShapes = map[string][]string{
	capabilities.Release202611V1: {
		"stmtshape/v1:3dae2011a5b17b43e4de11f54abb66cc9739167882977bbd18bf2470e9a567da", // readmitHostV2SQL (host_incarnation)
		"stmtshape/v1:6450d3276c39ec8bf822855d4383a8e28f237e957f420516ca0755ce08894478",
		"stmtshape/v1:7ed4a32cf5eac0729d6dd4133bbbcf74826005634126d1e32504b864aa15982e",
		"stmtshape/v1:83f910f2e35a4b7ab7ac51f5dee634c2b37925838de6ac23c1543786c14de656", // hostOwnEndpointSQL (host_incarnation)
		"stmtshape/v1:ab30a087c3d613badbf21d09a8699381fe9d6f5d73fe19ac96aad997eb32dfa4",
		"stmtshape/v1:d91a17399ef8d0d2ea02dd132405a64a053f9aea5c6b7cfaac9cd18cf1665f66", // deleteHostAdmissionSQL (RemoveHost)
		"stmtshape/v1:e3428cc6a7557a34588a878ed81a5f47e59c17c11b1be584384d4afb0b832c8e",
	},
	// Not shipped yet: corrected only by one reviewed change here and in
	// latchGatedShapes together.
	capabilities.Release202612V1: {
		"stmtshape/v1:82fe2007c26d71d40ae839297bea613768791ec4a0ec0b681d352570dda9c59b", // HostFenceSSHUpsertSQL (fence_ssh)
	},
	// Not shipped yet (the rc2 train): corrected only by one reviewed change
	// here and in latchGatedShapes together.
	capabilities.Release202701V1: {
		"stmtshape/v1:6f039aff36330ccd98dff94968e61f991c6c11c1a6ea34e3687e68763b509c1b", // projectsAdoptIncarnationSQL (project_adoption)
	},
	// Not shipped yet (F1): corrected only by one reviewed change here and in
	// latchGatedShapes together.
	capabilities.Release202702V1: {
		"stmtshape/v1:34c2e0c1e7ebc2e4e34bbcc475ac4093bd33cf1b70c97c3f656cb0bf0bc1e1de", // storagePoolBirthSQL (catalog_incarnation)
		"stmtshape/v1:512af81cfa9173a60e2eed52a53e24d6f776f5b4ecb9015d7ded49ce6f15853d", // imageBirthSQL (catalog_incarnation)
		"stmtshape/v1:74d6132826649e2ef6f5bf5e523e6e3521c41bb7f811bc59b2e3f84da7d3066e", // storagePoolMutateSQL (catalog_incarnation)
		"stmtshape/v1:b7f486e9a5bc30558b24a87df6ff6752eb43bdc28b8309ee7fdbb1ab0a7ead52", // imageContinueSQL (catalog_incarnation)
		"stmtshape/v1:c02913c78cfed1908d03aad604cabdab49415bf1ba1b38da7c1073803d64edce", // imageLifetimeDeleteSQL (catalog_incarnation)
		"stmtshape/v1:db66476377d56ccad4cc2b2211d2d3c01c69ed45dedad555f0e1d8758f587d20", // storagePoolLifetimeDeleteSQL (catalog_incarnation)
	},
}

// TestLatchGatedShapesAreFrozen (review round 1, m-3): each token's latch-gated
// statements fingerprint to exactly its pinned list, every one is in the
// ledger, and every token is a release token with a pin.
func TestLatchGatedShapesAreFrozen(t *testing.T) {
	releases := capabilities.ReleaseTokens()
	for tok, stmts := range latchGatedShapes {
		if !slices.Contains(releases, tok) {
			t.Errorf("latch-gated shapes are declared under %s, which is not a release token", tok)
		}
		var got []string
		for _, q := range stmts {
			fp, err := FingerprintSQL(q)
			if err != nil {
				t.Fatalf("fingerprint %q: %v", q, err)
			}
			if _, ok := LedgerLookup(fp); !ok {
				t.Errorf("latch-gated shape %s is not in the ledger", fp)
			}
			got = append(got, fp)
		}
		slices.Sort(got)
		want, ok := frozenLatchGatedShapes[tok]
		if !ok {
			t.Errorf("release token %s has latch-gated shapes but no pinned list in frozenLatchGatedShapes: %v", tok, got)
			continue
		}
		if !slices.Equal(got, want) {
			t.Errorf("latch-gated shapes under %s = %v, want exactly %v: a shipped release token's shapes are frozen; "+
				"gate a new shape on the next release token", tok, got, want)
		}
	}
	for tok := range frozenLatchGatedShapes {
		if _, ok := latchGatedShapes[tok]; !ok {
			t.Errorf("frozenLatchGatedShapes pins %s, which declares no latch-gated shapes", tok)
		}
	}
}
