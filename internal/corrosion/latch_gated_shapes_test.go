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
		"stmtshape/v1:6450d3276c39ec8bf822855d4383a8e28f237e957f420516ca0755ce08894478",
		"stmtshape/v1:7ed4a32cf5eac0729d6dd4133bbbcf74826005634126d1e32504b864aa15982e",
		"stmtshape/v1:ab30a087c3d613badbf21d09a8699381fe9d6f5d73fe19ac96aad997eb32dfa4",
		"stmtshape/v1:e3428cc6a7557a34588a878ed81a5f47e59c17c11b1be584384d4afb0b832c8e",
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
