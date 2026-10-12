package corrosion

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
)

// CheckVMSpecGrants is the check InsertVMWithReleaseFeatures makes, run by a
// caller before it creates anything (createVM, ahead of the define): for every
// combination of what the spec needs and which grants were taken, it refuses
// exactly when the writer refuses.
//
// Mutation: drop any one feature from CheckVMSpecGrants — the combinations
// that need it and lack its grant go red.
func TestCheckVMSpecGrants_AgreesWithTheWriter(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	grant := func(on bool, f capabilities.Feature) capabilities.FeatureGrant {
		if on {
			return capabilities.GrantForTest(t, f)
		}
		return capabilities.FeatureGrant{}
	}
	n := 0
	for needs := 0; needs < 8; needs++ {
		for held := 0; held < 8; held++ {
			nd := VMSpecFeatures{Tuning: needs&1 != 0, Passthrough: needs&2 != 0, Limits: needs&4 != 0}
			tg := grant(held&1 != 0, capabilities.FeatureVMDiskNICIO)
			pg := grant(held&2 != 0, capabilities.FeatureUSBMountsMemory)
			lg := grant(held&4 != 0, capabilities.FeatureVMLimits)
			n++
			name := fmt.Sprintf("v%d", n)
			werr := InsertVMWithReleaseFeatures(ctx, c, tg, pg, lg, nd,
				VMRecord{Name: name, HostName: "h1", State: "stopped", Spec: `{"name":"` + name + `"}`}, nil, nil, nil, nil, false)
			cerr := CheckVMSpecGrants(tg, pg, lg, nd)
			if werr != nil && !errors.Is(werr, capabilities.ErrNoFeatureGrant) {
				t.Fatalf("needs %+v held %03b: writer failed for another reason: %v", nd, held, werr)
			}
			if (werr == nil) != (cerr == nil) {
				t.Errorf("needs %+v held %03b: writer = %v, CheckVMSpecGrants = %v", nd, held, werr, cerr)
			}
			if cerr != nil && !errors.Is(cerr, capabilities.ErrNoFeatureGrant) {
				t.Errorf("needs %+v held %03b: CheckVMSpecGrants = %v, want ErrNoFeatureGrant", nd, held, cerr)
			}
		}
	}
}
