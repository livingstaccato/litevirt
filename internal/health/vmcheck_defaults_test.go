package health

import (
	"fmt"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
)

// What `lv compose up` shows for a healthcheck with every default must be what
// this checker does with it: the sweep interval, the probe timeout, the
// retries and the action it falls back to.
func TestComposeDescribeMatchesTheCheckersDefaults(t *testing.T) {
	f, err := compose.ParseBytes([]byte("name: s\nvms:\n  web:\n    image: u\n    healthcheck:\n      target: \"22\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	empty := &pb.HealthCheckSpec{}
	want := fmt.Sprintf("tcp (inferred) <vm address>:22 every %s, timeout %s, %d retries, then %s",
		vmCheckSweepInterval, probeTimeout(empty), probeRetries(empty), probeAction(empty))
	if got := f.VMs["web"].HealthCheck.Describe(); got != want {
		t.Errorf("Describe() = %q\n    checker = %q", got, want)
	}
}
