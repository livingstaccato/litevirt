package main

import (
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// The capacity table's DB cell shows what VMs hold and, apart, the memory
// running containers hold, so an operator can tell the two apart; a host with
// no containers reads exactly as before.
func TestCapacityDBCell(t *testing.T) {
	cases := []struct {
		c    *pb.HostCapacityAssessment
		want string
	}{
		{&pb.HostCapacityAssessment{DbCpu: 1, DbMemMib: 1280, DbCtMemMib: 512}, "1c/768MiB +512MiB ct"},
		{&pb.HostCapacityAssessment{DbCpu: 0, DbMemMib: 512, DbCtMemMib: 512}, "0c/0MiB +512MiB ct"},
		{&pb.HostCapacityAssessment{DbCpu: 2, DbMemMib: 2048}, "2c/2048MiB"},
	}
	for _, tc := range cases {
		if got := capacityDBCell(tc.c); got != tc.want {
			t.Errorf("capacityDBCell(%v) = %q, want %q", tc.c, got, tc.want)
		}
	}
}
