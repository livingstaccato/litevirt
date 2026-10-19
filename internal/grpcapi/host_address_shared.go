package grpcapi

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// ── host.address_shared ─────────────────────────────────────────────────────
//
// An admission is refused at an address another live or joining host holds,
// by a check inside the admission's own write (corrosion.AdmitHost). That
// check sees only this replica: two admissions on two replicas, each made
// before the other's row arrived, both commit. The lease holder names every
// such pair once it holds both rows, and which of them keeps the address
// (corrosion.AddressWinner): only that one is activated.

const (
	hostAddressEvaluator  = "host_admission"
	condHostAddressShared = "host.address_shared"
	hostAddressSubject    = "hosts"
)

// sharedHostAddresses is host.address_shared's evidence, one line per
// address: the live or joining hosts that hold it at one gRPC port (a port of
// 0 is not known, and matches any).
func (s *Server) sharedHostAddresses(ctx context.Context) (map[string]string, []string, error) {
	rows, err := s.db.Query(ctx, `SELECT name, address, COALESCE(grpc_port, 0) AS port FROM hosts
		WHERE deleted_at IS NULL AND address <> '' ORDER BY address, name`)
	if err != nil {
		return nil, nil, err
	}
	winners := map[string]string{}
	for _, r := range rows {
		w, err := corrosion.AddressWinner(ctx, s.db, r.String("name"))
		if err != nil {
			return nil, nil, err
		}
		winners[r.String("name")] = w
	}
	type held struct {
		name string
		port int
	}
	byAddr := map[string][]held{}
	var order []string
	for _, r := range rows {
		a := r.String("address")
		if _, ok := byAddr[a]; !ok {
			order = append(order, a)
		}
		byAddr[a] = append(byAddr[a], held{r.String("name"), r.Int("port")})
	}
	lines := map[string]string{}
	var hosts []string
	for _, a := range order {
		hs := byAddr[a]
		for i := range hs {
			for j := i + 1; j < len(hs); j++ {
				x, y := hs[i], hs[j]
				if x.port != 0 && y.port != 0 && x.port != y.port {
					continue
				}
				port := x.port
				if port == 0 {
					port = y.port
				}
				at := a
				if port != 0 {
					at = a + ":" + strconv.Itoa(port)
				}
				won, lost := x.name, y.name
				if winners[y.name] == y.name || winners[x.name] == y.name {
					won, lost = y.name, x.name
				}
				lines[a+" "+x.name+" "+y.name] = fmt.Sprintf("%s and %s are both admitted at %s; %s, admitted "+
					"first, keeps the address, and %s is not activated while it does. The machine serves one of "+
					"them: remove the other (`lv host rm %s` or `lv host rm %s`; `lv host rm --dead` for one that is "+
					"fenced and gone for good).", x.name, y.name, at, won, lost, lost, won)
				hosts = append(hosts, x.name, y.name)
			}
		}
	}
	return lines, hosts, nil
}

// applyHostAddressShared raises host.address_shared for every address two
// live or joining hosts hold at one port, or resolves it when none does. The
// lease holder is the only writer.
func (s *Server) applyHostAddressShared(ctx context.Context) {
	lines, hosts, err := s.sharedHostAddresses(ctx)
	if err != nil {
		slog.Warn("host admission: evaluate shared host addresses", "error", err)
		return
	}
	s.applyClusterCondition(ctx, hostAddressEvaluator, condHostAddressShared, hostAddressSubject, lines, hosts,
		"hosts admitted at one address: ")
}
