package ui

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// synfloodRow is one host's row of the firewall page's SYN-flood panel.
type synfloodRow struct {
	Host, Policy, InForce, Rate, Burst, From, DropsV4, DropsV6, Error string
}

// handleFWSynflood renders the SYN-flood panel: the cluster's policy, then
// per host its policy and what the host itself has in force (as `lv firewall
// synflood status` shows them). It is loaded after the page, since the daemon
// asks every host.
func (s *Server) handleFWSynflood(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(s.uiBearerCtx(r), 30*time.Second)
	defer cancel()
	resp, err := s.grpc.GetFirewallSynflood(ctx, &pb.GetFirewallSynfloodRequest{})
	data := map[string]any{}
	switch {
	case status.Code(err) == codes.Unimplemented:
		data["Unsupported"] = true
	case err != nil:
		data["Err"] = status.Convert(err).Message()
	case len(resp.GetPolicies()) == 0:
		data["Err"] = "the daemon returned no SYN-flood policy"
	default:
		ps := resp.GetPolicies()
		data["Cluster"] = synfloodPolicyText(ps[0])
		var rows []synfloodRow
		for _, p := range ps[1:] {
			row := synfloodRow{Host: strings.TrimPrefix(p.GetScope(), "host/"), Policy: p.GetMode(), From: "host",
				Rate: "-", Burst: "-", DropsV4: "-", DropsV6: "-", Error: p.GetError()}
			if p.GetInherited() {
				row.From = "cluster"
			}
			if p.GetMode() == "on" {
				row.Rate, row.Burst = fmt.Sprint(p.GetRate()), fmt.Sprint(p.GetBurst())
			}
			// A count that could not be read is "-", never a 0.
			if p.GetError() == "" {
				row.DropsV4, row.DropsV6 = fmt.Sprint(p.GetDropsV4()), fmt.Sprint(p.GetDropsV6())
			}
			switch {
			case p.GetInForce() != "":
				row.InForce = p.GetInForce()
			case p.GetError() != "":
				row.InForce = "-"
			default:
				row.InForce = "predates" // the host's daemon does not report it
			}
			rows = append(rows, row)
		}
		data["Rows"] = rows
	}
	s.renderFragment(w, "firewall_synflood.html", data)
}

func synfloodPolicyText(p *pb.FirewallSynfloodPolicy) string {
	if p.GetMode() != "on" {
		return p.GetMode()
	}
	return fmt.Sprintf("on, %d/second burst %d", p.GetRate(), p.GetBurst())
}
