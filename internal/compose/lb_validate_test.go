package compose

import (
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
)

const lbBase = `name: STACK
images:
  img:
    source: file:///dev/null
vms:
  web:
    image: img
    loadbalancer:
      enabled: true
      vip: 10.0.0.50/24
      algorithm: ALGO
      ports:
        - listen: 80
          target: 8080
          protocol: PROTO80
          redirect-https: true
        - listen: 443
          target: 8080
          protocol: http
          tls:
            cert: /etc/litevirt/lb-certs/a.crt
            key: /etc/litevirt/lb-certs/a.key
      health:
        type: http
        path: PATH
`

func lbFile(stack, algo, proto80, path string) string {
	return strings.NewReplacer("STACK", stack, "ALGO", algo, "PROTO80", proto80, "PATH", path).Replace(lbBase)
}

// TestValidate_LBValuesAndStackName: compose validation refuses a stack
// name that is not a safe name, and LB values that would not render as one
// plain token or are outside their enums, including a newline injected into
// a quoted YAML string; and redirect-https on a tcp listener.
//
// Mutations (each red): drop the stack-name check; drop the CheckSettings
// loop in validate.
func TestValidate_LBValuesAndStackName(t *testing.T) {
	if _, err := ParseBytes([]byte(lbFile("shop", "roundrobin", "http", "/healthz"))); err != nil {
		t.Fatalf("valid file refused: %v", err)
	}
	for name, yaml := range map[string]string{
		"stack name":  lbFile(`"../../profile.d/$(id)"`, "roundrobin", "http", "/healthz"),
		"algorithm":   lbFile("shop", `"roundrobin\nglobal\n    pidfile /x"`, "http", "/healthz"),
		"health path": lbFile("shop", "roundrobin", "http", `"/x\nglobal\n    pidfile /etc/litevirt/pki/host.key"`),
		"protocol":    lbFile("shop", "roundrobin", `"http\nglobal"`, "/healthz"),
		"redirect":    lbFile("shop", "roundrobin", "tcp", "/healthz"),
	} {
		if _, err := ParseBytes([]byte(yaml)); err == nil {
			t.Errorf("%s: file accepted", name)
		}
	}
}

// TestValidate_OneLoadBalancerPerStack (M2): a stack has one LB, so two
// enabled loadbalancer sections are refused rather than applied over each
// other.
func TestValidate_OneLoadBalancerPerStack(t *testing.T) {
	two := lbFile("shop", "roundrobin", "http", "/healthz") + `  api:
    image: img
    loadbalancer:
      vip: 10.0.0.51/24
      ports:
        - listen: 81
          target: 8081
`
	_, err := ParseBytes([]byte(two))
	if err == nil || !strings.Contains(err.Error(), "one load balancer") {
		t.Errorf("two loadbalancer sections: %v", err)
	}
}

// TestValidate_IdenticalLBCopiesParse (I-R1): the documented extends
// pattern, a replicas: 0 base carrying the stack's loadbalancer and children
// that extend it, and a YAML anchor reusing one LB block, give every VM the
// same definition: one LB, which parses as on main.
//
// Mutation: compare by presence (any second enabled LB) instead of
// proto.Equal — red.
func TestValidate_IdenticalLBCopiesParse(t *testing.T) {
	extends := `name: shop
images:
  img:
    source: file:///dev/null
vms:
  base:
    image: img
    replicas: 0
    loadbalancer:
      vip: 10.0.0.50/24
      ports:
        - listen: 80
          target: 8080
  web:
    extends: base
    replicas: 2
  api:
    extends: base
`
	f, err := ParseBytes([]byte(extends))
	if err != nil {
		t.Fatalf("extends base with an LB refused: %v", err)
	}
	if !proto.Equal(BuildLBSpec(f.VMs["web"].LoadBalancer), BuildLBSpec(f.VMs["api"].LoadBalancer)) {
		t.Error("children of one base carry different LBs")
	}
	anchor := `name: shop
images:
  img:
    source: file:///dev/null
vms:
  web:
    image: img
    loadbalancer: &lb
      vip: 10.0.0.50/24
      ports:
        - listen: 80
          target: 8080
  api:
    image: img
    loadbalancer: *lb
`
	if _, err := ParseBytes([]byte(anchor)); err != nil {
		t.Errorf("one LB block reused by an anchor refused: %v", err)
	}
	// A child that overrides the LB is a second, different definition.
	differ := extends + `    loadbalancer:
      vip: 10.0.0.51/24
      ports:
        - listen: 81
          target: 8081
`
	_, err = ParseBytes([]byte(differ))
	if err == nil || !strings.Contains(err.Error(), "differs from") {
		t.Errorf("differing LB definitions: %v", err)
	}
}
