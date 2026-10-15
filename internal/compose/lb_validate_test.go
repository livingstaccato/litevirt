package compose

import (
	"strings"
	"testing"
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
