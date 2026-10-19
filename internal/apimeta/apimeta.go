// Package apimeta names the gRPC metadata the daemon and its clients (the
// CLI, REST, MCP and the web UI) exchange, so both sides use one spelling.
package apimeta

// InspectStaleHeader is the response header InspectVM sets when it answered
// from the entry node's replica because the VM's host could not be reached.
// Its value says which host did not answer and why.
const InspectStaleHeader = "x-litevirt-inspect-stale"

// AdmitInstallsReleaseHeader is the request metadata `lv host add` sets on
// AdmitHost: the release token of the build it installs on the machine, its
// own. A previous release's `lv` sets none, and the build it installs cannot
// keep a host incarnation, so AdmitHost refuses to issue one for it.
const AdmitInstallsReleaseHeader = "x-litevirt-admit-installs-release"
