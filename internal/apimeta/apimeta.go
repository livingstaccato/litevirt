// Package apimeta names the gRPC response metadata the daemon sets and its
// clients (the CLI, REST, MCP and the web UI) read, so both sides use one
// spelling.
package apimeta

// InspectStaleHeader is the response header InspectVM sets when it answered
// from the entry node's replica because the VM's host could not be reached.
// Its value says which host did not answer and why.
const InspectStaleHeader = "x-litevirt-inspect-stale"
