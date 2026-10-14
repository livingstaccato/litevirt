package ui

import (
	"net/http"
	"testing"

	"google.golang.org/grpc/metadata"

	"github.com/litevirt/litevirt/internal/apimeta"
)

// An inspect the daemon answered from its replica says so on the VM page,
// as the CLI and REST do.
//
// Mutation: drop the header read — the page carries no note.
func TestHandler_VMDetail_ShowsTheStaleNote(t *testing.T) {
	mock := newDefaultMock()
	mock.inspectVMHeader = metadata.Pairs(apimeta.InspectStaleHeader, "host node-1 did not answer")
	s := newTestUIServer(t, mock)
	w := serveRequest(s, withAuth(mustReq(t, "GET", "/vms/vm1")))
	assertStatus(t, w, http.StatusOK)
	assertContains(t, w, "host node-1 did not answer")
}
