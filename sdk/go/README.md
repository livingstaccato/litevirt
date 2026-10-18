# LiteVirt Go SDK

Package `litevirt` provides typed clients for the public Automation service, including independent submission, lookup, observation and recovery-aware waiting.

This SDK is currently for source development. Its module is `github.com/livingstaccato/litevirt/sdk/go`; public request and response types come from `github.com/livingstaccato/litevirt/api/gen/litevirt/automation/v1`. The [module file](go.mod) requires Go 1.26.0 and uses API version `v0.0.0` with a local `replace` to `../../api`. Preserve that source layout while developing. The placeholder version and local replacement must be replaced with released dependencies before publication; they are not a public installation recipe.

Production Automation service integration, authorization/durability validation and real VM acceptance remain pending. The [executable examples](example_test.go) exercise ephemeral TLS implementations of the generated service; their fixture credentials and VM input do not describe a deployed server.

## Configure trust and enroll

Use static `host:port` endpoints, server-verifying TLS and an existing credential source. The SDK does not log in or store credentials. These fragments belong inside application functions that return an error; imports used across them are:

```go
import (
    "context"
    "crypto/tls"
    "errors"
    "time"

    av "github.com/livingstaccato/litevirt/api/gen/litevirt/automation/v1"
    lv "github.com/livingstaccato/litevirt/sdk/go"
)
```

The following configuration adapts `ExampleEnroll`. `trustedRoots` is your application's `*x509.CertPool`, `currentToken` is your concurrency-safe `func(context.Context) (string, error)`, and endpoint names are placeholders. Supply your actual trust roots, credential provider and service addresses.

```go
config := lv.Config{
    Endpoints: []string{"node-a.example:8443", "node-b.example:8443"},
    TLSConfig: &tls.Config{
        RootCAs: trustedRoots,
        MinVersion: tls.VersionTLS12,
    },
    CredentialSource: currentToken,
    RequiredCapabilities: []av.EnforcedFeature{
        av.EnforcedFeature_ENFORCED_FEATURE_AUTHORITATIVE_READS,
        av.EnforcedFeature_ENFORCED_FEATURE_DURABLE_IDEMPOTENCY,
    },
    DefaultDeadline: time.Minute,
}
```

For first enrollment, leave `ExpectedClusterUID` empty and explicitly discover the TLS-authenticated identity:

```go
enrollCtx, cancelEnrollment := context.WithTimeout(context.Background(), 10*time.Second)
discovered, err := lv.Enroll(enrollCtx, config)
cancelEnrollment()
if err != nil {
    return err
}
// Application step: inspect and accept discovered.ClusterUid and capabilities,
// then durably persist the accepted UID before constructing an ordinary client.
```

Enrollment returns capabilities; it does not accept or persist trust for you. The application must complete the acceptance step before proceeding. On subsequent starts, load the previously accepted UID instead of enrolling again. `savedClusterUID` below is that persisted value:

```go
config.ExpectedClusterUID = savedClusterUID
client, err := lv.NewClient(config)
if err != nil {
    return err
}
defer client.Close()
```

`NewClient` validates configuration without networking. Ordinary clients reject an empty expected UID with `ErrEnrollmentRequired`; they never learn a replacement UID on reconnect. Each endpoint is checked against the enrolled UID, required capabilities and durability mode. The returned contract version is server-defined. There is no endpoint discovery RPC.

`CredentialSource` may be called concurrently and is called for each wire RPC, including capability verification. Return the token without the `Bearer ` prefix. Configured credentials replace caller outgoing `authorization` metadata. TLS client certificates may also be provided through `TLSConfig`.

By default, the client requires the advertised HA durability mode with at least three required durable voters. A server advertising development durability additionally requires explicit `AllowDevelopment: true`; that opt-in does not promise HA survival. Mutations also require advertised durable idempotency.

## Establish an owner session

This fragment follows `ExampleClient_EnsureOwner`. The strings are example identifiers: use your actual project/owner and durably stored request/session IDs. Persist those IDs before sending the requests and reuse them when recovering the same decision. `ctx` is a caller-controlled context.

```go
owner := &av.OwnerRef{
    ProjectUid: "project-uid",
    OwnerId: "controller-deployment",
}
_, err = client.EnsureOwner(ctx, &av.EnsureOwnerRequest{
    Owner: owner,
    RequestId: "persisted-ensure-request",
})
if err != nil {
    return err
}
acquired, err := client.AcquireOwnerSession(ctx, &av.AcquireOwnerSessionRequest{
    Owner: owner,
    ExpectedActivationGeneration: 0,
    SessionId: "persisted-session-id",
    RequestId: "persisted-acquire-request",
})
if err != nil {
    return err
}
session := acquired.Session
// Application step: durably persist the returned session before using it.
```

The example uses expected activation generation zero for initial activation. For an existing owner, use the generation appropriate to your protocol state. Session activation is explicit; expiry alone does not authorize a successor. `HandoffOwnerSession` is separately callable.

## Persist and submit a decision

This fragment follows `ExampleClient_SubmitCreateVM`, using the acquired `session` above. Its identifiers and minimal VM desired input are illustrative; supply valid deployment-specific input. The SDK does not generate request IDs.

```go
request := &av.SubmitCreateVMRequest{
    Identity: &av.MutationIdentity{
        RequestId: "persisted-create-request",
        Session: session,
    },
    Binding: &av.BindingKey{
        ProjectUid: "project-uid",
        OwnerId: "controller-deployment",
        ManagementKey: "machine-123",
    },
    Desired: &av.VMDesired{
        Name: "machine-123",
        Cpu: 2,
        MemoryMib: 2048,
    },
}
// Application step: durably persist the complete request before sending it.
submitted, err := client.SubmitCreateVM(ctx, request)
if err != nil {
    return err
}
// Application step: durably persist submitted.Operation independently.
```

Persist the binding key, request ID, session identity and immutable desired input before submission. Preserve bootstrap field presence and exact bytes when present. A retry of the same decision reuses the persisted request; losing a reply is not a reason to generate another request ID. Successful submission means acceptance, not completion.

The SDK clones requests for a logical call and preserves their identity/input across its transport attempts. Application persistence is still required for process crashes and later recovery; comments above mark application obligations, not SDK storage functions.

## Recover after a lost reply

Follow `ExampleClient_GetOperation` to look up the admitted operation by the saved binding and original request ID. `savedBindingKey` and `savedRequestID` below come from the persisted submission:

```go
recovered, err := client.GetOperation(ctx, &av.GetOperationRequest{
    Lookup: &av.GetOperationRequest_Request{
        Request: &av.OperationRequestLookup{
            Binding: savedBindingKey,
            RequestId: savedRequestID,
        },
    },
})
if err != nil {
    return err
}
// Application step: durably persist recovered.Operation.Ref.
```

This lookup requires no saved resource UID, operation UID or creation generation. Transport failure or an unavailable authoritative barrier does not prove absence.

`ResolveBinding`, `ObserveResource`, `GetOperation` and `WaitOperation` remain independently callable. Numeric observation-prefix floors are retained within the client and carried in supported read requests; returned resource revisions are opaque equality tokens. Persist returned operation references, including their minimum sequence, for later recovery.

## Wait with a caller-controlled context

This adapts `ExampleClient_WaitOperation` to the recovered reference. The configuration above permits a one-minute wait. The effective deadline is always the earlier caller deadline and configured `DefaultDeadline`: its zero value selects a 30-second cap for the whole logical call, including dialing, verification, retries and waiting. A longer caller timeout alone does not extend that cap.

```go
waitCtx, cancelWait := context.WithTimeout(ctx, time.Minute)
defer cancelWait()
completed, err := client.WaitOperation(waitCtx, recovered.Operation.Ref)
var interrupted *lv.WaitError
if errors.As(err, &interrupted) {
    // Application step: persist interrupted.Operation for a later wait.
    // If present, interrupted.Retry retains server advice for deferred polling.
    return err
}
if err != nil {
    // A terminal failure can return completed and a typed *lv.Error together.
    return err
}
_ = completed // Inspect the completed operation and its outcome.
```

Canceling the wait context stops observation and leaves admitted work running. It does not submit cancellation or create a new request. `WaitError.Operation` retains a cloned known reference on context cancellation, deadline expiry or client closure; `errors.Is` recognizes the wrapped cause. The SDK has no cancel-after-admission method. `BLOCKED` is nonterminal; waiting continues through accepted, running and blocked states.

If valid server polling advice exceeds `MaxBackoff`, waiting returns the current response and a `WaitError` with the cloned reference and retry advice. Check `errors.Is(err, lv.ErrWaitBackoffExceeded)` and schedule later observation according to that advice. The server operation is not relabeled as failed, and the client does not sleep beyond its configured bound.

## Errors, retries and lifecycle

Use `errors.As(err, &typed)` with `var typed *lv.Error` to inspect `typed.Code` and, when present, `typed.Detail` for application codes, references and retry guidance. Do not match diagnostic strings. `status.Code(err)` from `google.golang.org/grpc/status` preserves the underlying gRPC status on `*lv.Error`. `errors.Is` recognizes context cancellation/deadlines. Configuration and lifecycle errors can also be returned directly, including `ErrEnrollmentRequired`, `ErrClusterMismatch` and `ErrClosed`.

Retries are bounded and jittered. Defaults are three attempts, 25 milliseconds minimum backoff and one second maximum backoff. Only safe reads and validated identity-bound mutations are retried; structured advice such as refresh-state or do-not-retry is not blindly retried. If error retry advice exceeds the configured bound, the call returns the error and preserves its advice. The SDK does not submit legacy mutations.

Every attempt uses a fresh TLS connection and verifies cluster identity, capabilities and durability before application dispatch. A replacement physical connection requires a new verified SDK attempt. This adds handshake overhead to attempts and polls. Client connections, credentials and retry state are instance-local.

`Close` is idempotent, cancels active calls and closes their transports. Later calls return `ErrClosed`. Keep a client alive while its operations are being observed; use the persisted operation reference with a new correctly enrolled client when resuming later.

See [example_test.go](example_test.go) for the five complete executable examples and their explicit TLS fixture, [client.go](client.go) for configuration, [operations.go](operations.go) for waiting, [errors.go](errors.go) for typed errors, [rpc.go](rpc.go) for the typed methods, and the [public generated types](../../api/gen/litevirt/automation/v1/automation.pb.go) for request and response fields.
