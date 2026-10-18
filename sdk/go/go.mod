module github.com/livingstaccato/litevirt/sdk/go

go 1.26.0

require (
	github.com/livingstaccato/litevirt/api v0.0.0
	google.golang.org/grpc v1.83.2
	google.golang.org/protobuf v1.36.12
)

require (
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
)

// Temporary source-development bridge; remove before module release (Task14).
replace github.com/livingstaccato/litevirt/api => ../../api
