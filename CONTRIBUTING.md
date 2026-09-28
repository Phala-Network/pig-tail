# Contributing

Start focused changes from `main`, include affected tests and update runtime
configuration documentation. TAIL owns authentication, transport and attestation;
admission behavior belongs in the backend component.

Use Go 1.24 or later. On Linux with CGO enabled:

```bash
go test -race ./...
go vet ./...
go build ./cmd/phala-tail
```

Format changed Go files with `gofmt`. Exercise streaming, cancellation, route
allowlisting and TLS binding when relevant. Unit tests use controlled fixtures;
real dstack/NVML and image qualification are separate checks. Never commit tokens,
private keys or credentials. Merge validated work into `main` and use immutable
tags; see [release policy](docs/RELEASING.md).
