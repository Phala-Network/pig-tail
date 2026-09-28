# TAIL — TEE-Attested Inference Layer

TAIL is a small authenticated proxy and attestation endpoint for Phala inference
services. It forwards opaque OpenAI-compatible requests and streams to one fixed
backend origin with the deployment's unified bearer token.

TAIL does not make admission/TPS decisions or own queues and KV cache. Those
remain with the backend and optional [Governor](https://github.com/Phala-Network/phala-inference-governor).
It is separate from the [Guard proxy](https://github.com/Phala-Network/phala-inference-guard).

## Local quick start

Use Go 1.24 or later and a reachable backend. In Bash:

```bash
go build -o phala-tail ./cmd/phala-tail
export TOKEN='replace-with-a-strong-token'
export UPSTREAM='http://127.0.0.1:30000'
./phala-tail
```

In another terminal with the same `TOKEN`:

```bash
./phala-tail healthcheck
curl --fail -H "Authorization: Bearer $TOKEN" http://127.0.0.1:31081/v1/models
```

The backend must use the same token. `UPSTREAM` is an HTTP(S) origin without a
path, query, fragment or embedded credentials. The healthcheck proves local
liveness; model discovery checks the backend path. This example does not qualify
attestation: reports require real dstack and supported NVIDIA infrastructure.

## Production and attestation

Production uses Linux/amd64 with CGO, the pinned [Dockerfile](Dockerfile), the
NVIDIA container runtime and a release's immutable image digest. Set
`LISTEN=0.0.0.0:31081` on a private network when other containers connect.

Set and mount `DSTACK_ENDPOINT=/var/run/dstack.sock` for attestation. GPU evidence
requires a compatible confidential-compute NVML driver. Matching `TLS_CERT_PATH`
and `TLS_KEY_PATH` enable TAIL TLS and bind the v2 report to that listener's
certificate. External TLS termination needs independent binding verification.

See [runtime and TLS details](docs/runtime.md) and the
[deployment contract](docs/production.md) for configuration and acceptance.

## Management forwarding

TAIL forwards authenticated `GET/PATCH /admin/v1/predictive-policy` and
`GET /admin/v1/predictive-profile?expected_epoch=...` without interpreting policy.
Unlisted admin paths remain outside its allowlist. Profile requirements belong
to the selected Governor/backend version.

## Development and releases

- [Contributing and tests](CONTRIBUTING.md)
- [Release policy](docs/RELEASING.md)
- [Source tags](https://github.com/Phala-Network/pig-tail/tags)

`main` integrates maintained code; immutable tags identify releases. Source tests,
image qualification and production acceptance are separate checks.

## License

[GNU General Public License v3.0](LICENSE). TAIL was extracted from former Phala
Inference Guard development source and maintains its independent scope.
