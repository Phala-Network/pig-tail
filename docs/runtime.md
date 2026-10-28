# Runtime, TLS and attestation

## Runtime contract

TAIL requires TOKEN and UPSTREAM. UPSTREAM must be one HTTP(S) origin without
userinfo, path, query, or fragment. The proxy always overwrites the upstream
Authorization header with the same unified Bearer TOKEN.

`POST /v1/embeddings` uses this authenticated opaque forwarding path, including
single and batch inputs, dimensions, encoding format, vector data and usage.
The backend owns validation and error responses; TAIL does not parse embedding
JSON or retry failed requests. Missing or invalid credentials return 401 before
forwarding. Other methods and noncanonical embedding paths return 404. Use the
embedding backend's origin as `UPSTREAM`; no embedding-specific configuration
is required. Requests and responses are not logged.

The authenticated Governor management surface is fixed to
`GET|PATCH /admin/v1/predictive-policy` and
`GET /admin/v1/predictive-profile?expected_epoch=...`. TAIL preserves the
profile query and the upstream response status and body without interpreting
the epoch. Other methods on the profile route return 405, and all other admin
paths remain outside the allowlist and return 404.

DSTACK_ENDPOINT should be set explicitly to /var/run/dstack.sock in production,
with that Unix socket mounted into the container. TAIL obtains GetQuote and Info
through this local dstack RPC endpoint. Do not use DSTACK_SIMULATOR_ENDPOINT for
a production deployment.

The native NVIDIA evidence collector is built only on Linux with CGO enabled.
At runtime it dynamically opens libnvidia-ml.so.1 and requires the NVIDIA
container runtime to inject a confidential-compute-capable driver, GPU device
nodes, and the utility capability. It does not require nvidia-smi or a shell
collector. A missing or incompatible NVML driver makes a required NVIDIA
evidence report fail.

LISTEN defaults to 127.0.0.1:31081 for local use. A separate Compose service
that is reached by another container must set LISTEN to 0.0.0.0:31081 and keep
the port on an internal network rather than publishing it directly.

The packaged `phala-tail healthcheck` command checks the local listener's
`/healthz` endpoint with a five-second timeout. It does not initialize dstack or
NVIDIA evidence collection and does not require TOKEN. Wildcard LISTEN addresses
map to loopback for the probe. Redirects and non-2xx statuses fail. With TLS
enabled, the probe verifies certificate trust, SAN and the configured listener
certificate; it does not disable TLS verification. Use it as an exec-form
container healthcheck. Backend readiness remains a separate dependency and
inference acceptance check.

## TLS and attestation report versions

With neither TLS path set, TAIL listens as local HTTP and supports v1 reports.
Setting only `TLS_CERT_PATH` keeps this HTTP listener and supplies the external
ingress certificate for v2 attestation. Mount the public certificate read-only;
TAIL does not need the ingress private key. The report reads the certificate
on each request and rejects v2 when it is missing or invalid, so ingress can
start and issue a certificate after TAIL's liveness check passes.

Setting `TLS_KEY_PATH` enables TAIL's own HTTPS listener and requires a matching
`TLS_CERT_PATH`. In this mode v2 binds the exact certificate snapshot loaded by
the listener, even if the files later change. Restart TAIL after replacing the
pair to reload it. A key without a certificate remains a configuration error.

For external TLS, the quote binds the mounted certificate's SPKI and fresh
nonce. The verifier must compare that SPKI with the actual public TLS peer;
merely mounting a certificate does not prove it is the one ingress is serving.
Check the binding after deployment and certificate renewal. V1 behavior and
authentication are unchanged.
