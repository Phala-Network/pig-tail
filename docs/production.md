# TAIL Deployment Contract

TAIL transports authenticated requests to one origin. It has no TPS calibration
profile, ABI library, reservation state, or admission policy. Governor ABI4 and
its response-surface profile are owned and loaded by the SGLang backend.

## Configuration

Use the release receipt's immutable `tag@sha256` image for Linux/amd64. Set:

| Variable | Production value |
| --- | --- |
| `TOKEN` | Existing sealed model-service TOKEN, shared with backend/ingress |
| `UPSTREAM` | One backend HTTP(S) origin, e.g. `http://sglang:30000` |
| `LISTEN` | `0.0.0.0:31081` on the private container network |
| `DSTACK_ENDPOINT` | `/var/run/dstack.sock`, mounted from the local CVM |
| `TLS_CERT_PATH`, `TLS_KEY_PATH` | Matching certificate/key when TAIL owns TLS |
| `NVIDIA_VISIBLE_DEVICES` | The intended GPU set |
| `NVIDIA_DRIVER_CAPABILITIES` | `utility` for native NVML evidence |

Use the NVIDIA container runtime and a read-only dstack socket bind. No dstack
simulator, downloaded executable, source overlay, or runtime package install is
part of this contract. The image needs no GPU compute allocation. Keep its root
filesystem read-only with a small writable `/tmp` tmpfs, bounded Docker logs,
`restart: unless-stopped`, and a shutdown grace period of at least 10 seconds.
Healthcheck is exec-form `[/phala-tail, healthcheck]` with timeout 6 seconds,
interval 10 seconds and retries 3. `/healthz` proves TAIL liveness only.

When HAProxy/ingress owns public TLS, route on the private network and retain its
independent CPU/GPU/TLS binding verification. A TAIL v1 report is not proof of an
external terminator's certificate. For TAIL TLS use report v2 and verify its
fingerprint against that exact listener certificate. Certificate renewal requires
an orderly TAIL restart after a complete matching pair is written atomically;
the listener does not hot-reload certificates.

## Governor Compatibility

The qualified backend pair is SGLang P1 engine `181598031c` with Governor
`d60a93a` / 0.2.5 / ABI4. TAIL forwards `/admin/v1/predictive-policy` GET/PATCH
and `/admin/v1/predictive-profile?expected_epoch=...` GET without interpreting
or caching the response. Backend errors (including 429 and CAS 409), bodies,
query strings, SSE events and cancellations must reach the caller unchanged.
Other profile methods return 405; unlisted admin paths return 404.

Backend configuration must independently set `PIG_GOVERNOR_ENABLE=1`, reference
50, the actual image library path `/opt/phala/governor/libpig_governor_core.so`,
and a read-only `PIG_TPS_PROFILE_PATH` plus exact `PIG_TPS_PROFILE_SHA256`.
Use a fresh, fully covered profile from the matching model artifact, hardware,
engine, Governor and resolved runtime configuration. A profile sampled with a
different scheduler, context, KV dtype or topology is not compatible. Detected KV
capacity may only increase from the sampled minimum. Never edit a profile identity
or reuse GPU805's profile across production nodes without this validation.

## Deployment and Rollback Gates

Image qualification permits preparing a controlled deployment; it does not accept
an untested production target. Before removing Guard, verify the candidate Compose,
private routing, sealed TOKEN agreement, exact running image/config IDs, backend
profile hash/identity/expiry/coverage, positive-reference admission, protocol,
cancellation/drain, fresh CPU/GPU attestation and public TLS binding. Preserve each
original Compose hash and route membership. Do not widen management exposure.

For failure, keep the target route down, stop accepting new requests, naturally
drain TAIL/backend inflight and native reservations, then restore that target's
original Compose and sealed environment through the scoped update API. Check
original image IDs, model readiness, credentials and protocol before restoring the
original route state. Retain the old Guard image and rollback YAML until target
acceptance/observation ends; TAIL has no persistent state requiring migration.
