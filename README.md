# Phala Inference TAIL

TAIL is the thin trusted inference entrypoint for the native Phala Inference
Governor architecture. It authenticates a deliberately small OpenAI-compatible
surface with the deployment's unified TOKEN, forwards opaque request bodies and
streams to one fixed SGLang origin, and serves the attestation report endpoint.

TAIL does not classify request bodies, make admission or TPS decisions, own a
queue, read scheduler state, allocate KV cache, or construct the legacy Phala
Inference Guard controller. The native SGLang scheduler remains the sole QoS
authority.

## Runtime contract

TAIL requires TOKEN and UPSTREAM. UPSTREAM must be one HTTP(S) origin without
userinfo, path, query, or fragment. The proxy always overwrites the upstream
Authorization header with the same unified Bearer TOKEN.

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

## TLS and attestation report versions

Without both TLS_CERT_PATH and TLS_KEY_PATH, TAIL listens as local HTTP and
serves the existing v1 report behavior. When both paths are present and form a
matching key pair, TAIL terminates TLS itself and binds the v2 report to the
SPKI of the exact certificate snapshot loaded by that listener.

An external TLS terminator has a separate certificate-binding proof obligation.
Mounting only its certificate into TAIL does not bind TAIL's report to the
public endpoint, and a certificate without its matching key is rejected.

## Build and source provenance

This v0.1.0 source is a minimal GPL-3.0-only extraction from the former Phala
Inference Guard development worktree. The extraction contains only the
phala-tail command, TAIL handler, required HTTP/OpenAI helpers, and the
attestation implementation with its tests. It does not contain the legacy
Guard server, admission controller, native-QoS client, classifier, predictive
configuration, or telemetry observer. The v0.1.0 release manifest must freeze
the exact source/revision inputs before publication.

The Dockerfile pins the Go build and distroless runtime bases recorded by the
previous verified PIG release inputs. It builds a Linux/amd64 CGO binary without
runtime source mounts or dependency installation. A later authorized builder
release must still run the source tests, race tests, dependency-closure check,
image-level NVML/dstack qualification, reproducibility builds, and registry
provenance/readback before any CVM deployment.

See LICENSE for the GNU GPL version 3 terms.
