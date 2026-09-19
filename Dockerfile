FROM golang:1.24-bookworm@sha256:1a6d4452c65dea36aac2e2d606b01b4a029ec90cc1ae53890540ce6173ea77ac AS go-build

WORKDIR /src

ARG VERSION=v0.1.0

COPY go.mod go.sum ./
COPY cmd ./cmd
COPY internal ./internal

RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build \
        -trimpath \
        -buildvcs=false \
        -ldflags="-s -w -X main.version=${VERSION}" \
        -o /out/phala-tail \
        ./cmd/phala-tail

FROM gcr.io/distroless/base-debian12@sha256:348dac1808083ccc3366399d6db835875b4eaf7c9b694783f5a3f353c4b58a28

ARG VERSION=v0.1.0
ARG SOURCE_REVISION

LABEL org.opencontainers.image.title="Phala Inference TAIL" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${SOURCE_REVISION}" \
      org.opencontainers.image.licenses="GPL-3.0-only"

# The executable dynamically loads libnvidia-ml.so.1 for confidential-compute
# evidence. The NVIDIA container runtime must inject the driver library and
# device nodes; this image does not contain a copied driver.
ENV NVIDIA_VISIBLE_DEVICES=all \
    NVIDIA_DRIVER_CAPABILITIES=utility

COPY --from=go-build /out/phala-tail /phala-tail
COPY LICENSE /usr/share/licenses/pig-tail/LICENSE

EXPOSE 31081

ENTRYPOINT ["/phala-tail"]
