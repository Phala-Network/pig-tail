"""Linux final-image smoke; no GPU/TEE validity claim, no production credentials."""
import http.server
import json
import pathlib
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import uuid


EMBEDDINGS = [
    (b'{"model":"fixture-embedding","input":"query: single","dimensions":2}', 200,
     b'{"object":"list","data":[{"object":"embedding","index":0,"embedding":[0.5,-0.5]}],"model":"fixture-embedding","usage":{"prompt_tokens":3,"total_tokens":3}}'),
    (b'{"model":"fixture-embedding","input":["query: alpha","query: beta"],"dimensions":2}', 200,
     b'{"object":"list","data":[{"object":"embedding","index":0,"embedding":[0.5,-0.5]},{"object":"embedding","index":1,"embedding":[0.25,0.75]}],"model":"fixture-embedding","usage":{"prompt_tokens":6,"total_tokens":6}}'),
    (b'{"model":"fixture-embedding","input":"fixture","dimensions":-1}', 400,
     b'{"error":{"message":"unsupported dimensions","type":"invalid_request_error"}}'),
]


class Backend(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        assert self.headers.get("Authorization") == "Bearer fixture-only-token"
        body = self.rfile.read(int(self.headers["Content-Length"]))
        if self.path == "/v1/systemone":
            status, response = 202, body
        else:
            assert self.path == "/v1/embeddings"
            status, response = next((status, response) for payload, status, response in EMBEDDINGS if payload == body)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, *args):
        pass


def docker(*args):
    return subprocess.run(["docker", *args], check=True, capture_output=True, text=True).stdout.strip()


def main():
    image = sys.argv[1]
    name = "tail-smoke-" + uuid.uuid4().hex[:10]
    backend = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Backend)
    threading.Thread(target=backend.serve_forever, daemon=True).start()
    # Allocate a localhost port before Docker starts its host-network listener.
    probe = http.server.HTTPServer(("127.0.0.1", 0), Backend)
    port = probe.server_port
    probe.server_close()

    def request(path, token="fixture-only-token", body=None):
        headers = {"Content-Type": "application/json"}
        if token is not None:
            headers["Authorization"] = "Bearer " + token
        req = urllib.request.Request(f"http://127.0.0.1:{port}" + path, headers=headers, data=body)
        try:
            with urllib.request.urlopen(req, timeout=5) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as error:
            return error.code, error.read()

    with tempfile.TemporaryDirectory(prefix="tail-image-smoke-") as directory:
        root = pathlib.Path(directory)
        evidence = root / "evidence"
        evidence.mkdir()
        try:
            docker("run", "-d", "--name", name, "--network", "host", "--read-only", "--tmpfs", "/tmp",
                   "-e", "TOKEN=fixture-only-token", "-e", f"UPSTREAM=http://127.0.0.1:{backend.server_port}",
                   "-e", f"LISTEN=127.0.0.1:{port}", "-e", "TLS_CERT_PATH=/evidences/ingress.pem",
                   "-e", "DSTACK_ENDPOINT=/missing-dstack.sock", "-v", f"{evidence}:/evidences:ro", image)
            for attempt in range(30):
                try:
                    if request("/healthz")[0] == 200:
                        break
                except OSError:
                    pass
                time.sleep(0.2)
            else:
                raise AssertionError("image never became live in certificate-only mode")
            docker("exec", name, "/phala-tail", "healthcheck")
            path = "/v1/attestation/report?version=2&nonce=" + "12" * 32
            assert request(path)[0] == 400, "missing external certificate must reject v2"
            for token in (None, "wrong"):
                assert request(path, token)[0] == 401
                assert request("/v1/systemone", token, b'{}')[0] == 401
                assert request("/v1/embeddings", token, b'{}')[0] == 401
            payload = b'{"state":"fixture","questions":[]}'
            assert request("/v1/systemone", body=payload) == (202, payload)
            for embedding_payload, status, response in EMBEDDINGS:
                assert request("/v1/embeddings", body=embedding_payload) == (status, response)
            assert request("/v1/embeddings")[0] == 404, "embedding GET must remain outside the allowlist"
            assert request("/v1/embeddings/", body=b'{}')[0] == 404
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                            "-subj", "/CN=fixture.invalid", "-keyout", str(root / "private.key"),
                            "-out", str(evidence / "ingress.pem")], check=True, capture_output=True)
            # No key is mounted. A valid cert must advance to the unavailable TEE collector.
            status, body = request(path)
            assert status == 500 and b"get dstack quote" in body, (status, body)
            docker("exec", name, "/phala-tail", "healthcheck")
            log_result = subprocess.run(["docker", "logs", name], check=True, capture_output=True, text=True)
            logs = log_result.stdout + log_result.stderr
            assert "fixture-only-token" not in logs
            for embedding_payload, _, response in EMBEDDINGS:
                assert embedding_payload.decode() not in logs and response.decode() not in logs
            print(json.dumps({"passed": True, "image_id": docker("image", "inspect", image, "--format", "{{.Id}}"),
                              "checks": ["cert-only HTTP startup", "liveness without certificate", "auth rejection",
                                         "opaque System One forwarding", "embedding single/batch/usage/error forwarding",
                                         "embedding method/path rejection", "no fixture token or payload logging",
                                         "late certificate read without private key"],
                              "limitation": "No GPU/TEE signature verification on this CPU runner"}))
        finally:
            subprocess.run(["docker", "rm", "-f", name], capture_output=True)
            backend.shutdown()


if __name__ == "__main__":
    main()
