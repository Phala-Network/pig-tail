package tail

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestEmbeddingsAuthenticationAndOpaqueForwarding(t *testing.T) {
	const payload = `{"model":"Qwen/Qwen3-Embedding-8B","input":"query: fixture","dimensions":3,"encoding_format":"float","user":"fixture"}`
	const response = `{"object":"list","model":"Qwen/Qwen3-Embedding-8B","data":[{"object":"embedding","index":0,"embedding":[0.25,-0.5,0.75]}],"usage":{"prompt_tokens":4,"total_tokens":4}}`
	var calls atomic.Int64
	h := setup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		body, _ := io.ReadAll(r.Body)
		if r.Method != http.MethodPost || r.URL.Path != "/v1/embeddings" || string(body) != payload ||
			r.Header.Get("Authorization") != "Bearer test-token" || r.Header.Get("Content-Type") != "application/json" {
			t.Error("embedding request was changed")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Request-ID", "fixture-embedding")
		_, _ = io.WriteString(w, response)
	}), nil, time.Second)
	for _, credential := range []string{"", "Bearer wrong"} {
		r := httptest.NewRequest(http.MethodPost, "/v1/embeddings", strings.NewReader(payload))
		if credential != "" {
			r.Header.Set("Authorization", credential)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("invalid credential: %d", w.Code)
		}
	}
	for _, p := range []string{"/v1/embeddings/", "/v1/embeddings-extra", "/v1//embeddings", "/v1/%65mbeddings", "/v1/../v1/embeddings"} {
		if w := call(h, http.MethodPost, p, payload, true); w.Code != http.StatusNotFound {
			t.Fatalf("noncanonical route %s: %d", p, w.Code)
		}
	}
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodHead, http.MethodOptions} {
		if w := call(h, method, "/v1/embeddings", payload, true); w.Code != http.StatusNotFound {
			t.Fatalf("method %s: %d", method, w.Code)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("rejected request reached backend")
	}
	w := call(h, http.MethodPost, "/v1/embeddings", payload, true)
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "application/json" ||
		w.Header().Get("X-Request-ID") != "fixture-embedding" || w.Body.String() != response || calls.Load() != 1 {
		t.Fatalf("embedding response changed: status=%d calls=%d", w.Code, calls.Load())
	}
}

func TestEmbeddingsPreservesBatchAndBackendErrors(t *testing.T) {
	for _, tc := range []struct {
		name, payload, response string
		status                  int
	}{
		{"batch", `{"model":"Qwen/Qwen3-Embedding-8B","input":["query: alpha","query: beta"],"dimensions":2}`,
			`{"object":"list","model":"Qwen/Qwen3-Embedding-8B","data":[{"object":"embedding","index":0,"embedding":[0.5,-0.5]},{"object":"embedding","index":1,"embedding":[0.25,0.75]}],"usage":{"prompt_tokens":8,"total_tokens":8}}`, http.StatusOK},
		{"base64", `{"model":"Qwen/Qwen3-Embedding-8B","input":[1,2,3],"encoding_format":"base64"}`,
			`{"object":"list","data":[{"object":"embedding","index":0,"embedding":"AACAPw=="}],"usage":{"prompt_tokens":3,"total_tokens":3}}`, http.StatusOK},
		{"invalid-dimensions", `{"model":"Qwen/Qwen3-Embedding-8B","input":"fixture","dimensions":-1}`,
			`{"error":{"message":"unsupported dimensions","type":"invalid_request_error","code":null}}`, http.StatusBadRequest},
		{"upstream-busy", `{"model":"Qwen/Qwen3-Embedding-8B","input":"fixture"}`,
			`{"error":{"message":"backend busy","type":"rate_limit_error"}}`, http.StatusTooManyRequests},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int64
			h := setup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				body, _ := io.ReadAll(r.Body)
				if r.URL.Path != "/v1/embeddings" || string(body) != tc.payload {
					t.Error("embedding payload was changed")
				}
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Retry-After", "2")
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.response)
			}), nil, time.Second)
			w := call(h, http.MethodPost, "/v1/embeddings", tc.payload, true)
			if w.Code != tc.status || w.Header().Get("Retry-After") != "2" || w.Body.String() != tc.response || calls.Load() != 1 {
				t.Fatalf("upstream response changed or retried: status=%d calls=%d", w.Code, calls.Load())
			}
		})
	}
}

func TestEmbeddingsCancellationPropagatesWhileWaitingForResult(t *testing.T) {
	started, cancelled := make(chan struct{}), make(chan struct{})
	h := setup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		close(started)
		<-r.Context().Done()
		close(cancelled)
	}), nil, 5*time.Second)
	server := httptest.NewServer(h)
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+"/v1/embeddings", strings.NewReader(`{"input":"fixture"}`))
	req.Header.Set("Authorization", "Bearer test-token")
	done := make(chan error, 1)
	go func() {
		response, err := http.DefaultClient.Do(req)
		if response != nil {
			response.Body.Close()
		}
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("embedding request never reached backend")
	}
	cancel()
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("client cancellation did not cancel backend")
	}
	if err := <-done; err == nil {
		t.Fatal("cancelled request unexpectedly succeeded")
	}
}

func TestEmbeddingsUpstreamTransportFailure(t *testing.T) {
	target := httptest.NewServer(http.NotFoundHandler())
	target.Close()
	h, err := New(Config{Token: "test-token", Upstream: target.URL, RequestTimeout: time.Second}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	w := call(h, http.MethodPost, "/v1/embeddings", `{"input":"fixture"}`, true)
	if w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), target.URL) ||
		strings.Contains(w.Body.String(), "test-token") || h.unavailable.Load() != 1 || h.inflight.Load() != 0 {
		t.Fatalf("transport failure contract changed: status=%d unavailable=%d inflight=%d", w.Code, h.unavailable.Load(), h.inflight.Load())
	}
}
