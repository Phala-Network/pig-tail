package tail

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Phala-Network/pig-tail/internal/runtime/attestation"
)

type reporter struct{ calls []attestation.ReportRequest }

func (r *reporter) Generate(_ context.Context, q attestation.ReportRequest) (map[string]any, error) {
	r.calls = append(r.calls, q)
	if q.SigningAlgo == "invalid" {
		return nil, attestation.HTTPError{Status: http.StatusBadRequest, Message: "Unsupported signing algorithm"}
	}
	return map[string]any{"version": q.Version, "request_nonce": q.NonceHex, "quote": fmt.Sprintf("fresh-%d", len(r.calls))}, nil
}

func setup(t *testing.T, backend http.Handler, report Reporter, timeout time.Duration) *Handler {
	t.Helper()
	target := httptest.NewServer(backend)
	t.Cleanup(target.Close)
	h, err := New(Config{Token: "test-token", Upstream: target.URL, RequestTimeout: timeout}, report)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.Close)
	return h
}

func call(h http.Handler, method, path, body string, auth bool) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if auth {
		r.Header.Set("Authorization", "Bearer test-token")
	}
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestCanonicalWhitelistAndAuthenticationNeverReachBackend(t *testing.T) {
	var count atomic.Int64
	h := setup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { count.Add(1) }), nil, time.Second)
	for _, p := range []string{"/generate", "/tokenize", "/native_qos", "/metrics", "/v1/models/", "/v1//models", "/v1/../v1/models", "/v1/%6dodels", "/v1/attestation/report/"} {
		for _, m := range []string{http.MethodGet, http.MethodPost, http.MethodPatch} {
			if w := call(h, m, p, "{}", true); w.Code != http.StatusNotFound {
				t.Fatalf("%s %s: %d", m, p, w.Code)
			}
		}
	}
	for _, p := range []string{"/v1/models", "/v1/metrics", "/pig/metrics", "/v1/upstream-status", "/admin/v1/predictive-policy", "/v1/attestation/report"} {
		if w := call(h, http.MethodGet, p, "", false); w.Code != http.StatusUnauthorized {
			t.Fatalf("unauthorized %s: %d", p, w.Code)
		}
	}
	for _, p := range []string{"/v1/chat/completions", "/v1/completions", "/v1/responses"} {
		if w := call(h, http.MethodPost, p, "{}", false); w.Code != http.StatusUnauthorized {
			t.Fatal(p, w.Code)
		}
		if w := call(h, http.MethodGet, p, "", true); w.Code != http.StatusNotFound {
			t.Fatal(p, w.Code)
		}
	}
	for _, p := range []string{"/healthz", "/pig/metrics", "/v1/metrics", "/v1/upstream-status"} {
		if w := call(h, http.MethodPost, p, "", p != "/healthz"); w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("method %s: %d", p, w.Code)
		}
	}
	if w := call(h, http.MethodGet, "/healthz", "", false); w.Code != http.StatusOK || w.Body.String() != "ok\n" {
		t.Fatal(w.Code, w.Body.String())
	}
	if count.Load() != 0 {
		t.Fatal("blocked route forwarded")
	}
}

func TestInferenceForwardsOpaqueBodyWithoutNativeEpoch(t *testing.T) {
	calls := 0
	h := setup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		body, _ := io.ReadAll(r.Body)
		if string(body) != "not json" {
			t.Error("body rewritten")
		}
		if got := r.Header.Get("X-PIG-Native-QoS-Epoch"); got != "" {
			t.Errorf("legacy epoch forwarded: %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, `{"error":{"message":"native rejection"}}`)
	}), nil, time.Second)
	for _, p := range []string{"/v1/chat/completions", "/v1/completions", "/v1/responses"} {
		w := call(h, http.MethodPost, p, "not json", true)
		if w.Code != http.StatusTooManyRequests || w.Body.String() != `{"error":{"message":"native rejection"}}` {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	if calls != 3 {
		t.Fatal("inference was not forwarded", calls)
	}
}

func TestAdminPreservesPathBodyStatusAndDoesNotRetry(t *testing.T) {
	var calls atomic.Int64
	payload := `{"expected_epoch":"1234567890abcdef1234567890abcdef","expected_revision":1,"tps_reference":50}`
	h := setup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/admin/v1/predictive-policy" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Error("service authentication missing")
		}
		if r.Method == http.MethodPatch {
			body, _ := io.ReadAll(r.Body)
			if string(body) != payload {
				t.Errorf("body = %q", body)
			}
			w.Header().Set("X-Upstream-Status", "conflict")
			w.WriteHeader(http.StatusConflict)
			_, _ = io.WriteString(w, `{"error":"policy_conflict_or_invalid"}`)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		_, _ = io.WriteString(w, `{"epoch":"1234567890abcdef1234567890abcdef","revision":1,"mutable":{"tps_reference":35}}`)
	}), nil, time.Second)
	get := call(h, http.MethodGet, "/admin/v1/predictive-policy", "", true)
	if get.Code != http.StatusOK || get.Header().Get("Cache-Control") != "no-store" {
		t.Fatal(get.Code, get.Header())
	}
	patch := call(h, http.MethodPatch, "/admin/v1/predictive-policy", payload, true)
	if patch.Code != http.StatusConflict || patch.Header().Get("X-Upstream-Status") != "conflict" || patch.Body.String() != `{"error":"policy_conflict_or_invalid"}` {
		t.Fatal(patch.Code, patch.Header(), patch.Body.String())
	}
	if calls.Load() != 2 {
		t.Fatal("admin request retried", calls.Load())
	}
}

func TestMetricsMappingAndTailOnlyMetrics(t *testing.T) {
	var calls atomic.Int64
	h := setup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodGet || r.URL.Path != "/metrics" {
			t.Errorf("mapped request = %s %s", r.Method, r.URL.Path)
		}
		_, _ = io.WriteString(w, "sglang_running 0\n")
	}), nil, time.Second)
	mapped := call(h, http.MethodGet, "/v1/metrics", "", true)
	if mapped.Code != http.StatusOK || mapped.Body.String() != "sglang_running 0\n" {
		t.Fatal(mapped.Code, mapped.Body.String())
	}
	local := call(h, http.MethodGet, "/pig/metrics", "", true)
	for _, metric := range []string{"tail_info", "tail_uptime_seconds", "tail_inflight", "tail_forwarded_total", "tail_transport_unavailable_total"} {
		if !strings.Contains(local.Body.String(), metric) {
			t.Fatal(local.Body.String())
		}
	}
	if strings.Contains(local.Body.String(), "pig_native_qos") || strings.Contains(local.Body.String(), "pig_dynamic") {
		t.Fatal("legacy scheduler metric fabricated", local.Body.String())
	}
	if calls.Load() != 1 {
		t.Fatal("local metrics reached backend", calls.Load())
	}
	if w := call(h, http.MethodGet, "/v1/upstream-status", "", true); w.Code != http.StatusServiceUnavailable {
		t.Fatal(w.Code)
	}
}

func TestStreamingCancellationPropagates(t *testing.T) {
	cancelled := make(chan struct{})
	h := setup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"content\":\"hello\"}}]}\n\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		close(cancelled)
	}), nil, 30*time.Second)
	server := httptest.NewServer(h)
	defer server.Close()
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/v1/chat/completions", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer test-token")
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatal(response.StatusCode)
	}
	buf := make([]byte, 8)
	if _, err := io.ReadFull(response.Body, buf); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("disconnect did not cancel backend")
	}
}

func TestAttestationNonceVersionAndErrorsWithoutInferenceForwarding(t *testing.T) {
	report := &reporter{}
	h := setup(t, http.NotFoundHandler(), report, time.Second)
	for _, nonce := range []string{strings.Repeat("ab", 32), strings.Repeat("cd", 32)} {
		w := call(h, http.MethodGet, "/v1/attestation/report?version=2&signing_algo=ed25519&nonce="+nonce, "", true)
		var data map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &data)
		if w.Code != http.StatusOK || data["request_nonce"] != nonce || data["version"] != float64(2) {
			t.Fatal(w.Code, data)
		}
	}
	if len(report.calls) != 2 || report.calls[0].NonceHex == report.calls[1].NonceHex {
		t.Fatal("nonce cached")
	}
	if w := call(h, http.MethodGet, "/v1/attestation/report?signing_algo=invalid", "", true); w.Code != http.StatusBadRequest {
		t.Fatal(w.Code)
	}
}

func TestConfigRejectsArbitraryProxyTarget(t *testing.T) {
	for _, upstream := range []string{"", "http://", "file:///etc/passwd", "http://user:pass@localhost", "http://localhost/path", "http://localhost/?query=1", "http://localhost/#fragment"} {
		if h, err := New(Config{Token: "test-token", Upstream: upstream, RequestTimeout: time.Second}, nil); err == nil {
			h.Close()
			t.Fatal(upstream)
		}
	}
}
