package tail

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Rerank, speech and image endpoints use the same opaque transport as
// embeddings and transcriptions: JSON or multipart in, JSON or binary out.
func TestMediaEndpointsAuthenticationAndOpaqueForwarding(t *testing.T) {
	const multipart = `multipart/form-data; boundary="tail-image+fixture"`
	cases := []struct {
		path, requestType, payload, responseType, response string
	}{
		{"/v1/rerank", "application/json",
			`{"model":"fixture-rerank","query":"q","documents":["a","b"],"top_n":1}`, "application/json",
			`{"id":"fixture","results":[{"index":1,"relevance_score":0.75}],"usage":{"prompt_tokens":4,"total_tokens":4}}`},
		{"/v1/audio/speech", "application/json",
			`{"model":"fixture-tts","input":"fixture","voice":"fixture"}`, "audio/mpeg",
			"ID3\x00\xff\xfb\x90\x00\r\n\x7f"},
		{"/v1/images/generations", "application/json",
			`{"model":"fixture-image","prompt":"fixture","n":1,"response_format":"b64_json"}`, "application/json",
			`{"created":1,"data":[{"b64_json":"AP9/"}]}`},
		{"/v1/images/edits", multipart,
			"--tail-image+fixture\r\nContent-Disposition: form-data; name=\"prompt\"\r\n\r\nfixture\r\n" +
				"--tail-image+fixture\r\nContent-Disposition: form-data; name=\"image\"; filename=\"fixture.png\"\r\nContent-Type: image/png\r\n\r\n\x89PNG\x00\xff\r\n" +
				"--tail-image+fixture--\r\n", "application/json",
			`{"created":1,"data":[{"b64_json":"AP9/"}]}`},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			var calls atomic.Int64
			h := setup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
				}
				if r.Method != http.MethodPost || r.URL.Path != c.path || string(body) != c.payload ||
					r.Header.Get("Authorization") != "Bearer test-token" || r.Header.Get("Content-Type") != c.requestType {
					t.Error("request was changed")
				}
				w.Header().Set("Content-Type", c.responseType)
				_, _ = io.WriteString(w, c.response)
			}), nil, time.Second)
			send := func(method, path, credential string) *httptest.ResponseRecorder {
				r := httptest.NewRequest(method, path, strings.NewReader(c.payload))
				r.Header.Set("Content-Type", c.requestType)
				if credential != "" {
					r.Header.Set("Authorization", credential)
				}
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				return w
			}
			for _, credential := range []string{"", "Bearer wrong"} {
				if w := send(http.MethodPost, c.path, credential); w.Code != http.StatusUnauthorized {
					t.Fatalf("invalid credential: %d", w.Code)
				}
			}
			last := strings.LastIndex(c.path, "/")
			encoded := fmt.Sprintf("%s%%%02x%s", c.path[:last+1], c.path[last+1], c.path[last+2:])
			for _, p := range []string{c.path + "/", c.path + "-extra", "/v1/" + c.path[len("/v1"):], "/v1/.." + c.path, encoded} {
				if w := send(http.MethodPost, p, "Bearer test-token"); w.Code != http.StatusNotFound {
					t.Fatalf("noncanonical route %s: %d", p, w.Code)
				}
			}
			for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodHead, http.MethodOptions} {
				if w := send(method, c.path, "Bearer test-token"); w.Code != http.StatusNotFound {
					t.Fatalf("method %s: %d", method, w.Code)
				}
			}
			if calls.Load() != 0 {
				t.Fatal("rejected request reached backend")
			}
			w := send(http.MethodPost, c.path, "Bearer test-token")
			if w.Code != http.StatusOK || w.Header().Get("Content-Type") != c.responseType || w.Body.String() != c.response || calls.Load() != 1 {
				t.Fatalf("response changed: status=%d calls=%d", w.Code, calls.Load())
			}
		})
	}
}

func TestUnlistedMediaEndpointsStayOutsideAllowlist(t *testing.T) {
	var calls atomic.Int64
	h := setup(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }), nil, time.Second)
	for _, p := range []string{"/v1/audio/translations", "/v1/images/variations", "/v2/rerank", "/rerank", "/v1/audio", "/v1/images"} {
		if w := call(h, http.MethodPost, p, `{}`, true); w.Code != http.StatusNotFound {
			t.Fatalf("unlisted route %s: %d", p, w.Code)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("unlisted route reached backend")
	}
}
