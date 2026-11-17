package tail

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Rerank, translation, speech and image endpoints use the same opaque transport as
// embeddings and transcriptions: JSON or multipart in, JSON or binary out.
func TestMediaEndpointsAuthenticationAndOpaqueForwarding(t *testing.T) {
	const multipart = `multipart/form-data; boundary="tail-media+fixture"`
	cases := []struct {
		path, requestType, payload, responseType, response string
	}{
		{"/v1/rerank", "application/json",
			`{"model":"fixture-rerank","query":"q","documents":["a","b"],"top_n":1}`, "application/json",
			`{"id":"fixture","results":[{"index":1,"relevance_score":0.75}],"usage":{"prompt_tokens":4,"total_tokens":4}}`},
		{"/v1/audio/translations", multipart,
			"--tail-media+fixture\r\nContent-Disposition: form-data; name=\"file\"; filename=\"fixture.wav\"\r\nContent-Type: audio/wav\r\n\r\n\x00\xff\x7f\r\n" +
				"--tail-media+fixture--\r\n", "application/json",
			`{"text":"fixture translation","usage":{"type":"duration","seconds":1.5}}`},
		{"/v1/audio/speech", "application/json",
			`{"model":"fixture-tts","input":"fixture","voice":"fixture"}`, "audio/mpeg",
			"ID3\x00\xff\xfb\x90\x00\r\n\x7f"},
		{"/v1/images/generations", "application/json",
			`{"model":"fixture-image","prompt":"fixture","n":1,"response_format":"b64_json"}`, "application/json",
			`{"created":1,"data":[{"b64_json":"AP9/"}]}`},
		{"/v1/images/edits", multipart,
			"--tail-media+fixture\r\nContent-Disposition: form-data; name=\"prompt\"\r\n\r\nfixture\r\n" +
				"--tail-media+fixture\r\nContent-Disposition: form-data; name=\"image\"; filename=\"fixture.png\"\r\nContent-Type: image/png\r\n\r\n\x89PNG\x00\xff\r\n" +
				"--tail-media+fixture--\r\n", "application/json",
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
			if w := send(http.MethodPost, c.path, ""); w.Code != http.StatusUnauthorized || calls.Load() != 0 {
				t.Fatalf("missing credential: status=%d calls=%d", w.Code, calls.Load())
			}
			w := send(http.MethodPost, c.path, "Bearer test-token")
			if w.Code != http.StatusOK || w.Header().Get("Content-Type") != c.responseType || w.Body.String() != c.response || calls.Load() != 1 {
				t.Fatalf("response changed: status=%d calls=%d", w.Code, calls.Load())
			}
		})
	}
}
