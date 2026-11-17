package tail

import (
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Rerank, audio and image endpoints use the same opaque transport as
// embeddings: JSON or multipart in, JSON or binary out.
func TestMediaEndpointsAuthenticationAndOpaqueForwarding(t *testing.T) {
	const multipart = `multipart/form-data; boundary="tail-media+fixture"`
	cases := []struct {
		path, requestType, payload, responseType, response string
	}{
		{"/v1/rerank", "application/json",
			`{"model":"fixture-rerank","query":"q","documents":["a","b"],"top_n":1}`, "application/json",
			`{"id":"fixture","results":[{"index":1,"relevance_score":0.75}],"usage":{"prompt_tokens":4,"total_tokens":4}}`},
		{"/v1/audio/transcriptions", multipart,
			"--tail-media+fixture\r\nContent-Disposition: form-data; name=\"file\"; filename=\"fixture.wav\"\r\nContent-Type: audio/wav\r\n\r\n\x00\xff\x7f\r\n" +
				"--tail-media+fixture--\r\n", "application/json",
			`{"text":"fixture transcription","usage":{"type":"duration","seconds":1.5}}`},
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

func TestAudioTranscriptionsStreamsLargeMultipartUpload(t *testing.T) {
	const contentType = "multipart/form-data; boundary=tail-large-audio"
	const prefix = "--tail-large-audio\r\nContent-Disposition: form-data; name=\"file\"; filename=\"fixture.wav\"\r\nContent-Type: audio/wav\r\n\r\n"
	const suffix = "\r\n--tail-large-audio--\r\n"
	const audioSize = 25 << 20
	chunk := strings.Repeat("\x00\xff\x7f\r", 8192)
	expected := sha256.New()
	for n := 0; n < audioSize; n += len(chunk) {
		_, _ = io.WriteString(expected, chunk)
	}
	_, _ = io.WriteString(expected, suffix)
	started := make(chan struct{})
	h := setup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := make([]byte, len(prefix))
		_, err := io.ReadFull(r.Body, start)
		// The uploader sends the remaining bytes only after the backend reads
		// this prefix, so buffering the full request would stall the upload.
		close(started)
		if err != nil || string(start) != prefix || r.Header.Get("Content-Type") != contentType {
			t.Errorf("multipart prefix changed: %v", err)
		}
		actual := sha256.New()
		n, err := io.Copy(actual, r.Body)
		if err != nil || n != audioSize+int64(len(suffix)) || string(actual.Sum(nil)) != string(expected.Sum(nil)) {
			t.Errorf("large multipart upload changed or truncated: bytes=%d err=%v", n, err)
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "fixture transcription\n")
	}), nil, 10*time.Second)
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	uploaded := make(chan error, 1)
	go func() {
		err := func() error {
			if _, err := io.WriteString(writer, prefix); err != nil {
				return err
			}
			select {
			case <-started:
			case <-time.After(5 * time.Second):
				return errors.New("backend did not receive prefix before upload completed")
			}
			for n := 0; n < audioSize; n += len(chunk) {
				if _, err := io.WriteString(writer, chunk); err != nil {
					return err
				}
			}
			_, err := io.WriteString(writer, suffix)
			return err
		}()
		_ = writer.CloseWithError(err)
		uploaded <- err
	}()
	r := httptest.NewRequest(http.MethodPost, "/v1/audio/transcriptions", reader)
	r.Header.Set("Authorization", "Bearer test-token")
	r.Header.Set("Content-Type", contentType)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	_ = reader.Close()
	if err := <-uploaded; err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "text/plain" || w.Body.String() != "fixture transcription\n" {
		t.Fatalf("large upload response changed: status=%d", w.Code)
	}
}
