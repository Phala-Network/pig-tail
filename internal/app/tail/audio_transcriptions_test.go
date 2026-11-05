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

func TestAudioTranscriptionsAuthenticationAndMultipartForwarding(t *testing.T) {
	const contentType = `multipart/form-data; boundary="tail-audio+fixture"`
	const payload = "--tail-audio+fixture\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\nQwen/Qwen3-ASR\r\n" +
		"--tail-audio+fixture\r\nContent-Disposition: form-data; name=\"file\"; filename=\"fixture.wav\"\r\nContent-Type: audio/wav\r\n\r\n\x00\xff\x7f\r\n" +
		"--tail-audio+fixture--\r\n"
	const response = `{"text":"fixture transcription","usage":{"type":"duration","seconds":1.5}}`
	var calls atomic.Int64
	h := setup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		if r.Method != http.MethodPost || r.URL.Path != "/v1/audio/transcriptions" || string(body) != payload ||
			r.Header.Get("Authorization") != "Bearer test-token" || r.Header.Get("Content-Type") != contentType {
			t.Error("multipart transcription request was changed")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Request-ID", "fixture-transcription")
		_, _ = io.WriteString(w, response)
	}), nil, time.Second)
	for _, credential := range []string{"", "Bearer wrong"} {
		r := httptest.NewRequest(http.MethodPost, "/v1/audio/transcriptions", strings.NewReader(payload))
		r.Header.Set("Content-Type", contentType)
		if credential != "" {
			r.Header.Set("Authorization", credential)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("invalid credential: %d", w.Code)
		}
	}
	for _, p := range []string{"/v1/audio/transcriptions/", "/v1/audio/transcriptions-extra", "/v1//audio/transcriptions", "/v1/audio/%74ranscriptions", "/v1/../v1/audio/transcriptions"} {
		if w := call(h, http.MethodPost, p, payload, true); w.Code != http.StatusNotFound {
			t.Fatalf("noncanonical route %s: %d", p, w.Code)
		}
	}
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodHead, http.MethodOptions, http.MethodTrace, http.MethodConnect} {
		if w := call(h, method, "/v1/audio/transcriptions", payload, true); w.Code != http.StatusNotFound {
			t.Fatalf("method %s: %d", method, w.Code)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("rejected request reached backend")
	}
	r := httptest.NewRequest(http.MethodPost, "/v1/audio/transcriptions", strings.NewReader(payload))
	r.Header.Set("Authorization", "Bearer test-token")
	r.Header.Set("Content-Type", contentType)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "application/json" ||
		w.Header().Get("X-Request-ID") != "fixture-transcription" || w.Body.String() != response || calls.Load() != 1 {
		t.Fatalf("transcription response changed: status=%d calls=%d", w.Code, calls.Load())
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
