// Package tail implements the thin trusted inference entrypoint. It never
// classifies request bodies, decides TPS admission or owns scheduler resources.
package tail

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	httpx "github.com/Phala-Network/pig-tail/internal/infra/http"
	"github.com/Phala-Network/pig-tail/internal/infra/openai"
	"github.com/Phala-Network/pig-tail/internal/runtime/attestation"
)

type Reporter interface {
	Generate(context.Context, attestation.ReportRequest) (map[string]any, error)
}

type Config struct {
	Token          string
	Upstream       string
	RequestTimeout time.Duration
}

type Handler struct {
	cfg         Config
	report      Reporter
	proxy       *httputil.ReverseProxy
	transport   *http.Transport
	started     time.Time
	inflight    atomic.Int64
	forwarded   atomic.Uint64
	unavailable atomic.Uint64
}

func New(cfg Config, reporter Reporter) (*Handler, error) {
	target, err := url.Parse(cfg.Upstream)
	if err != nil || target == nil || (target.Scheme != "http" && target.Scheme != "https") ||
		target.Host == "" || target.User != nil || (target.Path != "" && target.Path != "/") ||
		target.RawPath != "" || target.RawQuery != "" || target.Fragment != "" || target.Opaque != "" {
		return nil, fmt.Errorf("TAIL requires one fixed HTTP(S) backend origin")
	}
	if cfg.Token == "" || strings.TrimSpace(cfg.Token) != cfg.Token || strings.ContainsAny(cfg.Token, "\r\n") {
		return nil, fmt.Errorf("TAIL requires the unified TOKEN")
	}
	if cfg.RequestTimeout <= 0 {
		return nil, fmt.Errorf("TAIL request timeout must be positive")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil // A trusted fixed backend must not route through an ambient proxy.
	transport.MaxIdleConnsPerHost = 512
	h := &Handler{cfg: cfg, report: reporter, transport: transport, started: time.Now()}
	h.proxy = &httputil.ReverseProxy{
		Transport: transport, FlushInterval: -1,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			if pr.In.URL.Path == "/admin/v1/predictive-profile" {
				// ReverseProxy removes unparsable query parameters before Rewrite.
				// ABI4 requires this authenticated read route to reach the Governor
				// byte-for-byte so it can own expected_epoch validation.
				pr.Out.URL.RawQuery = pr.In.URL.RawQuery
			}
			pr.Out.Host = target.Host
			pr.Out.Header.Set("Authorization", "Bearer "+cfg.Token)
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, _ error) {
			if errors.Is(r.Context().Err(), context.Canceled) {
				return
			}
			h.unavailable.Add(1)
			openai.WriteUnavailable(w)
		},
	}
	return h, nil
}

func (h *Handler) Close() { h.transport.CloseIdleConnections() }

func canonical(r *http.Request) (string, bool) {
	if r == nil || r.URL == nil || r.URL.Scheme != "" || r.URL.Host != "" || r.URL.Opaque != "" ||
		r.URL.Fragment != "" || r.URL.RawPath != "" {
		return "", false
	}
	p := r.URL.Path
	if p == "" || !strings.HasPrefix(p, "/") || path.Clean(p) != p || r.URL.EscapedPath() != p {
		return "", false
	}
	if r.RequestURI != "" && strings.SplitN(r.RequestURI, "?", 2)[0] != p {
		return "", false
	}
	return p, true
}

func authorized(r *http.Request, token string) bool {
	values := r.Header.Values("Authorization")
	return len(values) == 1 && subtle.ConstantTimeCompare([]byte(values[0]), []byte("Bearer "+token)) == 1
}

func generation(p string) bool {
	return p == "/v1/chat/completions" || p == "/v1/completions" || p == "/v1/responses"
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p, ok := canonical(r)
	if !ok {
		openai.WriteNotFound(w)
		return
	}
	// Preserve the existing local liveness contract. This is not backend
	// readiness; the measured public ingress retains its own auth policy.
	if p == "/healthz" {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		_, _ = io.WriteString(w, "ok\n")
		return
	}
	management := p == "/pig/metrics" || p == "/v1/metrics" || p == "/v1/upstream-status" ||
		p == "/admin/v1/predictive-policy" || p == "/admin/v1/predictive-profile" ||
		p == "/v1/attestation/report"
	public := (generation(p) && r.Method == http.MethodPost) || (p == "/v1/models" && r.Method == http.MethodGet)
	if !management && !public {
		openai.WriteNotFound(w)
		return
	}
	if !authorized(r, h.cfg.Token) {
		if p == "/pig/metrics" || p == "/v1/metrics" || p == "/v1/upstream-status" {
			http.Error(w, "unauthorized", 401)
		} else {
			openai.WriteUnauthorized(w)
		}
		return
	}
	if management {
		switch p {
		case "/v1/attestation/report":
			h.attestation(w, r)
		case "/admin/v1/predictive-policy":
			if r.Method != http.MethodGet && r.Method != http.MethodPatch {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			// The scheduler owns authentication, CAS validation, and the exact
			// response envelope. TAIL only protects and transports this route.
			h.forward(w, r)
		case "/admin/v1/predictive-profile":
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			// The scheduler owns epoch validation and the exact response envelope.
			// TAIL only protects and transports this ABI4 read route.
			h.forward(w, r)
		case "/v1/upstream-status":
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			// New Governor intentionally has no old native-QoS health document.
			// Do not derive readiness or backpressure from transport observations.
			http.Error(w, "upstream status unavailable", http.StatusServiceUnavailable)
		case "/pig/metrics":
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			h.metrics(w)
		case "/v1/metrics":
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			r = r.Clone(r.Context())
			r.URL.Path = "/metrics"
			r.URL.RawPath = ""
			h.forward(w, r)
		}
		return
	}
	h.forward(w, r)
}

func (h *Handler) forward(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.cfg.RequestTimeout)
	defer cancel()
	r = r.Clone(ctx)
	httpx.RemoveHopByHopHeaders(r.Header)
	// Every valid authenticated request reaches the engine. TAIL does not
	// consult or manufacture scheduler state; the scheduler owns QoS decisions.
	h.inflight.Add(1)
	h.forwarded.Add(1)
	defer h.inflight.Add(-1)
	h.proxy.ServeHTTP(w, r)
}

func (h *Handler) attestation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	if h.report == nil {
		http.NotFound(w, r)
		return
	}
	version := 1
	if raw := r.URL.Query().Get("version"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil {
			writeJSON(w, 400, map[string]any{"detail": "Unsupported attestation report version: " + raw})
			return
		}
		version = value
	}
	report, err := h.report.Generate(r.Context(), attestation.ReportRequest{
		Version: version, SigningAlgo: r.URL.Query().Get("signing_algo"), NonceHex: r.URL.Query().Get("nonce")})
	if err != nil {
		var e attestation.HTTPError
		if errors.As(err, &e) {
			writeJSON(w, e.Status, map[string]any{"detail": e.Message})
		} else {
			writeJSON(w, 500, map[string]any{"detail": err.Error()})
		}
		return
	}
	writeJSON(w, 200, report)
}

// metrics exports only TAIL-owned transport facts. Scheduler state belongs to
// the upstream Governor and is available through its own control API.
func (h *Handler) metrics(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintln(w, "tail_info{implementation=\"thin\"} 1")
	fmt.Fprintf(w, "tail_uptime_seconds %.6f\n", time.Since(h.started).Seconds())
	fmt.Fprintf(w, "tail_inflight %d\n", h.inflight.Load())
	fmt.Fprintf(w, "tail_forwarded_total %d\n", h.forwarded.Load())
	fmt.Fprintf(w, "tail_transport_unavailable_total %d\n", h.unavailable.Load())
}

func writeJSON(w http.ResponseWriter, status int, obj any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(obj)
}
