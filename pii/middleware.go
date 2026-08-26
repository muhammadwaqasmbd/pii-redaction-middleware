package pii

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
)

// MaxBodyBytes caps how much of a request body is read and scanned.
//
// An unbounded read is a denial-of-service vector: a client streaming an
// endless body makes the middleware allocate until the process dies. The cap is
// the whole defence, and it is why the body is not simply handed to io.ReadAll.
const MaxBodyBytes = 1 << 20 // 1 MiB

// Middleware redacts personal data from request bodies before they reach the
// handler.
//
// # Where this belongs
//
// In front of the handler that builds prompts, not in front of everything. A
// redactor sitting on your whole API scans and rewrites bodies that were never
// going near a model — that is latency and risk for no benefit, and it will
// eventually mangle a legitimate payload that happened to look like a card
// number.
//
// # What it does not do
//
// It does not redact URLs, query strings or headers. Those routinely carry
// identifiers, and rewriting them would break routing, authentication and
// caching in ways that are hard to see. Keep PII out of URLs at the source; a
// middleware cannot fix that safely.
//
// It also does not touch responses. Response redaction needs the streaming path
// (see StreamRedactor) and, more importantly, it needs Restore — the handler
// knows which placeholders belong to which request, and the middleware does not.
type Middleware struct {
	redactor *Redactor
	logger   *slog.Logger
	maxBytes int64
}

// MiddlewareOption configures a Middleware.
type MiddlewareOption func(*Middleware)

// WithLogger sets where redaction counts are reported.
//
// Counts only. The values themselves are never logged — writing them out would
// make the log a second, less protected copy of exactly the data the middleware
// exists to contain, which is a genuinely common way this control backfires.
func WithLogger(l *slog.Logger) MiddlewareOption {
	return func(m *Middleware) { m.logger = l }
}

// WithMaxBytes overrides the body size cap.
func WithMaxBytes(n int64) MiddlewareOption {
	return func(m *Middleware) {
		if n > 0 {
			m.maxBytes = n
		}
	}
}

// NewMiddleware returns a Middleware using r.
func NewMiddleware(r *Redactor, opts ...MiddlewareOption) *Middleware {
	m := &Middleware{redactor: r, logger: slog.Default(), maxBytes: MaxBodyBytes}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// Handler wraps next, redacting the request body.
func (m *Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Body == nil || req.ContentLength == 0 {
			next.ServeHTTP(w, req)
			return
		}

		body, err := io.ReadAll(io.LimitReader(req.Body, m.maxBytes))
		if err != nil {
			// Fail closed. Passing an unread body through would forward
			// exactly the data this middleware exists to remove.
			http.Error(w, "could not read request body", http.StatusBadRequest)
			return
		}
		_ = req.Body.Close()

		result := m.redactor.Redact(string(body))
		if len(result.Matches) > 0 && m.logger != nil {
			attrs := make([]any, 0, len(result.Counts())*2+2)
			attrs = append(attrs, "path", req.URL.Path)
			for kind, count := range result.Counts() {
				attrs = append(attrs, string(kind), count)
			}
			m.logger.Info("redacted personal data from request body", attrs...)
		}

		redacted := []byte(result.Text)
		req.Body = io.NopCloser(bytes.NewReader(redacted))
		// ContentLength must be corrected: placeholders are rarely the same
		// length as what they replaced, and a stale value makes downstream
		// decoders truncate the body or block waiting for bytes that never come.
		req.ContentLength = int64(len(redacted))
		req.Header.Set("X-PII-Redacted", "true")

		next.ServeHTTP(w, req)
	})
}
