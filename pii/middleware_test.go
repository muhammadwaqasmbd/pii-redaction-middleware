package pii

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func echoHandler(seen *string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		*seen = string(body)
		w.WriteHeader(http.StatusOK)
	})
}

func TestMiddlewareRedactsTheBodyBeforeTheHandlerSeesIt(t *testing.T) {
	var seen string
	handler := NewMiddleware(New()).Handler(echoHandler(&seen))

	body := `{"message":"contact alice@example.com"}`
	req := httptest.NewRequest(http.MethodPost, "/chat", strings.NewReader(body))
	handler.ServeHTTP(httptest.NewRecorder(), req)

	if strings.Contains(seen, "alice@example.com") {
		t.Errorf("the handler received unredacted data: %q", seen)
	}
	if !strings.Contains(seen, "[EMAIL_1]") {
		t.Errorf("expected a placeholder, got %q", seen)
	}
}

func TestContentLengthIsCorrected(t *testing.T) {
	// Placeholders are rarely the same length as what they replaced. A stale
	// ContentLength makes downstream decoders truncate the body or block
	// waiting for bytes that never arrive — and it is invisible until a
	// payload happens to change size in the wrong direction.
	var seen string
	handler := NewMiddleware(New()).Handler(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			seen = string(body)
			if r.ContentLength != int64(len(body)) {
				t.Errorf("ContentLength is %d but body is %d bytes", r.ContentLength, len(body))
			}
		}))

	body := `{"email":"averyverylongaddress@example.com"}`
	req := httptest.NewRequest(http.MethodPost, "/chat", strings.NewReader(body))
	handler.ServeHTTP(httptest.NewRecorder(), req)

	if seen == "" {
		t.Fatal("handler saw an empty body")
	}
}

func TestTheBodyRemainsValidJSON(t *testing.T) {
	// Redaction must not break the payload it is protecting.
	var seen string
	handler := NewMiddleware(New()).Handler(echoHandler(&seen))
	body := `{"user":"alice@example.com","card":"4111111111111111"}`
	req := httptest.NewRequest(http.MethodPost, "/chat", strings.NewReader(body))
	handler.ServeHTTP(httptest.NewRecorder(), req)

	if !strings.HasPrefix(seen, `{"user":"[EMAIL_1]"`) {
		t.Errorf("JSON structure was damaged: %q", seen)
	}
	if !strings.HasSuffix(seen, `"}`) {
		t.Errorf("JSON structure was damaged at the end: %q", seen)
	}
}

func TestOversizedBodiesAreTruncatedRatherThanExhaustingMemory(t *testing.T) {
	// An unbounded read is a denial-of-service vector: a client streaming an
	// endless body makes the middleware allocate until the process dies.
	var seen string
	handler := NewMiddleware(New(), WithMaxBytes(64)).Handler(echoHandler(&seen))

	req := httptest.NewRequest(http.MethodPost, "/chat", strings.NewReader(strings.Repeat("a", 10000)))
	handler.ServeHTTP(httptest.NewRecorder(), req)

	if len(seen) > 64 {
		t.Errorf("read %d bytes despite a 64-byte cap", len(seen))
	}
}

func TestTheRedactionHeaderIsSet(t *testing.T) {
	handler := NewMiddleware(New()).Handler(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("X-PII-Redacted") != "true" {
				t.Error("expected the redaction header to be set for downstream handlers")
			}
		}))
	req := httptest.NewRequest(http.MethodPost, "/chat", strings.NewReader("alice@example.com"))
	handler.ServeHTTP(httptest.NewRecorder(), req)
}

func TestAnEmptyBodyPassesThrough(t *testing.T) {
	called := false
	handler := NewMiddleware(New()).Handler(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) { called = true }))

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	handler.ServeHTTP(httptest.NewRecorder(), req)

	if !called {
		t.Error("the handler was not reached for a body-less request")
	}
}

func TestCleanBodiesAreForwardedUnchanged(t *testing.T) {
	var seen string
	handler := NewMiddleware(New()).Handler(echoHandler(&seen))
	body := `{"message":"the deployment finished in 42 seconds"}`
	req := httptest.NewRequest(http.MethodPost, "/chat", strings.NewReader(body))
	handler.ServeHTTP(httptest.NewRecorder(), req)

	if seen != body {
		t.Errorf("a clean body was modified:\n got %q\nwant %q", seen, body)
	}
}

func TestUrlsAndHeadersAreDeliberatelyUntouched(t *testing.T) {
	// Rewriting them would break routing, authentication and caching in ways
	// that are hard to see. Keep personal data out of URLs at the source.
	var gotPath, gotHeader string
	handler := NewMiddleware(New()).Handler(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			gotPath = r.URL.String()
			gotHeader = r.Header.Get("X-User")
		}))

	req := httptest.NewRequest(http.MethodPost, "/u/alice@example.com", strings.NewReader("{}"))
	req.Header.Set("X-User", "alice@example.com")
	handler.ServeHTTP(httptest.NewRecorder(), req)

	if !strings.Contains(gotPath, "alice@example.com") {
		t.Errorf("the URL was rewritten: %q", gotPath)
	}
	if gotHeader != "alice@example.com" {
		t.Errorf("the header was rewritten: %q", gotHeader)
	}
}
