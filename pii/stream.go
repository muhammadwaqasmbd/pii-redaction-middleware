package pii

import (
	"strings"
	"unicode/utf8"
)

// DefaultHoldback is the number of bytes withheld from the output while waiting
// to see whether a match continues. It must exceed the longest span any
// detector can produce — an IBAN at 34 characters plus separators, or a long
// API key — with margin.
const DefaultHoldback = 128

// StreamRedactor redacts text arriving in chunks.
//
// # The bug this exists to prevent
//
// Streaming is the default for model output, and the naive implementation
// redacts each chunk as it arrives. That leaks, because chunk boundaries fall
// wherever the tokeniser put them:
//
//	chunk 1: "contact me at user@exa"
//	chunk 2: "mple.com tomorrow"
//
// Neither chunk contains a matchable email. Both pass a per-chunk redactor
// untouched, and the address reaches the client in two pieces that the browser
// helpfully reassembles. The redactor reports zero matches and looks like it is
// working.
//
// # The fix, and its cost
//
// Text is buffered and only released once it cannot be part of a longer match:
// output lags input by up to Holdback bytes, and a match straddling the cut
// pushes the cut back to where the match starts.
//
// The cost is real and worth stating — the first token reaches the user later
// than it otherwise would. That is the trade for not leaking, and it is why
// Holdback is a knob rather than a constant: tune it to your longest detector,
// not to your latency budget. Setting it too low silently reintroduces the bug.
//
// A StreamRedactor is not safe for concurrent use; give each stream its own.
// The underlying Redactor is shared safely, so placeholders stay consistent
// across streams that need it.
type StreamRedactor struct {
	redactor *Redactor
	holdback int
	buf      []byte
	matches  []Match
}

// NewStream returns a StreamRedactor writing through r.
//
// A holdback of zero or less uses DefaultHoldback rather than disabling
// buffering, because a zero holdback is never what someone means — it is the
// per-chunk redactor whose leak this type exists to prevent.
func NewStream(r *Redactor, holdback int) *StreamRedactor {
	if holdback <= 0 {
		holdback = DefaultHoldback
	}
	return &StreamRedactor{redactor: r, holdback: holdback}
}

// Write accepts a chunk and returns the redacted text that is now safe to emit.
//
// It returns an empty string while everything received so far is still inside
// the holdback window. That is normal at the start of a stream and is not an
// error.
func (s *StreamRedactor) Write(chunk string) string {
	s.buf = append(s.buf, chunk...)

	if len(s.buf) <= s.holdback {
		return ""
	}

	cut := s.safeCut()
	if cut <= 0 {
		return ""
	}

	result := s.redactor.Redact(string(s.buf[:cut]))
	s.matches = append(s.matches, result.Matches...)
	s.buf = append(s.buf[:0:0], s.buf[cut:]...)
	return result.Text
}

// safeCut finds the furthest offset that cannot split a match.
func (s *StreamRedactor) safeCut() int {
	cut := len(s.buf) - s.holdback

	// Never split a UTF-8 rune: emitting half a multi-byte character produces
	// a replacement character in the client and corrupts the text even when no
	// PII was involved.
	for cut > 0 && !utf8.RuneStart(s.buf[cut]) {
		cut--
	}

	// If a match straddles the cut, retreat to where it begins so the whole
	// span is redacted together on this pass or a later one. Progress is still
	// guaranteed: a match cannot be longer than the holdback, so the cut only
	// retreats inside that window while len(buf) keeps growing.
	for _, m := range Detect(string(s.buf), s.redactor.detectors) {
		if m.Start < cut && m.End > cut {
			cut = m.Start
		}
	}
	return cut
}

// Flush redacts and returns everything still buffered.
//
// Always call it. Skipping Flush loses the tail of every stream — up to
// Holdback bytes, which is usually the end of the last sentence.
func (s *StreamRedactor) Flush() string {
	if len(s.buf) == 0 {
		return ""
	}
	result := s.redactor.Redact(string(s.buf))
	s.matches = append(s.matches, result.Matches...)
	s.buf = nil
	return result.Text
}

// Matches returns everything redacted so far across the stream.
func (s *StreamRedactor) Matches() []Match {
	out := make([]Match, len(s.matches))
	copy(out, s.matches)
	return out
}

// Buffered reports how many bytes are held back, for tests and diagnostics.
func (s *StreamRedactor) Buffered() int { return len(s.buf) }

// RedactAll is a convenience for the non-streaming case, so the common path
// does not have to think about buffering at all.
func RedactAll(r *Redactor, chunks []string) string {
	stream := NewStream(r, DefaultHoldback)
	var b strings.Builder
	for _, chunk := range chunks {
		b.WriteString(stream.Write(chunk))
	}
	b.WriteString(stream.Flush())
	return b.String()
}
