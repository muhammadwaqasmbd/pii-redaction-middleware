package pii

import (
	"fmt"
	"strings"
	"sync"
)

// Redactor replaces detected personal data with stable placeholders and can put
// the original values back.
//
// # Why reversible
//
// Irreversible redaction breaks the use case. Send "[EMAIL_1] cannot log in" to
// a model and it answers "ask [EMAIL_1] to reset their password" — which is
// useless to a support agent unless something restores the address on the way
// out. One-way scrubbing is why so many redaction layers get removed within a
// month of being added.
//
// The vault holds the mapping in memory for the lifetime of the Redactor, and
// never leaves the process. That is the entire security property: the model
// sees placeholders, your application sees real values, and the boundary is
// explicit rather than implied.
//
// # Why placeholders are stable
//
// The same value always gets the same placeholder within one Redactor. If two
// mentions of the same address became [EMAIL_1] and [EMAIL_2], the model would
// reason about them as two different people — which is a correctness bug, not a
// cosmetic one. Consistent tokens preserve the relationships in the text.
//
// A Redactor is safe for concurrent use.
type Redactor struct {
	detectors []Detector

	mu       sync.RWMutex
	toValue  map[string]string // placeholder -> original
	toToken  map[string]string // original -> placeholder
	counters map[Kind]int
}

// Option configures a Redactor.
type Option func(*Redactor)

// WithDetectors replaces the detector set.
//
// Passing an empty slice is allowed and disables redaction entirely — useful
// for a benchmark or an A/B, and it fails loudly in the sense that nothing is
// redacted rather than quietly half-working.
func WithDetectors(detectors []Detector) Option {
	return func(r *Redactor) { r.detectors = detectors }
}

// New builds a Redactor with the default detector set.
func New(opts ...Option) *Redactor {
	r := &Redactor{
		detectors: DefaultDetectors(),
		toValue:   make(map[string]string),
		toToken:   make(map[string]string),
		counters:  make(map[Kind]int),
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// Result is one redaction, with enough detail to log what happened without
// logging what was found.
type Result struct {
	Text    string
	Matches []Match
}

// Counts returns how many of each kind were redacted.
//
// This is the safe thing to log and the safe thing to alert on. A spike in
// KindCreditCard reaching your prompt path is worth a page; the values
// themselves must never appear in a log line, which is the mistake that turns a
// redaction layer into a second copy of the data.
func (r Result) Counts() map[Kind]int {
	counts := make(map[Kind]int)
	for _, m := range r.Matches {
		counts[m.Kind]++
	}
	return counts
}

// Redact replaces personal data with placeholders.
func (r *Redactor) Redact(text string) Result {
	matches := Detect(text, r.detectors)
	if len(matches) == 0 {
		return Result{Text: text}
	}

	var b strings.Builder
	b.Grow(len(text))
	last := 0
	for _, m := range matches {
		b.WriteString(text[last:m.Start])
		b.WriteString(r.tokenFor(m))
		last = m.End
	}
	b.WriteString(text[last:])

	return Result{Text: b.String(), Matches: matches}
}

// tokenFor returns the stable placeholder for a value, minting one if needed.
func (r *Redactor) tokenFor(m Match) string {
	key := string(m.Kind) + ":" + m.Value

	r.mu.RLock()
	token, ok := r.toToken[key]
	r.mu.RUnlock()
	if ok {
		return token
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	// Re-check: another goroutine may have minted this token between the
	// read unlock and the write lock. Without this, two callers redacting the
	// same value concurrently get different placeholders — the exact
	// inconsistency the stable-token design exists to prevent.
	if token, ok := r.toToken[key]; ok {
		return token
	}

	r.counters[m.Kind]++
	token = fmt.Sprintf("[%s_%d]", m.Kind, r.counters[m.Kind])
	r.toToken[key] = token
	r.toValue[token] = m.Value
	return token
}

// Restore puts original values back, reversing Redact.
//
// Call this on the model's output before showing it to a user or writing it to
// your own store. Placeholders the vault does not know are left untouched: a
// model that invents "[EMAIL_9]" must not cause a panic, and silently deleting
// it would hide the hallucination.
func (r *Redactor) Restore(text string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if len(r.toValue) == 0 {
		return text
	}
	// Replace longer tokens first so [EMAIL_11] is not damaged by a
	// replacement of [EMAIL_1].
	pairs := make([]string, 0, len(r.toValue)*2)
	for token, value := range r.toValue {
		pairs = append(pairs, token, value)
	}
	sortPairsByTokenLengthDesc(pairs)
	return strings.NewReplacer(pairs...).Replace(text)
}

// sortPairsByTokenLengthDesc sorts a flat (old, new, old, new…) slice so longer
// tokens are replaced first. Insertion sort: these slices are small, and the
// clarity is worth more here than the asymptotics.
func sortPairsByTokenLengthDesc(pairs []string) {
	for i := 2; i < len(pairs); i += 2 {
		token, value := pairs[i], pairs[i+1]
		j := i - 2
		for j >= 0 && len(pairs[j]) < len(token) {
			pairs[j+2], pairs[j+3] = pairs[j], pairs[j+1]
			j -= 2
		}
		pairs[j+2], pairs[j+3] = token, value
	}
}

// VaultSize reports how many distinct values are held.
//
// Worth watching: the vault grows for the lifetime of the Redactor, so a
// long-lived one over high-cardinality traffic is a memory leak with a
// respectable job title. Use a per-request or per-conversation Redactor unless
// you have measured otherwise.
func (r *Redactor) VaultSize() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.toValue)
}
