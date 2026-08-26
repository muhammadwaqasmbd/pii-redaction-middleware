package pii

import (
	"strings"
	"testing"
)

func TestTheChunkBoundaryLeak(t *testing.T) {
	// The bug this whole type exists to prevent. A naive per-chunk redactor
	// passes both of these untouched, reports zero matches, and looks like it
	// is working while the address reaches the client in two pieces.
	chunks := []string{"contact me at user@exa", "mple.com tomorrow"}

	naive := New()
	var leaked strings.Builder
	for _, c := range chunks {
		leaked.WriteString(naive.Redact(c).Text)
	}
	if !strings.Contains(leaked.String(), "user@example.com") {
		t.Fatal("premise broken: the naive path was expected to leak")
	}

	safe := RedactAll(New(), chunks)
	if strings.Contains(safe, "user@example.com") {
		t.Errorf("streaming redactor leaked the address: %q", safe)
	}
	if !strings.Contains(safe, "[EMAIL_1]") {
		t.Errorf("expected a placeholder in %q", safe)
	}
}

func TestSplitAtEveryPossibleOffset(t *testing.T) {
	// One boundary case passing proves very little. This splits the same text
	// at every byte offset, which is the only way to be confident the holdback
	// logic has no off-by-one.
	full := "please email alice@example.com or call +44 20 7946 0958 today"
	for i := 1; i < len(full); i++ {
		chunks := []string{full[:i], full[i:]}
		got := RedactAll(New(), chunks)
		if strings.Contains(got, "alice@example.com") {
			t.Errorf("split at %d leaked the email: %q", i, got)
		}
	}
}

func TestManySmallChunks(t *testing.T) {
	// Token-by-token streaming, the realistic worst case.
	full := "card 4111 1111 1111 1111 belongs to alice@example.com"
	var chunks []string
	for _, r := range full {
		chunks = append(chunks, string(r))
	}
	got := RedactAll(New(), chunks)
	if strings.Contains(got, "alice@example.com") {
		t.Errorf("leaked email under 1-byte chunking: %q", got)
	}
	if strings.Contains(got, "4111 1111 1111 1111") {
		t.Errorf("leaked card under 1-byte chunking: %q", got)
	}
}

func TestStreamPreservesCleanText(t *testing.T) {
	full := "The deployment finished successfully after 42 seconds of work."
	got := RedactAll(New(), []string{full[:20], full[20:]})
	if got != full {
		t.Errorf("clean text was altered:\n got %q\nwant %q", got, full)
	}
}

func TestMultibyteRunesAreNotSplit(t *testing.T) {
	// Emitting half a UTF-8 rune corrupts the text in the client even when no
	// personal data was involved.
	full := "déjà vu — naïve café " + strings.Repeat("ü", 200) + " alice@example.com"
	got := RedactAll(New(), []string{full[:100], full[100:]})
	if strings.ContainsRune(got, '�') {
		t.Error("output contains a replacement character; a rune was split")
	}
	if strings.Contains(got, "alice@example.com") {
		t.Errorf("leaked the email: %q", got)
	}
}

func TestFlushEmitsTheTail(t *testing.T) {
	// Skipping Flush loses up to Holdback bytes — usually the last sentence.
	s := NewStream(New(), DefaultHoldback)
	emitted := s.Write("a short message that never reaches the holdback limit")
	if emitted != "" {
		t.Errorf("expected nothing emitted before the holdback fills, got %q", emitted)
	}
	if tail := s.Flush(); tail == "" {
		t.Error("Flush emitted nothing; the whole message would have been lost")
	}
}

func TestFlushOnAnEmptyStreamIsSafe(t *testing.T) {
	s := NewStream(New(), DefaultHoldback)
	if got := s.Flush(); got != "" {
		t.Errorf("expected empty output, got %q", got)
	}
	if got := s.Flush(); got != "" {
		t.Errorf("expected a second Flush to be a no-op, got %q", got)
	}
}

func TestZeroHoldbackFallsBackToTheDefault(t *testing.T) {
	// A zero holdback is the per-chunk redactor whose leak this type prevents,
	// so it is never what someone means.
	s := NewStream(New(), 0)
	if s.holdback != DefaultHoldback {
		t.Errorf("expected the default holdback, got %d", s.holdback)
	}
}

func TestStreamReportsWhatItRedacted(t *testing.T) {
	s := NewStream(New(), DefaultHoldback)
	s.Write("alice@example.com and bob@example.com and " + strings.Repeat("filler ", 40))
	s.Flush()
	if len(s.Matches()) < 2 {
		t.Errorf("expected at least 2 matches across the stream, got %d", len(s.Matches()))
	}
}

func TestStreamMakesProgressOnLongCleanInput(t *testing.T) {
	// The holdback must not grow without bound: text well past the window has
	// to be emitted, or a long stream buffers until the process dies.
	s := NewStream(New(), 64)
	var emitted strings.Builder
	for i := 0; i < 50; i++ {
		emitted.WriteString(s.Write("a chunk of perfectly ordinary text. "))
	}
	if emitted.Len() == 0 {
		t.Fatal("nothing was emitted across 50 chunks; the buffer is not draining")
	}
	if s.Buffered() > 256 {
		t.Errorf("buffer grew to %d bytes with a 64-byte holdback", s.Buffered())
	}
}

func TestPlaceholdersStayConsistentAcrossStreams(t *testing.T) {
	// Two streams sharing one Redactor must agree on placeholders, or a
	// multi-turn conversation reasons about one person as several.
	r := New()
	first := RedactAll(r, []string{"from alice@example.com ", strings.Repeat("x", 200)})
	second := RedactAll(r, []string{"reply to alice@example.com ", strings.Repeat("y", 200)})
	if !strings.Contains(first, "[EMAIL_1]") || !strings.Contains(second, "[EMAIL_1]") {
		t.Errorf("placeholders diverged across streams:\n%q\n%q", first, second)
	}
}
