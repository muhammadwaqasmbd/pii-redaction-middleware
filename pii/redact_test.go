package pii

import (
	"strings"
	"sync"
	"testing"
)

func TestRedactReplacesWithPlaceholders(t *testing.T) {
	r := New()
	got := r.Redact("email alice@example.com about it").Text
	if strings.Contains(got, "alice@example.com") {
		t.Errorf("original value survived redaction: %q", got)
	}
	if !strings.Contains(got, "[EMAIL_1]") {
		t.Errorf("expected a placeholder, got %q", got)
	}
}

func TestTheSameValueGetsTheSamePlaceholder(t *testing.T) {
	// Not cosmetic. If two mentions of one address became [EMAIL_1] and
	// [EMAIL_2], the model would reason about them as two different people.
	r := New()
	got := r.Redact("alice@example.com wrote; reply to alice@example.com").Text
	if strings.Count(got, "[EMAIL_1]") != 2 {
		t.Errorf("expected one stable placeholder used twice, got %q", got)
	}
}

func TestDifferentValuesGetDifferentPlaceholders(t *testing.T) {
	r := New()
	got := r.Redact("alice@example.com and bob@example.com").Text
	if !strings.Contains(got, "[EMAIL_1]") || !strings.Contains(got, "[EMAIL_2]") {
		t.Errorf("expected two distinct placeholders, got %q", got)
	}
}

func TestRestoreRoundTrips(t *testing.T) {
	// The property that makes redaction usable: the model answers about
	// [EMAIL_1] and the agent sees a real address.
	r := New()
	original := "alice@example.com cannot log in from 192.168.1.50"
	redacted := r.Redact(original)
	if got := r.Restore(redacted.Text); got != original {
		t.Errorf("round trip failed:\n got %q\nwant %q", got, original)
	}
}

func TestRestoreWorksOnModelOutputThatOnlyMentionsPlaceholders(t *testing.T) {
	r := New()
	r.Redact("ticket from alice@example.com")
	answer := "Ask [EMAIL_1] to reset their password."
	if got := r.Restore(answer); !strings.Contains(got, "alice@example.com") {
		t.Errorf("expected the address back, got %q", got)
	}
}

func TestRestoreLeavesUnknownPlaceholdersAlone(t *testing.T) {
	// A model that invents [EMAIL_9] must not panic the process, and silently
	// deleting it would hide the hallucination from whoever is reviewing.
	r := New()
	r.Redact("alice@example.com")
	got := r.Restore("contact [EMAIL_9] instead")
	if got != "contact [EMAIL_9] instead" {
		t.Errorf("expected the unknown placeholder untouched, got %q", got)
	}
}

func TestRestoreHandlesDoubleDigitPlaceholders(t *testing.T) {
	// [EMAIL_1] must not corrupt [EMAIL_11]. Longest tokens replace first.
	r := New()
	var b strings.Builder
	for i := 0; i < 12; i++ {
		b.WriteString("user")
		b.WriteString(strings.Repeat("x", i+1))
		b.WriteString("@example.com ")
	}
	redacted := r.Redact(b.String())
	restored := r.Restore(redacted.Text)
	if restored != b.String() {
		t.Errorf("round trip failed with double-digit placeholders:\n got %q\nwant %q",
			restored, b.String())
	}
}

func TestCountsReportKindsWithoutLeakingValues(t *testing.T) {
	// Counts are the safe thing to log. Logging values would make the log a
	// second, less protected copy of the data.
	r := New()
	result := r.Redact("alice@example.com and bob@example.com from 192.168.1.1")
	counts := result.Counts()
	if counts[KindEmail] != 2 {
		t.Errorf("expected 2 emails, got %d", counts[KindEmail])
	}
	if counts[KindIPAddress] != 1 {
		t.Errorf("expected 1 IP, got %d", counts[KindIPAddress])
	}
}

func TestTextWithoutPersonalDataIsUnchanged(t *testing.T) {
	r := New()
	clean := "The deployment finished successfully in 42 seconds."
	result := r.Redact(clean)
	if result.Text != clean {
		t.Errorf("clean text was modified: %q", result.Text)
	}
	if len(result.Matches) != 0 {
		t.Errorf("expected no matches, got %v", result.Matches)
	}
}

func TestEmptyDetectorSetRedactsNothing(t *testing.T) {
	r := New(WithDetectors(nil))
	text := "alice@example.com"
	if got := r.Redact(text).Text; got != text {
		t.Errorf("expected no redaction with no detectors, got %q", got)
	}
}

func TestConcurrentRedactionProducesStablePlaceholders(t *testing.T) {
	// The double-checked lock in tokenFor exists for exactly this: without it
	// two goroutines redacting the same value mint different placeholders,
	// which is the inconsistency stable tokens are meant to prevent.
	r := New()
	const goroutines = 32

	results := make([]string, goroutines)
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = r.Redact("contact alice@example.com").Text
		}(i)
	}
	wg.Wait()

	for i, got := range results {
		if got != results[0] {
			t.Fatalf("goroutine %d produced %q, goroutine 0 produced %q", i, got, results[0])
		}
	}
	if r.VaultSize() != 1 {
		t.Errorf("expected 1 vault entry for 1 distinct value, got %d", r.VaultSize())
	}
}

func TestVaultSizeTracksDistinctValues(t *testing.T) {
	// Worth watching: the vault grows for the lifetime of the Redactor, so a
	// long-lived one over high-cardinality traffic is a memory leak.
	r := New()
	r.Redact("alice@example.com bob@example.com alice@example.com")
	if r.VaultSize() != 2 {
		t.Errorf("expected 2 distinct values, got %d", r.VaultSize())
	}
}

func TestRestoreOnAnEmptyVaultIsANoOp(t *testing.T) {
	r := New()
	if got := r.Restore("nothing to restore"); got != "nothing to restore" {
		t.Errorf("expected input unchanged, got %q", got)
	}
}
