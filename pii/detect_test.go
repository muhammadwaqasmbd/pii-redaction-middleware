package pii

import (
	"strconv"
	"strings"
	"testing"
)

func TestValidLuhn(t *testing.T) {
	// The single highest-value check in the package: without it a card
	// detector fires on order numbers, timestamps and tracking ids.
	valid := []string{
		"4111111111111111",
		"5500005555555559",
		"4111 1111 1111 1111",
		"4111-1111-1111-1111",
		"378282246310005",
	}
	for _, s := range valid {
		if !ValidLuhn(s) {
			t.Errorf("ValidLuhn(%q) = false, want true", s)
		}
	}

	invalid := []string{
		"4111111111111112",
		"1234567890123456",
		"411111111111",
		"41111111111111111111",
	}
	for _, s := range invalid {
		if ValidLuhn(s) {
			t.Errorf("ValidLuhn(%q) = true, want false", s)
		}
	}
}

func TestLuhnAcceptsAllZeroes(t *testing.T) {
	// Documented rather than fixed. Luhn is a checksum, not a validator: all
	// zeroes sums to zero and passes. Special-casing it would imply a
	// guarantee the algorithm does not make and hide that from the next reader.
	if !ValidLuhn("0000000000000000") {
		t.Error("expected Luhn to accept all zeroes; if this changed, update the docs")
	}
}

func TestLuhnRejectsMostArbitraryDigitStrings(t *testing.T) {
	// The practical argument for the check: about 9 in 10 arbitrary 16-digit
	// strings fail, which is the difference between a usable filter and one
	// that redacts every order number in the corpus.
	rejected, total := 0, 0
	for n := 1000000000000000; n < 1000000000000100; n++ {
		total++
		if !ValidLuhn(strconv.Itoa(n)) {
			rejected++
		}
	}
	if rejected*10 < total*8 {
		t.Errorf("Luhn rejected %d/%d strings; expected at least 80%%", rejected, total)
	}
}

func TestDetectFindsEachKind(t *testing.T) {
	cases := []struct {
		name string
		text string
		want Kind
	}{
		{"email", "write to alice@example.com please", KindEmail},
		{"card", "card 4111 1111 1111 1111 declined", KindCreditCard},
		{"ssn", "ssn 123-45-6789 on file", KindSSN},
		{"ip", "request from 192.168.1.100 failed", KindIPAddress},
		{"github token", "token ghp_" + strings.Repeat("a", 36) + " leaked", KindAPIKey},
		{"aws key", "key AKIAIOSFODNN7EXAMPLE in config", KindAPIKey},
		{"iban", "pay GB82WEST12345698765432 today", KindIBAN},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var found bool
			for _, m := range Detect(tc.text, DefaultDetectors()) {
				if m.Kind == tc.want {
					found = true
				}
			}
			if !found {
				t.Errorf("Detect(%q) did not find %s", tc.text, tc.want)
			}
		})
	}
}

func TestDetectRejectsLookalikes(t *testing.T) {
	// The false positives that get a redactor switched off within a fortnight.
	cases := []struct {
		name string
		text string
		kind Kind
	}{
		{"order number is not a card", "order 1234567890123456 shipped", KindCreditCard},
		{"invalid ssn area", "reference 666-45-6789", KindSSN},
		{"zero ssn group", "reference 123-00-6789", KindSSN},
		{"octet over 255", "version 10.20.300.40 released", KindIPAddress},
		{"short number is not a phone", "port 8080 open", KindPhone},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, m := range Detect(tc.text, DefaultDetectors()) {
				if m.Kind == tc.kind {
					t.Errorf("false positive: %q matched %s as %q", tc.text, tc.kind, m.Value)
				}
			}
		})
	}
}

func TestOverlapsResolveToTheLongestMatch(t *testing.T) {
	// An email contains things other detectors also match. Applying every
	// detector naively mangles offsets and yields garbage like "[EMAIL_1][IP_1]".
	matches := Detect("contact alice@example.com now", DefaultDetectors())
	if len(matches) != 1 {
		t.Fatalf("expected exactly 1 match, got %d: %v", len(matches), matches)
	}
	if matches[0].Kind != KindEmail || matches[0].Value != "alice@example.com" {
		t.Errorf("expected the whole email, got %s %q", matches[0].Kind, matches[0].Value)
	}
}

func TestDetectIsDeterministic(t *testing.T) {
	// Output depending on map iteration order makes placeholders unstable,
	// which breaks caching, diffing and reversal at once.
	text := "alice@example.com from 192.168.1.1 card 4111111111111111"
	first := Detect(text, DefaultDetectors())
	for i := 0; i < 20; i++ {
		again := Detect(text, DefaultDetectors())
		if len(again) != len(first) {
			t.Fatalf("run %d found %d matches, first found %d", i, len(again), len(first))
		}
		for j := range first {
			if again[j] != first[j] {
				t.Fatalf("run %d differs at %d: %v vs %v", i, j, again[j], first[j])
			}
		}
	}
}

func TestMatchesAreOrderedByPosition(t *testing.T) {
	text := "first@example.com then 192.168.1.1 then second@example.com"
	matches := Detect(text, DefaultDetectors())
	for i := 1; i < len(matches); i++ {
		if matches[i].Start < matches[i-1].Start {
			t.Errorf("matches out of order at %d: %v", i, matches)
		}
	}
}

func TestIBANChecksum(t *testing.T) {
	if !validIBAN("GB82WEST12345698765432") {
		t.Error("expected a valid IBAN to pass mod-97")
	}
	if validIBAN("GB82WEST12345698765433") {
		t.Error("expected a corrupted IBAN to fail mod-97")
	}
}

func TestEmptyTextFindsNothing(t *testing.T) {
	if got := Detect("", DefaultDetectors()); len(got) != 0 {
		t.Errorf("expected no matches in empty text, got %v", got)
	}
}

func TestNoDetectorsFindsNothing(t *testing.T) {
	// Allowed, and it fails visibly: nothing is redacted, rather than the
	// filter quietly half-working.
	if got := Detect("alice@example.com", nil); len(got) != 0 {
		t.Errorf("expected no matches with no detectors, got %v", got)
	}
}

func TestPhoneDoesNotSliceALongerNumber(t *testing.T) {
	// The phone pattern can match 12 digits out of the middle of a 16-digit
	// order number. RE2 has no lookbehind and \b breaks the leading "+" case,
	// so WholeRun does the work.
	for _, text := range []string{
		"order 1234567890123456 shipped",
		"trace 900000000000000001 recorded",
	} {
		for _, m := range Detect(text, DefaultDetectors()) {
			if m.Kind == KindPhone {
				t.Errorf("%q sliced a phone out of a longer number: %q", text, m.Value)
			}
		}
	}
}

func TestARealPhoneNumberStillMatches(t *testing.T) {
	// The other half: WholeRun must not suppress genuine numbers, including
	// the international form whose leading "+" defeats a \b anchor.
	for _, text := range []string{
		"call +44 20 7946 0958 today",
		"ring 020 7946 0958 please",
		"phone: 555-123-4567",
	} {
		var found bool
		for _, m := range Detect(text, DefaultDetectors()) {
			if m.Kind == KindPhone {
				found = true
			}
		}
		if !found {
			t.Errorf("no phone found in %q", text)
		}
	}
}

func TestADottedQuadIsNeverAPhoneNumber(t *testing.T) {
	// "10.20.300.40" fails IP validation on the third octet, and would then be
	// picked up by the phone detector — a worse answer than no match at all.
	for _, text := range []string{
		"version 10.20.300.40 released",
		"host 192.168.1.1 responded",
	} {
		for _, m := range Detect(text, DefaultDetectors()) {
			if m.Kind == KindPhone {
				t.Errorf("%q matched a dotted quad as a phone: %q", text, m.Value)
			}
		}
	}
}
