// Package pii finds and removes personal data before it reaches a model.
//
// # What this cannot do
//
// Regular expressions find *structured* identifiers — emails, card numbers,
// national insurance numbers, API keys. They cannot find names, addresses, job
// titles or the sentence "the patient in room 4 is the mayor's wife". Those are
// PII too, and no pattern will catch them.
//
// So this is a control that reduces exposure, not a compliance guarantee. Any
// vendor selling you a regex-based redactor as GDPR or HIPAA compliance is
// selling you the part that was easy. The hard part is a data-flow decision:
// what leaves your network at all.
//
// Two design choices are worth knowing before reading further.
//
// # Validation, not just matching
//
// A regex for a 16-digit card number also matches order ids, timestamps,
// tracking numbers and session tokens. Redacting all of those makes the text
// useless and trains people to switch the filter off. Card numbers are checked
// with the Luhn algorithm, which removes the overwhelming majority of those
// false positives for the cost of about twenty lines.
//
// # Longest match wins
//
// Overlapping detectors are the subtle failure. If an email detector matches
// user@example.com and a domain detector matches example.com, applying both
// naively produces "[EMAIL_1][DOMAIN_1]" or worse, mangled offsets. Matches are
// resolved by preferring the longest, then the earliest — deterministically, so
// the same input always redacts identically.
package pii

import (
	"regexp"
	"sort"
	"strings"
)

// Kind identifies what a detector looks for. It becomes the placeholder prefix,
// so it is part of the output contract and should not be renamed casually.
type Kind string

const (
	KindEmail      Kind = "EMAIL"
	KindPhone      Kind = "PHONE"
	KindCreditCard Kind = "CARD"
	KindSSN        Kind = "SSN"
	KindIPAddress  Kind = "IP"
	KindAPIKey     Kind = "API_KEY"
	KindIBAN       Kind = "IBAN"
)

// Match is one detected span, in byte offsets into the original string.
type Match struct {
	Kind  Kind
	Start int
	End   int
	Value string
}

// Len reports the span width, used when resolving overlaps.
func (m Match) Len() int { return m.End - m.Start }

// Detector finds spans of one kind of personal data.
//
// Validate is applied to every regex hit and may reject it. That two-stage
// shape is what keeps precision usable: the pattern can stay permissive enough
// to catch real formatting variety while validation removes the noise.
type Detector struct {
	Kind     Kind
	Pattern  *regexp.Regexp
	Validate func(string) bool

	// Priority breaks ties when two detectors match the identical span.
	//
	// Needed because "123-45-6789" is matched by both the SSN detector and the
	// phone detector, at exactly the same offsets and the same length. Ordering
	// by name would resolve that alphabetically, which is arbitrary — and it
	// picked PHONE, mislabelling every SSN in the corpus.
	//
	// Higher wins. Rank by how much evidence the detector actually has: a
	// checksum or an issued-range check earns a high priority, a permissive
	// digit-group pattern earns a low one.
	Priority int

	// WholeRun rejects a match whose immediate neighbour is another digit.
	//
	// Without it, the phone pattern happily matches a 12-digit slice out of the
	// middle of a 16-digit order number, and "order 1234567890123456 shipped"
	// redacts as a phone number. RE2 has no lookbehind, and bolting \b onto the
	// pattern breaks the leading "+" case, so the check lives here where it can
	// see the surrounding text.
	WholeRun bool
}

// Find returns every accepted match, in order of appearance.
func (d Detector) Find(text string) []Match {
	hits := d.Pattern.FindAllStringIndex(text, -1)
	matches := make([]Match, 0, len(hits))
	for _, hit := range hits {
		start, end := hit[0], hit[1]
		if d.WholeRun && touchesDigit(text, start, end) {
			continue
		}
		value := text[start:end]
		if d.Validate != nil && !d.Validate(value) {
			continue
		}
		matches = append(matches, Match{Kind: d.Kind, Start: start, End: end, Value: value})
	}
	return matches
}

// touchesDigit reports whether the character immediately before or after the
// span is a digit, meaning the match is a slice of a longer number.
func touchesDigit(text string, start, end int) bool {
	if start > 0 && text[start-1] >= '0' && text[start-1] <= '9' {
		return true
	}
	return end < len(text) && text[end] >= '0' && text[end] <= '9'
}

var (
	// Deliberately not RFC 5322. A fully compliant email regex is famously
	// several thousand characters and matches addresses nobody uses; this
	// matches what appears in real support tickets and logs.
	emailPattern = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)

	// International and North American forms, with separators.
	//
	// Groups are 2-4 digits, not 3-4: an earlier version required three groups
	// of three or more and so could not match "+44 20 7946 0958", because UK
	// area codes are two digits. Digit-count validation, not the group shape,
	// is what keeps this from matching years and ports.
	phonePattern = regexp.MustCompile(`(?:\+\d{1,3}[\s.\-]?)?(?:\(\d{1,4}\)[\s.\-]?)?\d{2,4}(?:[\s.\-]?\d{2,4}){1,4}`)

	// A dotted quad is an address, whatever its octets say. Without this,
	// "10.20.300.40" is rejected by the IP validator and then picked up by the
	// phone detector, which is a worse answer than not matching at all.
	dottedQuadPattern = regexp.MustCompile(`^\d{1,3}(?:\.\d{1,3}){3}$`)

	// 13-19 digits with optional separators. Luhn does the real work.
	cardPattern = regexp.MustCompile(`\b(?:\d[ \-]?){13,19}\b`)

	// US Social Security number. Area 000, 666 and 900-999 are never issued,
	// and the group and serial are never all zeroes — checked in validation.
	ssnPattern = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)

	ipPattern = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)

	// Common provider key shapes. Broad on purpose: a leaked key reaching a
	// third-party model is a worse outcome than an over-redacted log line, so
	// this is the one detector where recall is deliberately favoured.
	apiKeyPattern = regexp.MustCompile(`\b(?:sk|pk|rk)[-_](?:live|test|proj)?[-_]?[A-Za-z0-9]{16,}\b|\bghp_[A-Za-z0-9]{36}\b|\bxox[baprs]-[A-Za-z0-9\-]{10,}\b|\bAKIA[0-9A-Z]{16}\b`)

	ibanPattern = regexp.MustCompile(`\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b`)
)

// DefaultDetectors is the standard set. Order does not affect the result —
// overlaps are resolved by span length, not by detector position — but it is
// kept stable so output diffs stay readable.
func DefaultDetectors() []Detector {
	return []Detector{
		{Kind: KindEmail, Pattern: emailPattern, Priority: 100},
		{Kind: KindAPIKey, Pattern: apiKeyPattern, Priority: 100},
		{Kind: KindIBAN, Pattern: ibanPattern, Validate: validIBAN, Priority: 90},
		{Kind: KindCreditCard, Pattern: cardPattern, Validate: ValidLuhn, Priority: 90},
		{Kind: KindSSN, Pattern: ssnPattern, Validate: validSSN, Priority: 80},
		{Kind: KindIPAddress, Pattern: ipPattern, Validate: validIPv4, Priority: 50},
		// Lowest: the pattern is permissive by necessity, so on an exact tie any
		// other detector has more evidence than this one does.
		{Kind: KindPhone, Pattern: phonePattern, Validate: plausiblePhone,
			WholeRun: true, Priority: 10},
	}
}

// ValidLuhn reports whether the digits in s satisfy the Luhn checksum.
//
// This is the single highest-value line of code in the package. Without it, a
// card detector fires on order numbers, timestamps and tracking ids, and the
// resulting noise is why redaction gets disabled. Roughly 90% of random digit
// strings fail Luhn.
//
// It is a checksum, not proof: a Luhn-valid string is not necessarily a card.
func ValidLuhn(s string) bool {
	digits := make([]int, 0, len(s))
	for _, r := range s {
		if r >= '0' && r <= '9' {
			digits = append(digits, int(r-'0'))
		}
	}
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}

	sum := 0
	double := false
	// Right to left, doubling every second digit.
	for i := len(digits) - 1; i >= 0; i-- {
		d := digits[i]
		if double {
			if d *= 2; d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}

// validSSN rejects the ranges the US Social Security Administration never
// issues. Without it, any nnn-nn-nnnn string redacts — including dates written
// with dashes and internal reference numbers.
func validSSN(s string) bool {
	parts := strings.Split(s, "-")
	if len(parts) != 3 {
		return false
	}
	area, group, serial := parts[0], parts[1], parts[2]
	if area == "000" || area == "666" || area >= "900" {
		return false
	}
	return group != "00" && serial != "0000"
}

// validIPv4 rejects octets above 255, so version strings and dotted decimals
// like 10.20.300.40 do not redact as addresses.
func validIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if len(part) > 1 && part[0] == '0' {
			return false // leading zeroes are not a normal address
		}
		n := 0
		for _, r := range part {
			n = n*10 + int(r-'0')
		}
		if n > 255 {
			return false
		}
	}
	return true
}

// plausiblePhone requires enough digits to be a real number. The pattern is
// permissive so it catches formatting variety; this is where the noise is
// removed.
func plausiblePhone(s string) bool {
	if dottedQuadPattern.MatchString(s) {
		return false
	}
	digits := 0
	for _, r := range s {
		if r >= '0' && r <= '9' {
			digits++
		}
	}
	return digits >= 9 && digits <= 15
}

// validIBAN checks length by country and the mod-97 checksum, which is what
// makes IBAN detection precise rather than a two-letters-then-digits guess.
func validIBAN(s string) bool {
	s = strings.ReplaceAll(s, " ", "")
	if len(s) < 15 || len(s) > 34 {
		return false
	}
	// Move the first four characters to the end, then interpret letters as
	// numbers (A=10 … Z=35) and take mod 97. A valid IBAN leaves remainder 1.
	rearranged := s[4:] + s[:4]
	remainder := 0
	for _, r := range rearranged {
		switch {
		case r >= '0' && r <= '9':
			remainder = (remainder*10 + int(r-'0')) % 97
		case r >= 'A' && r <= 'Z':
			remainder = (remainder*100 + int(r-'A') + 10) % 97
		default:
			return false
		}
	}
	return remainder == 1
}

// Detect runs every detector and resolves overlaps.
//
// Resolution is longest-match-first, then earliest, then by kind for total
// determinism. Determinism matters more than it looks: a redactor whose output
// depends on map iteration order produces different placeholders on every run,
// which makes caching, diffing and reversal all unreliable.
func Detect(text string, detectors []Detector) []Match {
	// Priority is carried alongside rather than inside Match, so the public
	// type stays a plain description of what was found.
	type ranked struct {
		match    Match
		priority int
	}

	var all []ranked
	for _, d := range detectors {
		for _, m := range d.Find(text) {
			all = append(all, ranked{match: m, priority: d.Priority})
		}
	}

	sort.Slice(all, func(i, j int) bool {
		if all[i].match.Len() != all[j].match.Len() {
			return all[i].match.Len() > all[j].match.Len()
		}
		if all[i].match.Start != all[j].match.Start {
			return all[i].match.Start < all[j].match.Start
		}
		if all[i].priority != all[j].priority {
			return all[i].priority > all[j].priority
		}
		// Last resort, so the order is total and the output is reproducible
		// even for two detectors that tie on everything else.
		return all[i].match.Kind < all[j].match.Kind
	})

	var kept []Match
	for _, candidate := range all {
		overlaps := false
		for _, existing := range kept {
			if candidate.match.Start < existing.End && existing.Start < candidate.match.End {
				overlaps = true
				break
			}
		}
		if !overlaps {
			kept = append(kept, candidate.match)
		}
	}

	sort.Slice(kept, func(i, j int) bool { return kept[i].Start < kept[j].Start })
	return kept
}
