# pii-redaction-middleware

Strip personal data out of text before it reaches a model — **and put it back
in the answer**. Go, standard library only.

```bash
go run ./cmd/piiredact -demo
go install github.com/muhammadwaqasmbd/pii-redaction-middleware/cmd/piiredact@latest
```

```go
r := pii.New()

safe := r.Redact("alice@example.com cannot log in from 192.168.1.50")
// "[EMAIL_1] cannot log in from [IP_1]"

answer := callModel(safe.Text)
// "Ask [EMAIL_1] to reset their password."

fmt.Println(r.Restore(answer))
// "Ask alice@example.com to reset their password."
```

---

## Start with what this cannot do

Regular expressions find **structured** identifiers: emails, card numbers,
national insurance numbers, API keys, IBANs. They cannot find names, addresses,
job titles, or "the patient in room 4 is the mayor's wife". That is PII too, and
no pattern will catch it.

So this reduces exposure. It is not GDPR or HIPAA compliance, and any vendor
selling a regex redactor as compliance is selling you the part that was easy.
The hard part is a data-flow decision: what leaves your network at all.

---

## Four things that are usually missing

### 1. Reversibility — or the layer gets removed

Irreversible redaction breaks the use case. The model answers "ask [EMAIL_1] to
reset their password", which is useless to a support agent unless something puts
the address back. One-way scrubbing is why so many redaction layers get deleted
a month after they are added.

The vault lives in memory for the lifetime of the `Redactor` and never leaves the
process. That is the whole security property: the model sees placeholders, your
application sees real values, and the boundary is explicit.

### 2. Stable placeholders — a correctness issue, not a cosmetic one

The same value always gets the same token. If two mentions of one address became
`[EMAIL_1]` and `[EMAIL_2]`, the model would reason about them as two different
people. Consistent tokens preserve the relationships in the text.

### 3. Validation, not just matching

A regex for 16 digits also matches order ids, timestamps, tracking numbers and
session tokens. Redacting all of them makes text useless and gets the filter
switched off.

| Detector | Validation | Rejects |
|---|---|---|
| Card | **Luhn checksum** | ~90% of arbitrary 16-digit strings |
| SSN | Unissued ranges (000, 666, 900+) | Dates and reference numbers |
| IP | Octets ≤ 255, no leading zeroes | Version strings like `10.20.300.40` |
| IBAN | **mod-97 checksum** | Two-letters-then-digits lookalikes |
| Phone | Digit count, plus `WholeRun` | Slices of longer numbers |

That last one is subtle enough to be worth naming. The phone pattern will
happily match twelve digits out of the middle of a sixteen-digit order number.
Go's RE2 has no lookbehind, and bolting `\b` onto the front breaks the leading
`+` of international numbers — so `WholeRun` checks the neighbouring character
instead, where it can see the surrounding text.

### 4. Streaming, where the leak actually happens

Streaming is the default for model output, and the naive implementation redacts
each chunk as it arrives. That leaks, because chunk boundaries fall wherever the
tokeniser put them:

```
chunk 1: "contact me at user@exa"
chunk 2: "mple.com tomorrow"
```

Neither chunk contains a matchable email. Both pass a per-chunk redactor
untouched, the address reaches the client in two pieces the browser reassembles,
and **the redactor reports zero matches** — so it looks like it is working.

`StreamRedactor` buffers until text cannot be part of a longer match:

```go
stream := pii.NewStream(r, pii.DefaultHoldback)
for chunk := range chunks {
    io.WriteString(w, stream.Write(chunk))
}
io.WriteString(w, stream.Flush())   // always — this is the tail of the stream
```

**The cost is real:** output lags input by up to `Holdback` bytes, so the first
token reaches the user later. That is the trade for not leaking, which is why
`Holdback` is tuned to your longest detector and not to your latency budget.
Setting it low silently reintroduces the bug.

A test splits the same sentence at *every byte offset* and asserts nothing
escapes at any of them. One boundary case passing proves very little.

---

## HTTP middleware

```go
redactor := pii.New()
mux.Handle("/chat", pii.NewMiddleware(redactor).Handler(chatHandler))
```

Put it in front of the handler that builds prompts, **not** in front of
everything — a redactor scanning bodies that never go near a model is latency
and risk for no benefit, and it will eventually mangle a payload that happened
to look like a card number.

Deliberate omissions:

- **URLs, query strings and headers are untouched.** They routinely carry
  identifiers, and rewriting them breaks routing, authentication and caching in
  ways that are hard to see. Keep PII out of URLs at the source.
- **Responses are untouched.** Response redaction needs the streaming path *and*
  `Restore` — and the handler knows which placeholders belong to which request
  while the middleware does not.
- **Bodies are capped** at 1 MiB. An unbounded read is a denial-of-service
  vector: a client streaming an endless body allocates until the process dies.
- **`ContentLength` is corrected.** Placeholders are rarely the same length as
  what they replaced, and a stale value makes downstream decoders truncate or
  hang.
- **Failures fail closed.** An unreadable body returns 400 rather than being
  forwarded unscanned.

Only counts are logged, never values. Logging what was found makes your log a
second, less protected copy of exactly the data the middleware exists to
contain — a genuinely common way this control backfires.

---

## Operational notes

**The vault is unbounded.** It grows for the lifetime of the `Redactor`, so a
long-lived one over high-cardinality traffic is a memory leak with a respectable
job title. Use a per-request or per-conversation `Redactor` unless you have
measured otherwise; `VaultSize()` is there to watch.

**`Redactor` is safe for concurrent use.** The double-checked lock in
`tokenFor` is not decoration — without it, two goroutines redacting the same
value mint different placeholders, which is the exact inconsistency stable
tokens exist to prevent. There is a test with 32 goroutines.

**Luhn accepts all zeroes.** Documented rather than special-cased: it is a
checksum, not a validator, and pretending otherwise would imply a guarantee the
algorithm does not make. There is a test asserting the current behaviour so a
change is deliberate.

---

## Testing

```bash
make test        # go test -race -cover ./...
```

The load-bearing cases: the chunk-boundary leak is demonstrated on the naive
path before being shown fixed, the same sentence is split at every byte offset,
multi-byte runes are never split, 32 concurrent goroutines agree on
placeholders, `[EMAIL_1]` does not corrupt `[EMAIL_11]` on restore, a
hallucinated `[EMAIL_9]` is left alone rather than deleted, redacted JSON stays
valid JSON, and `ContentLength` matches the rewritten body.

---

## Licence

MIT. Built by [Muhammad Waqas](https://muhammadwaqas.pages.dev/) — a decade of
enterprise engineering in banking, healthcare and compliance, where "we redacted
it" and "it never left" were always different claims.
