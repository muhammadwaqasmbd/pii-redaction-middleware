// Command piiredact demonstrates the package, including the chunk-boundary bug
// that motivates the streaming path.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/muhammadwaqasmbd/pii-redaction-middleware/pii"
)

const sample = `Ticket 4417 from alice@example.com (+44 20 7946 0958).
She reports card 4111 1111 1111 1111 was declined from 192.168.1.50.
Escalated by bob@example.com. Internal key: AKIAIOSFODNN7EXAMPLE`

func main() {
	demo := flag.Bool("demo", false, "run the bundled demonstration")
	flag.Parse()

	if *demo {
		runDemo()
		return
	}

	// Read stdin so this composes into a pipeline.
	redactor := pii.New()
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		fmt.Println(redactor.Redact(scanner.Text()).Text)
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "read error:", err)
		os.Exit(1)
	}
}

func runDemo() {
	rule := strings.Repeat("=", 68)

	fmt.Println(rule)
	fmt.Println("1  redact, then restore")
	fmt.Println(rule)
	redactor := pii.New()
	result := redactor.Redact(sample)
	fmt.Println(result.Text)
	fmt.Println()
	for kind, count := range result.Counts() {
		fmt.Printf("   %-8s %d\n", kind, count)
	}
	fmt.Println("\n   (counts are safe to log; the values never are)")

	fmt.Println()
	fmt.Println(rule)
	fmt.Println("2  the model answers about placeholders; Restore puts it back")
	fmt.Println(rule)
	answer := "Ask [EMAIL_1] to re-enter [CARD_1] — the request from [IP_1] was blocked."
	fmt.Println("   model output :", answer)
	fmt.Println("   agent sees   :", redactor.Restore(answer))

	fmt.Println()
	fmt.Println(rule)
	fmt.Println("3  the chunk-boundary leak")
	fmt.Println(rule)
	chunks := []string{"contact me at user@exa", "mple.com tomorrow"}

	naive := pii.New()
	var leaked strings.Builder
	for _, c := range chunks {
		leaked.WriteString(naive.Redact(c).Text)
	}
	fmt.Printf("   per-chunk  : %s\n", leaked.String())
	fmt.Printf("   streaming  : %s\n", pii.RedactAll(pii.New(), chunks))
	fmt.Println("\n   Neither chunk contains a matchable email, so a per-chunk redactor")
	fmt.Println("   passes both through and reports zero matches — while looking fine.")
}
