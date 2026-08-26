.PHONY: build test lint demo fmt

build:
	go build ./...

test:
	go test -race -cover ./...

lint:
	go vet ./...
	gofmt -l .

fmt:
	gofmt -w .

demo:
	go run ./cmd/piiredact -demo
