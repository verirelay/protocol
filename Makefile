.PHONY: build test lint check

build:
	go build ./...

test:
	go test ./...

lint:
	golangci-lint run

check: test build lint
