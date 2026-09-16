.PHONY: build run resources test lint

build:
	go build -o bin/doh-finder.exe ./cmd/doh-finder

run:
	go run ./cmd/doh-finder

resources:
	go generate ./cmd/doh-finder

test:
	go test ./...

lint:
	go vet ./...
