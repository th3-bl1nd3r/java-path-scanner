BINARY = jps
MODULE = github.com/nghia/java-path-scanner
VERSION = 1.0.0

.PHONY: all build test clean install

all: build

build:
	go build -ldflags="-s -w" -o $(BINARY) ./cmd/jps/

test:
	go test ./... -v -count=1

test-short:
	go test ./... -count=1

install:
	go install ./cmd/jps/

clean:
	rm -f $(BINARY)
	go clean -cache

tidy:
	go mod tidy

lint:
	@which golangci-lint > /dev/null 2>&1 || echo "Install golangci-lint: https://golangci-lint.run/usage/install/"
	golangci-lint run ./...

fmt:
	gofmt -w -s .
