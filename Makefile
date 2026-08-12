.PHONY: build test test-race vet check-comments staticcheck e2e-local clean lint all

BINARY := kauket
PKG := ./cmd/kauket

build:
	go build -o $(BINARY) $(PKG)

test:
	go test ./...

test-race:
	go test -race ./...

vet:
	go vet ./...

check-comments:
	./scripts/check-comments.sh

staticcheck:
	go run honnef.co/go/tools/cmd/staticcheck@latest ./...

e2e-local:
	./scripts/e2e-local.sh

lint: vet check-comments staticcheck
	gofmt -l . | tee /dev/stderr | (! read)

all: lint test test-race build

clean:
	rm -f $(BINARY)
	rm -rf dist/
	rm -f coverage.out
