# evidencelocker - one command gates everything: `make check`.
SHELL := /bin/bash
GO ?= go
GOLANGCI_LINT ?= golangci-lint
export GOFLAGS ?= -p=3
COVER_MIN ?= 80
PKGS := ./...
CORE := ./pkg/... ./internal/...

.PHONY: all build test race cover fmt fmt-check vet lint check demo bench fuzz fixtures clean help

all: check

help:
	@echo "targets: build test race cover fmt fmt-check vet lint check demo bench fuzz fixtures clean"

build:
	$(GO) build -o bin/evidencelocker ./cmd/evidencelocker

test:
	$(GO) test $(PKGS)

race:
	$(GO) test -race -short $(PKGS)

cover:
	./scripts/coverage.sh $(COVER_MIN)

fmt:
	gofmt -w $$(git ls-files '*.go')

fmt-check:
	@out=$$(gofmt -l $$(git ls-files '*.go')); \
	if [ -n "$$out" ]; then echo "gofmt needed on:"; echo "$$out"; exit 1; fi; \
	echo "fmt-check: ok"

vet:
	$(GO) vet $(PKGS)

lint:
	@command -v $(GOLANGCI_LINT) >/dev/null || { echo "golangci-lint v2 not found on PATH"; exit 1; }
	$(GOLANGCI_LINT) run $(PKGS)

# format-check + vet (type-check) + lint (zero warnings) + race tests +
# full tests with the coverage threshold.
check: fmt-check vet lint race cover
	@echo "check: all gates passed"

demo:
	./scripts/demo.sh

bench:
	./scripts/bench.sh

fuzz:
	./scripts/fuzz.sh

fixtures:
	rm -rf testdata/hosts
	$(GO) run ./tools/genfixtures -out testdata/hosts

clean:
	rm -rf bin .demo coverage.out coverage.txt
