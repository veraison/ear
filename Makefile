.DEFAULT_GOAL := test

export GO111MODULE := on
export SHELL := /bin/bash

GOPKG := github.com/veraison/ear
GOPKG += github.com/veraison/ear/arc/cmd

TOPDIR := $(realpath $(dir $(lastword $(MAKEFILE_LIST))))

GOLINT_ARGS ?= run --timeout=3m -E dupl -E gocritic -E prealloc

GOLINT_VERSION = v2.13.2
GOLINT = $(TOPDIR)/tools-bin/golangci-lint
GOLINT_STAMP = $(TOPDIR)/tools-bin/golangci-lint-$(GOLINT_VERSION).stamp

$(GOLINT): $(GOLINT_STAMP)

$(GOLINT_STAMP):
	mkdir -p $(dir $(GOLINT))
	touch $(GOLINT_STAMP)
	GOBIN=$(dir $(GOLINT)) go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLINT_VERSION)

.PHONY: lint
lint: $(GOLINT)
	$(GOLINT) $(GOLINT_ARGS)

.PHONY: test
test:
	go test $(GOTEST_ARGS) -v -race $(GOPKG)

COVER_THRESHOLD := $(shell sed -n "s/^ *min-coverage: '\(.*\)'/≥\1%/p" .github/workflows/ci-go-cover.yml)

.PHONY: test-cover cover
test-cover cover:
	go test $(GOTEST_ARGS) -short -cover $(GOPKG)

.PHONY: cover-report report
cover-report report coverage.html:
	go test -coverprofile=coverage.out $(GOPKG)
	go tool cover -html=coverage.out -o coverage.html

presubmit:
	@echo
	@echo ">>> Check that the reported coverage figures are $(COVER_THRESHOLD)"
	@echo
	$(MAKE) test-cover
	@echo
	@echo ">>> Fix any lint error"
	@echo
	$(MAKE) lint

.PHONY: licenses
licenses: ; @./scripts/licenses.sh

.PHONY: help
help:
	@echo "Available targets:"
	@echo "  * test:       run unit tests for $(GOPKG)"
	@echo "  * test-cover: run unit tests and measure coverage for $(GOPKG)"
	@echo "  * licenses:   check licenses of dependent packages"
	@echo "  * lint:       lint sources using .golangci.yml"
	@echo "  * presubmit:  check you are ready to push your local branch to remote"
	@echo "  * help:       print this menu"
