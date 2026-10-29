.DEFAULT_GOAL := test

export GO111MODULE := on
export SHELL := /bin/bash

# GOEXPERIMENT needs to be set for 1.26 but not later.
GO_VERSION := $(shell go env GOVERSION)
ifneq ($(filter go1.26.%,$(GO_VERSION)),)
export GOEXPERIMENT := jsonv2
endif

GOPKG := github.com/veraison/ear
GOPKG += github.com/veraison/ear/arc/cmd

include mk/lint.mk

TEST_ARGS ?= -v -race

.PHONY: all
all:
	go build ./...

.PHONY: test
test:
	go test $(GOTEST_ARGS) $(TEST_ARGS) $(GOPKG)

COVERAGE_THRESHOLD ?= 90.0

include mk/cover.mk

presubmit:
	@echo
	@echo ">>> Check that the coverage figures are above $(COVERAGE_THRESHOLD)%"
	@echo
	$(MAKE) coverage
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
	@echo "  * coverage:   run a check to make sure that unit test coverage is above a pre-determined threshold ($(COVERAGE_THRESHOLD)%)"
	@echo "  * licenses:   check licenses of dependent packages"
	@echo "  * lint:       lint sources using .golangci.yml"
	@echo "  * presubmit:  check you are ready to push your local branch to remote"
	@echo "  * help:       print this menu"
