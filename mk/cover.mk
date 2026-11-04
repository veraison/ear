# Copyright 2023-2026 Contributors to the Veraison project.
# SPDX-License-Identifier: Apache-2.0

ROOT_REPO_DIR :=  $(realpath $(dir $(lastword $(MAKEFILE_LIST)))/..)
GO_TEST_COVERAGE_VERSION = v2.21.0
GO_TEST_COVERAGE = $(ROOT_REPO_DIR)/tools-bin/$(GO_TEST_COVERAGE_VERSION)/go-test-coverage

$(GO_TEST_COVERAGE):
	GOBIN=$(@D) go install github.com/vladopajic/go-test-coverage/v2@$(GOLINT_VERSION)

.PHONY: coverage cover test-cover
coverage cover test-cover: $(GO_TEST_COVERAGE)
	@go test $(ROOT_REPO_DIR)/./... -coverprofile=$(ROOT_REPO_DIR)/cover.out -covermode=atomic -coverpkg=./... > /dev/null
	@$(GO_TEST_COVERAGE) --config=$(ROOT_REPO_DIR)/.testcoverage.yml | sed "/Files with uncovered lines/Q"
