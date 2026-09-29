# Makefile for the MCP Policy Gateway.
#
# Unit tests live next to the code they exercise (standard Go convention, and
# several of ours are white-box tests of unexported functions). This file is just
# a single, convenient place to build, test, and run everything.
#
# Run `make` or `make help` to list targets.

GO        ?= go
PKG       := ./...
GATEWAY   := ./cmd/gateway
MINT      := ./cmd/mint-token
POLICYCTL := ./cmd/policyctl
COVERFILE := coverage.out

# Overridable defaults, e.g. `make run ADDR=127.0.0.1:9090` or
# `make explain GROUPS=hr TOOL=payroll.get_employee`.
ADDR    ?= 127.0.0.1:8080
POLICY  ?= config/policies.yaml
SUBJECT ?= alice
GROUPS  ?= engineering
TOOL    ?= github.create_issue

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## Compile all packages and commands
	$(GO) build $(PKG)

.PHONY: test
test: ## Run all unit + integration tests
	$(GO) test $(PKG)

.PHONY: test-race
test-race: ## Run all tests with the race detector
	$(GO) test -race -count=1 $(PKG)

.PHONY: cover
cover: ## Run tests with coverage and print a per-function summary
	$(GO) test -coverprofile=$(COVERFILE) $(PKG)
	$(GO) tool cover -func=$(COVERFILE) | tail -n 25

.PHONY: cover-html
cover-html: cover ## Open the HTML coverage report in a browser
	$(GO) tool cover -html=$(COVERFILE)

.PHONY: vet
vet: ## Run go vet
	$(GO) vet $(PKG)

.PHONY: fmt
fmt: ## Format all Go files
	gofmt -w .

.PHONY: fmt-check
fmt-check: ## Fail if any file is not gofmt-clean
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "not gofmt-clean:"; echo "$$out"; exit 1; fi

.PHONY: lint
lint: fmt-check vet ## Static checks (gofmt + go vet)

.PHONY: check
check: lint test-race ## Full gate: static checks + race tests

.PHONY: tidy
tidy: ## Tidy go.mod / go.sum
	$(GO) mod tidy

.PHONY: genkey
genkey: ## Generate the demo ES256 key pair (testdata/keys, git-ignored)
	$(GO) run $(MINT) genkey

.PHONY: run
run: ## Run the gateway (make run ADDR=127.0.0.1:8080)
	$(GO) run $(GATEWAY) -addr $(ADDR) -policy $(POLICY)

.PHONY: token
token: ## Mint a demo token (make token SUBJECT=alice GROUPS=engineering)
	@$(GO) run $(MINT) mint -sub $(SUBJECT) -groups $(GROUPS)

.PHONY: explain
explain: ## Explain a decision (make explain GROUPS=hr TOOL=payroll.get_employee)
	$(GO) run $(POLICYCTL) explain -groups $(GROUPS) -tool $(TOOL) -policy $(POLICY)

.PHONY: policy-lint
policy-lint: ## Lint the policy rulebase for shadowed/redundant rules
	$(GO) run $(POLICYCTL) lint -policy $(POLICY)

.PHONY: clean
clean: ## Remove build and coverage artifacts
	rm -f $(COVERFILE)
	$(GO) clean
