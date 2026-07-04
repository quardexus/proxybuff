# ══════════════════════════════════════════════════════════
#   QUARDEXUS · functional entity — ProxyBuff
# ══════════════════════════════════════════════════════════

BINARY  := proxybuff
PKG     := ./cmd/proxybuff
BIN_DIR := bin
GO      ?= go

.DEFAULT_GOAL := build

.PHONY: build
build: ## Build the binary into ./bin
	$(GO) build -trimpath -ldflags="-s -w" -o $(BIN_DIR)/$(BINARY) $(PKG)

.PHONY: run
run: ## Build and run (pass ARGS="--origin ...")
	$(GO) run $(PKG) $(ARGS)

.PHONY: test
test: ## Run tests
	$(GO) test ./...

.PHONY: test-race
test-race: ## Run tests with the race detector
	$(GO) test -race -count=1 ./...

.PHONY: cover
cover: ## Run tests with a coverage summary
	$(GO) test -cover ./...

.PHONY: vet
vet: ## Run go vet
	$(GO) vet ./...

.PHONY: fmt
fmt: ## Format the code in place
	gofmt -w .

.PHONY: fmt-check
fmt-check: ## Fail if any file is not gofmt-clean
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "not gofmt-clean:"; echo "$$out"; exit 1; fi

.PHONY: lint
lint: fmt-check vet ## gofmt check + go vet

.PHONY: tidy
tidy: ## Tidy go.mod / go.sum
	$(GO) mod tidy

.PHONY: docker
docker: ## Build the Docker image (override with TAG=name:tag)
	docker build -t $(or $(TAG),proxybuff:local) .

.PHONY: cross
cross: ## Cross-compile for linux/darwin/windows on amd64+arm64
	@set -e; for p in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64; do \
		os=$${p%/*}; arch=$${p#*/}; ext=""; [ "$$os" = "windows" ] && ext=".exe"; \
		echo "-> $$os/$$arch"; \
		GOOS=$$os GOARCH=$$arch $(GO) build -trimpath -ldflags="-s -w" \
			-o $(BIN_DIR)/$(BINARY)-$$os-$$arch$$ext $(PKG); \
	done

.PHONY: clean
clean: ## Remove build artifacts
	rm -rf $(BIN_DIR)

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'
