BINARY_DIR     := build
PROTO_DIR      := proto/v1
PROTO_OUT      := pkg/proto/v1
MODULE         := github.com/prateekpurohit13/frien

.PHONY: all build test test-race test-integration test-adversarial coverage lint vet proto-gen clean fmt

all: build

# ─── Build ────────────────────────────────────────────────────────────────────

build: vet
	go build -o $(BINARY_DIR)/friend      ./cmd/friend/...
	go build -o $(BINARY_DIR)/frienctl    ./cmd/frienctl/...
	go build -o $(BINARY_DIR)/frien-enforcer ./cmd/frien-enforcer/...

# ─── Test ─────────────────────────────────────────────────────────────────────

test:
	go test ./...

test-race:
	go test -race ./...

test-integration:
	go test -tags=integration ./tests/integration/...

test-adversarial:
	go test -tags=adversarial ./tests/adversarial/...

test-simulation:
	go test -tags=simulation ./tests/simulation/...

coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# ─── Code Quality ─────────────────────────────────────────────────────────────

fmt:
	gofmt -w .

vet:
	go vet ./...

lint:
	golangci-lint run ./...

# ─── Proto ────────────────────────────────────────────────────────────────────

proto-gen:
	protoc \
	  --proto_path=$(PROTO_DIR) \
	  --go_out=$(PROTO_OUT) \
	  --go_opt=paths=source_relative \
	  --go-grpc_out=$(PROTO_OUT) \
	  --go-grpc_opt=paths=source_relative \
	  $(PROTO_DIR)/frien.proto

# ─── Vulnerability scan ───────────────────────────────────────────────────────

vuln:
	govulncheck ./...

# ─── Clean ────────────────────────────────────────────────────────────────────

clean:
	rm -rf $(BINARY_DIR) coverage.out coverage.html

# ─── Smoke test (post-deploy) ─────────────────────────────────────────────────

test-smoke:
	@echo "Smoke tests: not yet implemented"
