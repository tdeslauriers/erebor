BUILD_BIN := build/bin
BUF_BIN := $(BUILD_BIN)/buf
PROTOC_GEN_GO_BIN := $(BUILD_BIN)/protoc-gen-go
PROTOC_GEN_GO_GRPC_BIN := $(BUILD_BIN)/protoc-gen-go-grpc
PROTOC_GEN_GRPC_GATEWAY_BIN := $(BUILD_BIN)/protoc-gen-grpc-gateway
GOLANGCI_LINT_BIN := $(BUILD_BIN)/golangci-lint

.PHONY: build
build: generate-proto

.PHONY: protos
generate-proto: .tools-install
	$(BUF_BIN) generate --template buf.gen.api.yaml

.PHONY: .tools-install
.tools-install:
	@echo "Installing required tools to build/bin..."
	@if [ ! -d $(BUILD_BIN) ]; then \
		mkdir -p $(BUILD_BIN); \
	fi
	@if [ ! -f $(BUF_BIN) ]; then \
		echo "Installing buf..."; \
		GOBIN=$(shell pwd)/$(BUILD_BIN) go install github.com/bufbuild/buf/cmd/buf@latest; \
	fi
	@if [ ! -f $(PROTOC_GEN_GO_BIN) ]; then \
		echo "Installing protoc-gen-go..."; \
		GOBIN=$(shell pwd)/$(BUILD_BIN) go install google.golang.org/protobuf/cmd/protoc-gen-go@latest; \
	fi
	@if [ ! -f $(PROTOC_GEN_GO_GRPC_BIN) ]; then \
		echo "Installing protoc-gen-go-grpc..."; \
		GOBIN=$(shell pwd)/$(BUILD_BIN) go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest; \
	fi
	@if [ ! -f $(GOLANGCI_LINT_BIN) ]; then \
		echo "Installing golangci-lint..."; \
		GOBIN=$(shell pwd)/$(BUILD_BIN) go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest; \
	fi

.PHONY: fmt
fmt: lint fmt-go

.PHONY: lint-go
lint-go: .tools-install
	$(GOLANGCI_LINT_BIN) run

.PHONY: fmt-go
fmt-go: .tools-install
	$(GOLANGCI_LINT_BIN) run --fix

.PHONY: clean-build
clean-build:
	rm -rf build/

.PHONY: clean-proto
clean-proto:
	rm -f api/v1/*.pb.go
	rm -f api/v1/*.pb.gw.go


