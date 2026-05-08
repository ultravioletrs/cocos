BUILD_DIR = build
SERVICES = manager agent cli attestation-service log-forwarder computation-runner egress-proxy ingress-proxy
NVIDIA_ATTESTATION_HELPER = nvidia-attestation-helper
NVIDIA_ATTESTATION_HELPER_DIR = tools/$(NVIDIA_ATTESTATION_HELPER)
NVIDIA_ATTESTATION_HELPER_MANIFEST = $(NVIDIA_ATTESTATION_HELPER_DIR)/Cargo.toml
NVIDIA_ATTESTATION_HELPER_BINARY = $(BUILD_DIR)/$(NVIDIA_ATTESTATION_HELPER)
NVIDIA_ATTESTATION_HELPER_LIB_DIR = $(BUILD_DIR)/lib
NVAT_SDK_CPP_DIR ?= $(firstword $(wildcard $(HOME)/.cargo/git/checkouts/attestation-sdk-*/*/nv-attestation-sdk-cpp))
NVAT_SDK_CPP_BUILD_DIR ?= $(NVAT_SDK_CPP_DIR)/build
NVAT_SDK_HEADER ?= $(NVAT_SDK_CPP_BUILD_DIR)/include/nvat.h
NVAT_SDK_SHARED_LIB ?= $(NVAT_SDK_CPP_BUILD_DIR)/libnvat.so.1
NVAT_SYSTEM_HEADER ?= /usr/include/nvat.h
CARGO ?= cargo
CMAKE ?= cmake
CGO_ENABLED ?= 0
GOARCH ?= amd64
VERSION ?= $(shell git describe --abbrev=0 --tags --always)
COMMIT ?= $(shell git rev-parse HEAD)
TIME ?= $(shell date +%F_%T)
EMBED_ENABLED ?= 0
NVAT_USE_SYSTEM_LIB ?=
INSTALL_DIR ?= /usr/local/bin
CONFIG_DIR ?= /etc/cocos
SERVICE_NAME ?= cocos-manager
SERVICE_DIR ?= /etc/systemd/system
SERVICE_FILE = init/systemd/$(SERVICE_NAME).service
IGVM_BUILD_SCRIPT := ./scripts/igvmmeasure/igvm.sh

define compile_service
	CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS) GOARCH=$(GOARCH) GOARM=$(GOARM) \
	go build -ldflags "-s -w \
	-X 'github.com/absmach/supermq.BuildTime=$(TIME)' \
	-X 'github.com/absmach/supermq.Version=$(VERSION)' \
	-X 'github.com/absmach/supermq.Commit=$(COMMIT)'" \
	$(if $(filter 1,$(EMBED_ENABLED)),-tags "embed",) \
	-o ${BUILD_DIR}/cocos-$(1) ./cmd/$(1)
endef

NVIDIA_ATTESTATION_HELPER_CARGO_ENV = $(if $(filter 1,$(NVAT_USE_SYSTEM_LIB)),NVAT_USE_SYSTEM_LIB=1,)
NVIDIA_ATTESTATION_HELPER_RUSTFLAGS = $(strip $(RUSTFLAGS) $(if $(filter 1,$(NVAT_USE_SYSTEM_LIB)),,-C link-arg=-Wl,-rpath,$$ORIGIN/lib))

.PHONY: all $(SERVICES) $(NVIDIA_ATTESTATION_HELPER) nvidia-attestation-helper-prereqs install clean

all: $(SERVICES)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(SERVICES): | $(BUILD_DIR)
	$(call compile_service,$@)
	@if [ "$@" = "cli" ] || [ "$@" = "manager" ]; then $(MAKE) build-igvm; fi

nvidia-attestation-helper-prereqs:
ifeq ($(filter 1,$(NVAT_USE_SYSTEM_LIB)),1)
	@test -f $(NVAT_SYSTEM_HEADER) || \
		( echo "Missing $(NVAT_SYSTEM_HEADER). Install the NVAT development package or run without NVAT_USE_SYSTEM_LIB=1."; exit 1 )
	@ldconfig -p | grep -q libnvat.so.1 || \
		( echo "libnvat.so.1 not found in the dynamic linker cache. Install the NVAT runtime package or run without NVAT_USE_SYSTEM_LIB=1."; exit 1 )
else
	@if [ -z "$(NVAT_SDK_CPP_DIR)" ]; then \
		echo "Unable to locate nv-attestation-sdk-cpp under $$HOME/.cargo/git/checkouts."; \
		echo "Run 'cargo fetch --manifest-path $(NVIDIA_ATTESTATION_HELPER_MANIFEST)' first, or install NVAT and use 'make NVAT_USE_SYSTEM_LIB=1 $(NVIDIA_ATTESTATION_HELPER)'."; \
		exit 1; \
	fi
	@if [ ! -f "$(NVAT_SDK_HEADER)" ] || [ ! -f "$(NVAT_SDK_SHARED_LIB)" ]; then \
		$(CMAKE) -S $(NVAT_SDK_CPP_DIR) -B $(NVAT_SDK_CPP_BUILD_DIR) && \
		$(CMAKE) --build $(NVAT_SDK_CPP_BUILD_DIR); \
	fi
endif

$(NVIDIA_ATTESTATION_HELPER): nvidia-attestation-helper-prereqs | $(BUILD_DIR)
	RUSTFLAGS='$(NVIDIA_ATTESTATION_HELPER_RUSTFLAGS)' $(NVIDIA_ATTESTATION_HELPER_CARGO_ENV) $(CARGO) build --manifest-path $(NVIDIA_ATTESTATION_HELPER_MANIFEST) --release
	install -m 755 $(NVIDIA_ATTESTATION_HELPER_DIR)/target/release/$(NVIDIA_ATTESTATION_HELPER) $(NVIDIA_ATTESTATION_HELPER_BINARY)
	@if [ "$(filter 1,$(NVAT_USE_SYSTEM_LIB))" != "1" ]; then \
		install -d $(NVIDIA_ATTESTATION_HELPER_LIB_DIR); \
		install -m 755 $(NVAT_SDK_SHARED_LIB) $(NVIDIA_ATTESTATION_HELPER_LIB_DIR)/libnvat.so.1; \
	fi

protoc:
	protoc -I. --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative agent/agent.proto
	protoc -I. --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative manager/manager.proto
	protoc -I. --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative agent/events/events.proto
	protoc -I. --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative agent/cvms/cvms.proto
	protoc -I. --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative internal/proto/attestation/v1/attestation.proto
	protoc -I. --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative internal/proto/attestation-agent/attestation-agent.proto
	protoc -I. --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative agent/log/log.proto
	protoc -I. --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative agent/runner/runner.proto

mocks:
	mockery --config ./.mockery.yml

install: $(SERVICES)
	install -d $(INSTALL_DIR)
	install $(BUILD_DIR)/cocos-cli $(INSTALL_DIR)/cocos-cli
	install $(BUILD_DIR)/cocos-manager $(INSTALL_DIR)/cocos-manager
	install -d $(CONFIG_DIR)
	install cocos-manager.env $(CONFIG_DIR)/cocos-manager.env

clean:
	rm -rf $(BUILD_DIR)

run: install_service
	sudo systemctl start $(SERVICE_NAME).service

stop:
	sudo systemctl stop $(SERVICE_NAME).service

install_service:
	sudo install -m 644 $(SERVICE_FILE) $(SERVICE_DIR)/$(SERVICE_NAME).service
	sudo systemctl daemon-reload

build-igvm:
	@echo "Running build script for igvmmeasure..."
	@$(IGVM_BUILD_SCRIPT)
