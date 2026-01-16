BUILD_DIR = build
SERVICES = manager agent cli attestation-service log-forwarder computation-runner egress-proxy ingress-proxy
ATTESTATION_POLICY = attestation_policy
CGO_ENABLED ?= 0
GOARCH ?= amd64
VERSION ?= $(shell git describe --abbrev=0 --tags --always)
COMMIT ?= $(shell git rev-parse HEAD)
TIME ?= $(shell date +%F_%T)
EMBED_ENABLED ?= 0
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
	-o ${BUILD_DIR}/cocos-$(1) cmd/$(1)/main.go
endef

.PHONY: all $(SERVICES) $(ATTESTATION_POLICY) install clean

all: $(SERVICES) $(ATTESTATION_POLICY)

$(SERVICES): 
	$(call compile_service,$@)
	@if [ "$@" = "cli" ] || [ "$@" = "manager" ]; then $(MAKE) build-igvm; fi

$(ATTESTATION_POLICY):
	$(MAKE) -C ./scripts/attestation_policy OUTPUT_DIR=../../$(BUILD_DIR)

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

install: $(SERVICES) $(ATTESTATION_POLICY)
	install -d $(INSTALL_DIR)
	install $(BUILD_DIR)/cocos-cli $(INSTALL_DIR)/cocos-cli
	install $(BUILD_DIR)/cocos-manager $(INSTALL_DIR)/cocos-manager
	install $(BUILD_DIR)/attestation_policy $(INSTALL_DIR)/attestation_policy
	install -d $(CONFIG_DIR)
	install cocos-manager.env $(CONFIG_DIR)/cocos-manager.env

clean:
	rm -rf $(BUILD_DIR)
	$(MAKE) -C ./scripts/attestation_policy OUTPUT_DIR=../../$(BUILD_DIR) clean

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
