BUILD_DIR = build
SERVICES = manager agent cli
BACKEND_INFO = backend_info
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

define compile_service
	CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS) GOARCH=$(GOARCH) GOARM=$(GOARM) \
	go build -ldflags "-s -w \
	-X 'github.com/absmach/magistrala.BuildTime=$(TIME)' \
	-X 'github.com/absmach/magistrala.Version=$(VERSION)' \
	-X 'github.com/absmach/magistrala.Commit=$(COMMIT)'" \
	$(if $(filter 1,$(EMBED_ENABLED)),-tags "embed",) \
	-o ${BUILD_DIR}/cocos-$(1) cmd/$(1)/main.go
endef

.PHONY: all $(SERVICES) $(BACKEND_INFO) install clean test_coverage

all: $(SERVICES)

$(SERVICES):
	$(call compile_service,$@)

$(BACKEND_INFO):
	$(MAKE) -C ./scripts/backend_info

protoc:
	protoc -I. --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative agent/agent.proto
	protoc -I. --go_out=./pkg --go_opt=paths=source_relative --go-grpc_out=./pkg --go-grpc_opt=paths=source_relative manager/manager.proto

mocks:
	go generate ./...

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

test_coverage:
	go test ./... -coverprofile coverage.out
	$(eval COVERAGE := $(shell go tool cover -func=coverage.out | grep total: | grep -Eo '[0-9]+\.[0-9]+'))
	@echo "Coverage: $(COVERAGE)%"
	$(eval COLOR := $(shell if [ $$(echo "$(COVERAGE) <= 50" | bc -l) -eq 1 ]; then echo "red"; elif [ $$(echo "$(COVERAGE) > 80" | bc -l) -eq 1 ]; then echo "green"; else echo "orange"; fi))
	curl -s "https://img.shields.io/badge/coverage-$(COVERAGE)%25-$(COLOR)" > badge.svg
	rm coverage.out
