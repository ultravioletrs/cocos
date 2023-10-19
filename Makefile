BUILD_DIR = build
SERVICES = manager agent cli
CGO_ENABLED ?= 0
GOARCH ?= amd64
VERSION ?= $(shell git describe --abbrev=0 --tags --always)
COMMIT ?= $(shell git rev-parse HEAD)
TIME ?= $(shell date +%F_%T)
CLI_SOURCE = ./cmd/cli/main.go
CLI_BIN = ${BUILD_DIR}/cocos-cli


define compile_service
	CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS) GOARCH=$(GOARCH) GOARM=$(GOARM) \
	go build -mod=vendor -ldflags "-s -w \
	-X 'github.com/mainflux/mainflux.BuildTime=$(TIME)' \
	-X 'github.com/mainflux/mainflux.Version=$(VERSION)' \
	-X 'github.com/mainflux/mainflux.Commit=$(COMMIT)'" \
	-o ${BUILD_DIR}/cocos-$(1) cmd/$(1)/main.go
endef

.PHONY: all $(SERVICES)

all: $(SERVICES)

$(SERVICES):
	$(call compile_service,$(@))

install-cli: cli
	cp ${CLI_BIN} ~/.local/bin/cocos-cli

protoc:
	protoc -I. --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative agent/agent.proto
