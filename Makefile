BUILD_DIR = build
INSTALL_DIR = /usr/bin
SERVICES = manager agent cli
BINARIES = $(addprefix cocos-,$(SERVICES))
CGO_ENABLED ?= 0
GOARCH ?= amd64
VERSION ?= $(shell git describe --abbrev=0 --tags --always)
COMMIT ?= $(shell git rev-parse HEAD)
TIME ?= $(shell date +%F_%T)
empty:=
space:= $(empty) $(empty)

define compile_service
	CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS) GOARCH=$(GOARCH) GOARM=$(GOARM) \
	go build -ldflags "-s -w \
	-X 'github.com/absmach/magistrala.BuildTime=$(TIME)' \
	-X 'github.com/absmach/magistrala.Version=$(VERSION)' \
	-X 'github.com/absmach/magistrala.Commit=$(COMMIT)'" \
	-o ${BUILD_DIR}/cocos-$(1) cmd/$(1)/main.go
endef

.PHONY: all $(SERVICES)

all: $(SERVICES)

$(SERVICES):
	$(call compile_service,$(@))


install: $(BINARIES)

$(BINARIES):
	if [ "$@" != "cocos-cli" ]; then \
        cp "${BUILD_DIR}/$(@)" "${INSTALL_DIR}/$(@)"; \
    fi

protoc:
	protoc -I. --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative agent/agent.proto
	protoc -I. --go_out=./pkg --go_opt=paths=source_relative --go-grpc_out=./pkg --go-grpc_opt=paths=source_relative manager/manager.proto
