BUILD_DIR = build
SERVICES = manager agent cli
BACKEND_INFO = backend_info
CGO_ENABLED ?= 0
GOARCH ?= amd64
VERSION ?= $(shell git describe --abbrev=0 --tags --always)
COMMIT ?= $(shell git rev-parse HEAD)
TIME ?= $(shell date +%F_%T)
EMBED_ENABLED ?= 0

define compile_service
	CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS) GOARCH=$(GOARCH) GOARM=$(GOARM) \
	go build -ldflags "-s -w \
	-X 'github.com/absmach/magistrala.BuildTime=$(TIME)' \
	-X 'github.com/absmach/magistrala.Version=$(VERSION)' \
	-X 'github.com/absmach/magistrala.Commit=$(COMMIT)'" \
	$(if $(filter 1,$(EMBED_ENABLED)),-tags "embed",) \
	-o ${BUILD_DIR}/cocos-$(1) cmd/$(1)/main.go
endef

.PHONY: all $(SERVICES) $(BACKEND_INFO)

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
