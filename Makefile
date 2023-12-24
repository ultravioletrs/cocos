BUILD_DIR = build
SERVICES = manager agent cli
CGO_ENABLED ?= 0
GOARCH ?= amd64
VERSION ?= $(shell git describe --abbrev=0 --tags --always)
COMMIT ?= $(shell git rev-parse HEAD)
TIME ?= $(shell date +%F_%T)
CLI_SOURCE = ./cmd/cli/main.go
CLI_BIN = ${BUILD_DIR}/cocos-cli
DOCKERS = $(addprefix docker_,$(SERVICES))
DOCKERS_DEV = $(addprefix docker_dev_,$(SERVICES))
COCOS_DOCKER_IMAGE_NAME_PREFIX=ghcr.io/ultravioletrs/cocos/

USER_REPO ?= $(shell git remote get-url origin | sed -e 's/.*\/\([^/]*\)\/\([^/]*\).*/\1_\2/' )
empty:=
space:= $(empty) $(empty)

define compile_service
	CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS) GOARCH=$(GOARCH) GOARM=$(GOARM) \
	go build -tags nats -ldflags "-s -w \
	-X 'github.com/absmach/magistrala.BuildTime=$(TIME)' \
	-X 'github.com/absmach/magistrala.Version=$(VERSION)' \
	-X 'github.com/absmach/magistrala.Commit=$(COMMIT)'" \
	-o ${BUILD_DIR}/cocos-$(1) cmd/$(1)/main.go
endef

define make_docker
	$(eval svc=$(subst docker_,,$(1)))

	docker build \
		--no-cache \
		--build-arg SVC=$(svc) \
		--build-arg GOARCH=$(GOARCH) \
		--build-arg GOARM=$(GOARM) \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg TIME=$(TIME) \
		--tag=$(COCOS_DOCKER_IMAGE_NAME_PREFIX)$(svc) \
		-f docker/Dockerfile .
endef

define make_docker_dev
	$(eval svc=$(subst docker_dev_,,$(1)))

	docker build \
		--no-cache \
		--build-arg SVC=$(svc) \
		--tag=$(COCOS_DOCKER_IMAGE_NAME_PREFIX)$(svc) \
		-f docker/Dockerfile.dev ./build
endef

.PHONY: all $(SERVICES) dockers dockers_dev

all: $(SERVICES)

$(DOCKERS):
	$(call make_docker,$(@),$(GOARCH))

$(DOCKERS_DEV):
	$(call make_docker_dev,$(@))

dockers: $(DOCKERS)
dockers_dev: $(DOCKERS_DEV)

$(SERVICES):
	$(call compile_service,$(@))


install-cli: cli
	cp ${CLI_BIN} ~/.local/bin/cocos-cli

protoc:
	protoc -I. --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative agent/agent.proto
	protoc -I. --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative manager/manager.proto

run:
	docker compose -f docker/docker-compose.yml -p cocos up
