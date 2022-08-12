UV_DOCKER_IMAGE_NAME_PREFIX ?= ultraviolet
BUILD_DIR = build
SVC = clients
CGO_ENABLED ?= 0
GOARCH ?= amd64

define compile_service
	CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS) GOARCH=$(GOARCH) GOARM=$(GOARM) \
	go build -mod=vendor -ldflags "-s -w " -o ${BUILD_DIR}/ultraviolet-clients cmd/main.go
endef

define make_docker
	docker build \
		--no-cache \
		--build-arg SVC=$(SVC) \
		--build-arg GOARCH=$(GOARCH) \
		--build-arg GOARM=$(GOARM) \
		--tag=$(UV_DOCKER_IMAGE_NAME_PREFIX)/$(SVC) \
		-f docker/Dockerfile .
endef

define make_docker_dev
	docker build \
		--no-cache \
		--build-arg SVC=$(SVC) \
		--tag=$(UV_DOCKER_IMAGE_NAME_PREFIX)/$(SVC) \
		-f docker/Dockerfile.dev ./build
endef

all: $(SVC)

.PHONY: $(SVC) docker docker_dev

clean:
	rm -rf ${BUILD_DIR}

cleandocker:
	# Stops containers and removes containers, networks, volumes, and images created by up
	docker-compose -f docker/docker-compose.yml down --rmi all -v --remove-orphans

test:
	go test -mod=vendor -v -race -count 1 -tags test $(shell go list ./... | grep -v 'vendor\|cmd')

proto:
	protoc --gofast_out=plugins=grpc:. *.proto

$(SVC):
	$(call compile_service)

docker:
	$(call make_docker)

docker_dev:
	$(call make_docker_dev)

run:
	docker-compose -f docker/docker-compose.yml up
