BUILD_DIR = build
SERVICES = manager agent cli
CGO_ENABLED ?= 0
GOARCH ?= amd64
VERSION ?= $(shell git describe --abbrev=0 --tags --always)
COMMIT ?= $(shell git rev-parse HEAD)
TIME ?= $(shell date +%F_%T)
CLI_SOURCE = ./cmd/cli/main.go
CLI_BIN = ${BUILD_DIR}/cocos-cli

USER_REPO ?= $(shell git remote get-url origin | sed -e 's/.*\/\([^/]*\)\/\([^/]*\).*/\1_\2/' )
empty:=
space:= $(empty) $(empty)
# Docker compose project name should follow this guidelines: https://docs.docker.com/compose/reference/#use--p-to-specify-a-project-name
DOCKER_PROJECT ?= $(shell echo $(subst $(space),,$(USER_REPO)) | tr -c -s '[:alnum:][=-=]' '_' | tr '[:upper:]' '[:lower:]')
DOCKER_PROFILE ?= $(COCOS_MESSAGE_BROKER_TYPE)
ifneq ($(COCOS_MESSAGE_BROKER_TYPE),)
    COCOS_MESSAGE_BROKER_TYPE := $(COCOS_MESSAGE_BROKER_TYPE)
else
    COCOS_MESSAGE_BROKER_TYPE=nats
endif

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

install-cli: cli
	cp ${CLI_BIN} ~/.local/bin/cocos-cli

protoc:
	protoc -I. --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative agent/agent.proto

define edit_docker_config
	sed -i "s/COCOS_MESSAGE_BROKER_TYPE=.*/COCOS_MESSAGE_BROKER_TYPE=$(1)/" docker/.env
	sed -i "s,file: .*.yml,file: $(1).yml," docker/brokers/docker-compose.yml
	sed -i "s,COCOS_MESSAGE_BROKER_URL=.*,COCOS_MESSAGE_BROKER_URL=$$\{COCOS_$(shell echo ${COCOS_MESSAGE_BROKER_TYPE} | tr 'a-z' 'A-Z')_URL\}," docker/.env
endef

change_config:
ifeq ($(DOCKER_PROFILE),nats)
	sed -i "s/- broker/- nats/g" docker/docker-compose.yml
	sed -i "s/- rabbitmq/- nats/g" docker/docker-compose.yml
	sed -i "s,COCOS_NATS_URL=.*,COCOS_NATS_URL=nats://nats:$$\{COCOS_NATS_PORT}," docker/.env
	$(call edit_docker_config,nats)
else ifeq ($(DOCKER_PROFILE),rabbitmq)
	sed -i "s/nats/broker/g" docker/docker-compose.yml
	sed -i "s,COCOS_NATS_URL=.*,COCOS_NATS_URL=nats://nats:$$\{COCOS_NATS_PORT}," docker/.env
	sed -i "s/rabbitmq/broker/g" docker/docker-compose.yml
	$(call edit_docker_config,rabbitmq)
else
	$(error Invalid DOCKER_PROFILE $(DOCKER_PROFILE))
endif

run:  change_config
	docker compose -f docker/docker-compose.yml --profile $(DOCKER_PROFILE) -p $(DOCKER_PROJECT) $(DOCKER_COMPOSE_COMMAND) up

