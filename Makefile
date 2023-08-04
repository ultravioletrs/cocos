BUILD_DIR = build
SERVICES = agent
CGO_ENABLED ?= 0
GOARCH ?= amd64
VERSION ?= $(shell git describe --abbrev=0 --tags)
COMMIT ?= $(shell git rev-parse HEAD)
TIME ?= $(shell date +%F_%T)
CLI_SOURCE = ./cmd/cli/main.go
AGENT_CLI_PATH = ${BUILD_DIR}/agent-cli

define compile_service
	CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS) GOARCH=$(GOARCH) GOARM=$(GOARM) \
	go build -mod=vendor -ldflags "-s -w \
	-X 'github.com/mainflux/mainflux.BuildTime=$(TIME)' \
	-X 'github.com/mainflux/mainflux.Version=$(VERSION)' \
	-X 'github.com/mainflux/mainflux.Commit=$(COMMIT)'" \
	-o ${BUILD_DIR}/cocos-$(1) cmd/$(1)/main.go
endef

.PHONY: all $(SERVICES)

$(SERVICES):
	$(call compile_service,$(@))

agent-cli: $(CLI_SOURCE)
	CGO_ENABLED=$(CGO_ENABLED) GOARCH=$(GOARCH) \
	go build -mod=vendor -ldflags "-s -w \
	-X 'github.com/ultravioletrs/cocos/internal/http.BuildTime=$(TIME)' \
	-X 'github.com/ultravioletrs/cocos/internal/http.Version=$(VERSION)' \
	-X 'github.com/ultravioletrs/cocos/internal/http.Commit=$(COMMIT)'" \
	-o ${AGENT_CLI_PATH} $(CLI_SOURCE)

install: agent-cli
	cp ${AGENT_CLI_PATH} ~/.local/bin

QCOW2_PATH = ~/go/src/github.com/ultravioletrs/manager/cmd/manager/img/boot.img

HOST_AGENT_PATH = ~/ultravioletrs/agent/build/cocos-agent
GUEST_AGENT_PATH = /root/agent

HOST_AGENT_SH_PATH = ~/go/src/github.com/ultravioletrs/agent/alpine/agent.sh
GUEST_AGENT_SH_PATH = /root/agent/

HOST_AGENT_RC_SH_PATH = ~/go/src/github.com/ultravioletrs/agent/alpine/agent
GUEST_AGENT_RC_SH_PATH=/etc/init.d/

# Copy the agent binary to the guest VM
copy-agent:
	sudo virt-copy-in -a $(QCOW2_PATH) $(HOST_AGENT_PATH) $(GUEST_AGENT_PATH)

# Copy the agent init sh script to the guest VM
copy-agent-sh:
	sudo virt-copy-in -a $(QCOW2_PATH) $(HOST_AGENT_SH_PATH) $(GUEST_AGENT_SH_PATH)

# Copy the agent-rc init sh script to the guest VM
copy-agent-rc-sh:
	chmod +x $(HOST_AGENT_RC_SH_PATH)
	sudo virt-copy-in -a $(QCOW2_PATH) $(HOST_AGENT_RC_SH_PATH) $(GUEST_AGENT_RC_SH_PATH)

protoc:
	protoc -I. --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative agent/agent.proto


