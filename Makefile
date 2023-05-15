BUILD_DIR = build
SERVICES = agent
CGO_ENABLED ?= 0
GOARCH ?= amd64
VERSION ?= $(shell git describe --abbrev=0 --tags)
COMMIT ?= $(shell git rev-parse HEAD)
TIME ?= $(shell date +%F_%T)

define compile_service
	CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS) GOARCH=$(GOARCH) GOARM=$(GOARM) \
	go build -mod=vendor -ldflags "-s -w \
	-X 'github.com/ultravioletrs/cocos/internal/http.BuildTime=$(TIME)' \
	-X 'github.com/ultravioletrs/cocos/internal/http.Version=$(VERSION)' \
	-X 'github.com/ultravioletrs/cocos/internal/http.Commit=$(COMMIT)'" \
	-o ${BUILD_DIR}/cocos-$(1) cmd/$(1)/main.go
endef

all: $(SERVICES)

$(SERVICES):
	$(call compile_service,$(@))


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

# docker_mfxkit:
# 	docker build --no-cache --tag=mainflux/mfxkit -f docker/Dockerfile .

# run:
# 	docker-compose -f docker/docker-compose.yml up

protoc:
	protoc --go_out=. proto/*.proto
	protoc --go-grpc_out=. proto/*.proto