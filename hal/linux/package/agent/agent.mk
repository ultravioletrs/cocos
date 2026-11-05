################################################################################
#
# Cocos AI Agent
#
################################################################################

AGENT_VERSION = main
# Build the image from the checked-out Cocos AI tree.  Using the GitHub
# snapshot here can silently select an older ingress-proxy implementation.
AGENT_SITE = $(BR2_EXTERNAL_COCOS_PATH)/../../../cocos-ai
AGENT_SITE_METHOD = local

define AGENT_BUILD_CMDS
	$(MAKE) -C $(@D) agent EMBED_ENABLED=$(AGENT_EMBED_ENABLED)
endef

define AGENT_INSTALL_TARGET_CMDS
	mkdir -p $(TARGET_DIR)/cocos/
	mkdir -p $(TARGET_DIR)/var/log/cocos
	mkdir -p $(TARGET_DIR)/cocos_init/
	$(INSTALL) -D -m 0750 $(@D)/build/cocos-agent $(TARGET_DIR)/usr/bin/cocos-agent
endef

define AGENT_INSTALL_INIT_SYSTEMD
    $(INSTALL) -D -m 0640 $(@D)/init/systemd/cocos-agent.service $(TARGET_DIR)/usr/lib/systemd/system/cocos-agent.service
    sed -i -e '/^Before=docker.service$$/d' $(TARGET_DIR)/usr/lib/systemd/system/cocos-agent.service
	$(INSTALL) -D -m 0750 $(@D)/init/systemd/agent_setup.sh $(TARGET_DIR)/cocos_init/agent_setup.sh
	$(INSTALL) -D -m 0750 $(@D)/init/systemd/agent_start_script.sh $(TARGET_DIR)/cocos_init/agent_start_script.sh
    mkdir -p $(TARGET_DIR)/usr/lib/systemd/system/multi-user.target.wants
    rm -f $(TARGET_DIR)/etc/systemd/system/basic.target.wants/cocos-agent.service \
        $(TARGET_DIR)/usr/lib/systemd/system/basic.target.wants/cocos-agent.service
    mkdir -p $(TARGET_DIR)/etc/systemd/system/multi-user.target.wants
    ln -sf /usr/lib/systemd/system/cocos-agent.service $(TARGET_DIR)/etc/systemd/system/multi-user.target.wants/cocos-agent.service
	ln -sf ../docker.service $(TARGET_DIR)/usr/lib/systemd/system/multi-user.target.wants/docker.service
	ln -sf ../log-forwarder.service $(TARGET_DIR)/usr/lib/systemd/system/multi-user.target.wants/log-forwarder.service
	ln -sf ../computation-runner.service $(TARGET_DIR)/usr/lib/systemd/system/multi-user.target.wants/computation-runner.service
	ln -sf ../egress-proxy.service $(TARGET_DIR)/usr/lib/systemd/system/multi-user.target.wants/egress-proxy.service
	ln -sf ../cocos-agent.service $(TARGET_DIR)/usr/lib/systemd/system/multi-user.target.wants/cocos-agent.service
endef

$(eval $(generic-package))
