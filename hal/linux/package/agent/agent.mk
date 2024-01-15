################################################################################
#
# Cocos AI Agent
#
################################################################################

AGENT_VERSION = main
AGENT_SITE = $(call github,ultravioletrs,cocos,$(AGENT_VERSION))

define AGENT_BUILD_CMDS 	
	$(MAKE) -C $(@D) agent
endef

define AGENT_INSTALL_TARGET_CMDS
	$(INSTALL) -D -m 0755 $(@D)/build/cocos-agent $(TARGET_DIR)/bin
	mkdir -p $(TARGET_DIR)/var/log/cocos
endef

define AGENT_INSTALL_INIT_SYSTEMD
	$(INSTALL) -D -m 0644 $(@D)/init/systemd/cocos-agent.service $(TARGET_DIR)/usr/lib/systemd/system/cocos-agent.service
	$(INSTALL) -D -m 0755 $(@D)/init/systemd/agent_start_script.sh $(TARGET_DIR)/bin/agent_start_script.sh
	$(INSTALL) -D -m 0644 $(@D)/init/systemd/00-network.link $(TARGET_DIR)/etc/systemd/network
endef

$(eval $(golang-package))
