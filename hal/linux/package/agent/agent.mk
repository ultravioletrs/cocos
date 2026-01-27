################################################################################
#
# Cocos AI Agent
#
################################################################################

AGENT_VERSION = 991610f870bb6f6738db823c7957481a933809c6
AGENT_SITE = $(call github,sammyoina,cocos-ai,$(AGENT_VERSION))

define AGENT_BUILD_CMDS
	$(MAKE) -C $(@D) agent EMBED_ENABLED=$(AGENT_EMBED_ENABLED)
endef

define AGENT_INSTALL_TARGET_CMDS
	mkdir -p $(TARGET_DIR)/cocos/
	mkdir -p $(TARGET_DIR)/var/log/cocos
	mkdir -p $(TARGET_DIR)/cocos_init/
	$(INSTALL) -D -m 0750 $(@D)/build/cocos-agent $(TARGET_DIR)/bin
endef

define AGENT_INSTALL_INIT_SYSTEMD
	$(INSTALL) -D -m 0640 $(@D)/init/systemd/cocos-agent.service $(TARGET_DIR)/usr/lib/systemd/system/cocos-agent.service
	$(INSTALL) -D -m 0750 $(@D)/init/systemd/agent_setup.sh $(TARGET_DIR)/cocos_init/agent_setup.sh
	$(INSTALL) -D -m 0750 $(@D)/init/systemd/agent_start_script.sh $(TARGET_DIR)/cocos_init/agent_start_script.sh
endef

$(eval $(generic-package))
