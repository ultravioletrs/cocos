################################################################################
#
# Cocos AI Agent
#
################################################################################

AGENT_VERSION = 1685c388349b276c2c0881f6844bb1d82a6e4e2d
AGENT_SITE = $(call github,sammyoina,cocos-ai,$(AGENT_VERSION))

define AGENT_BUILD_CMDS 	
	$(MAKE) -C $(@D) agent
endef

define AGENT_INSTALL_TARGET_CMDS
	$(INSTALL) -D -m 0750 $(@D)/build/cocos-agent $(TARGET_DIR)/bin
	mkdir -p $(TARGET_DIR)/var/log/cocos
	mkdir -p $(TARGET_DIR)/cocos/
endef

define AGENT_INSTALL_INIT_SYSTEMD
	$(INSTALL) -D -m 0640 $(@D)/init/systemd/cocos-agent.service $(TARGET_DIR)/usr/lib/systemd/system/cocos-agent.service
	$(INSTALL) -D -m 0750 $(@D)/init/systemd/cocos_network_setup.sh $(TARGET_DIR)/cocos/cocos_network_setup.sh
	$(INSTALL) -D -m 0750 $(@D)/init/systemd/agent_start_script.sh $(TARGET_DIR)/cocos/agent_start_script.sh
endef

$(eval $(golang-package))
