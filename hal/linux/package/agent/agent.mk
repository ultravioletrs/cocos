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
	cp $(@D)/build/cocos-agent $(TARGET_DIR)/bin
endef

$(eval $(golang-package))