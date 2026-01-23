################################################################################
#
# log-forwarder
#
################################################################################

LOG_FORWARDER_VERSION = 4bb8e587315cebd5cc8efdb9335a8ef4f6a0c04f
LOG_FORWARDER_SITE = $(call github,sammyoina,cocos-ai,$(LOG_FORWARDER_VERSION))

define LOG_FORWARDER_BUILD_CMDS
	$(MAKE) -C $(@D) log-forwarder
endef

define LOG_FORWARDER_INSTALL_TARGET_CMDS
	$(INSTALL) -D -m 0750 $(@D)/build/cocos-log-forwarder $(TARGET_DIR)/usr/bin/log-forwarder
endef

define LOG_FORWARDER_INSTALL_INIT_SYSTEMD
	$(INSTALL) -D -m 0640 $(@D)/init/systemd/log-forwarder.service $(TARGET_DIR)/usr/lib/systemd/system/log-forwarder.service
endef

$(eval $(generic-package))
