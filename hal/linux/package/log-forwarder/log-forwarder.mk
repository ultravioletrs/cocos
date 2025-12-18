################################################################################
#
# log-forwarder
#
################################################################################

LOG_FORWARDER_VERSION = bb694c0cabd466f9dcef732cdd982f047b5812ed
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
