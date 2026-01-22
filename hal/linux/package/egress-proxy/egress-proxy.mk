################################################################################
#
# Cocos AI Egress Proxy
#
################################################################################

EGRESS_PROXY_VERSION = f6981ac59edfe1abb9885089a0e0b00d7c87a422
EGRESS_PROXY_SITE = $(call github,sammyoina,cocos-ai,$(EGRESS_PROXY_VERSION))

define EGRESS_PROXY_BUILD_CMDS
	$(MAKE) -C $(@D) egress-proxy
endef

define EGRESS_PROXY_INSTALL_TARGET_CMDS
	$(INSTALL) -D -m 0755 $(@D)/build/cocos-egress-proxy $(TARGET_DIR)/usr/bin/egress-proxy
endef

define EGRESS_PROXY_INSTALL_INIT_SYSTEMD
	$(INSTALL) -D -m 0644 $(@D)/init/systemd/egress-proxy.service $(TARGET_DIR)/usr/lib/systemd/system/egress-proxy.service
endef

$(eval $(generic-package))
