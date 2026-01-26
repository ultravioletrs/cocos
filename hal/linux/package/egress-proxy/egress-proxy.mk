################################################################################
#
# Cocos AI Egress Proxy
#
################################################################################

EGRESS_PROXY_VERSION = cd33aa3a30fac611419fc7646f0c4aa59baf4f3f
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
