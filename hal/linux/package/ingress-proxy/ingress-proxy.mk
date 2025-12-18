################################################################################
#
# ingress-proxy
#
################################################################################

INGRESS_PROXY_VERSION = 9992f033cb436feeaede9126726c5f78f39fdd18
INGRESS_PROXY_SITE = $(call github,sammyoina,cocos-ai,$(INGRESS_PROXY_VERSION))

define INGRESS_PROXY_BUILD_CMDS
	$(MAKE) -C $(@D) ingress-proxy
endef

define INGRESS_PROXY_INSTALL_TARGET_CMDS
	$(INSTALL) -D -m 0750 $(@D)/build/cocos-ingress-proxy $(TARGET_DIR)/usr/bin/ingress-proxy
endef

define INGRESS_PROXY_INSTALL_INIT_SYSTEMD
	$(INSTALL) -D -m 0640 $(@D)/init/systemd/ingress-proxy.service $(TARGET_DIR)/usr/lib/systemd/system/ingress-proxy.service
endef

$(eval $(generic-package))
