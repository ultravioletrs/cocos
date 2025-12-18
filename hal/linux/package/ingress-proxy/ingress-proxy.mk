################################################################################
#
# ingress-proxy
#
################################################################################

INGRESS_PROXY_VERSION = e39eb1866866c9088b0c60f75735a162ff13e046
INGRESS_PROXY_SITE = $(call github,sammyoina,cocos-ai,$(INGRESS_PROXY_VERSION))

define INGRESS_PROXY_BUILD_CMDS
	$(MAKE) -C $(@D) ingress-proxy
endef

define INGRESS_PROXY_INSTALL_TARGET_CMDS
	$(INSTALL) -D -m 0750 $(@D)/build/cocos-ingress-proxy $(TARGET_DIR)/usr/bin/ingress-proxy
endef

# NOTE: The standalone ingress-proxy service is deprecated in favor of per-computation
# ingress-proxy managed by the agent. The ingress-proxy binary is still installed for
# use by the agent, but the systemd service is no longer needed.
#
# define INGRESS_PROXY_INSTALL_INIT_SYSTEMD
# 	$(INSTALL) -D -m 0640 $(@D)/init/systemd/ingress-proxy.service $(TARGET_DIR)/usr/lib/systemd/system/ingress-proxy.service
# endef

$(eval $(generic-package))
