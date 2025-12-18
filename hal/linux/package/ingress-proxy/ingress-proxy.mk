################################################################################
#
# ingress-proxy
#
################################################################################

INGRESS_PROXY_VERSION = bb694c0cabd466f9dcef732cdd982f047b5812ed
INGRESS_PROXY_SITE = $(call github,sammyoina,cocos-ai,$(INGRESS_PROXY_VERSION))

define INGRESS_PROXY_BUILD_CMDS
	$(MAKE) -C $(@D) ingress-proxy
endef

define INGRESS_PROXY_INSTALL_TARGET_CMDS
	$(INSTALL) -D -m 0750 $(@D)/build/cocos-ingress-proxy $(TARGET_DIR)/usr/bin/ingress-proxy
endef

# NOTE: The ingress-proxy is managed per-computation by the agent, not as a standalone
# systemd service. The binary is installed for use by the agent, but no systemd service
# is created.

$(eval $(generic-package))
