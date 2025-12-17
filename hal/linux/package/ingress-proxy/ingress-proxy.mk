################################################################################
#
# ingress-proxy
#
################################################################################

INGRESS_PROXY_VERSION = local
INGRESS_PROXY_SITE = $(BR2_EXTERNAL_COCOS_PATH)/../
INGRESS_PROXY_SITE_METHOD = local
INGRESS_PROXY_GO_BUILD_TARGET = ./cmd/ingress-proxy

define INGRESS_PROXY_INSTALL_INIT_SYSTEMD
	$(INSTALL) -D -m 0644 $(INGRESS_PROXY_PKGDIR)/../../../../init/systemd/ingress-proxy.service \
		$(TARGET_DIR)/usr/lib/systemd/system/ingress-proxy.service
endef

$(eval $(golang-package))
