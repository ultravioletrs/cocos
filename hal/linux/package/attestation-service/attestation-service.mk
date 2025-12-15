################################################################################
#
# attestation-service
#
################################################################################

ATTESTATION_SERVICE_VERSION = local
ATTESTATION_SERVICE_SITE = $(TOPDIR)/../..
ATTESTATION_SERVICE_SITE_METHOD = local
ATTESTATION_SERVICE_GO_ENV = $(GO_GO_ENV)

define ATTESTATION_SERVICE_BUILD_CMDS
	cd $(@D); \
	$(ATTESTATION_SERVICE_GO_ENV) \
	$(GO_BIN) build -v -ldflags "-s -w" -o bin/attestation-service cmd/attestation-service/main.go
endef

define ATTESTATION_SERVICE_INSTALL_TARGET_CMDS
	$(INSTALL) -D -m 0755 $(@D)/bin/attestation-service $(TARGET_DIR)/usr/bin/attestation-service
endef

define ATTESTATION_SERVICE_INSTALL_INIT_SYSTEMD
	$(INSTALL) -D -m 0640 $(@D)/init/systemd/attestation-service.service $(TARGET_DIR)/usr/lib/systemd/system/attestation-service.service
	$(INSTALL) -D -m 0750 $(@D)/init/systemd/attestation_setup.sh $(TARGET_DIR)/cocos_init/attestation_setup.sh
endef

$(eval $(generic-package))
