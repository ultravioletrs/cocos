################################################################################
#
# attestation-service
#
################################################################################

ATTESTATION_SERVICE_VERSION = e39eb1866866c9088b0c60f75735a162ff13e046
ATTESTATION_SERVICE_SITE = $(call github,sammyoina,cocos-ai,$(ATTESTATION_SERVICE_VERSION))

define ATTESTATION_SERVICE_BUILD_CMDS
	$(MAKE) -C $(@D) attestation-service
endef

define ATTESTATION_SERVICE_INSTALL_TARGET_CMDS
	$(INSTALL) -D -m 0755 $(@D)/build/cocos-attestation-service $(TARGET_DIR)/usr/bin/attestation-service
endef

define ATTESTATION_SERVICE_INSTALL_INIT_SYSTEMD
	$(INSTALL) -D -m 0640 $(@D)/init/systemd/attestation-service.service $(TARGET_DIR)/usr/lib/systemd/system/attestation-service.service
	$(INSTALL) -D -m 0750 $(@D)/init/systemd/attestation_setup.sh $(TARGET_DIR)/cocos_init/attestation_setup.sh
endef

$(eval $(generic-package))
