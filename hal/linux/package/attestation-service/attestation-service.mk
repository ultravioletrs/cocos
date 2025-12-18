################################################################################
#
# attestation-service
#
################################################################################

ATTESTATION_SERVICE_VERSION = bb694c0cabd466f9dcef732cdd982f047b5812ed
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
