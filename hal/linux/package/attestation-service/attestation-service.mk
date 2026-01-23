################################################################################
#
# attestation-service
#
################################################################################

ATTESTATION_SERVICE_VERSION = aa82cfceaa7068aa9f20f6a98a3ae05262477245
ATTESTATION_SERVICE_SITE = $(call github,sammyoina,cocos-ai,$(ATTESTATION_SERVICE_VERSION))

define ATTESTATION_SERVICE_BUILD_CMDS
	$(MAKE) -C $(@D) attestation-service
endef

define ATTESTATION_SERVICE_INSTALL_TARGET_CMDS
	$(INSTALL) -D -m 0755 $(@D)/build/cocos-attestation-service $(TARGET_DIR)/usr/bin/attestation-service
endef

ifeq ($(BR2_PACKAGE_CC_ATTESTATION_AGENT),y)
define ATTESTATION_SERVICE_INSTALL_INIT_SYSTEMD
	$(INSTALL) -D -m 0640 $(@D)/init/systemd/attestation-service.service $(TARGET_DIR)/usr/lib/systemd/system/attestation-service.service
	$(INSTALL) -D -m 0750 $(@D)/init/systemd/attestation_setup.sh $(TARGET_DIR)/cocos_init/attestation_setup.sh
	# CC attestation agent is already enabled by default
endef
else
define ATTESTATION_SERVICE_INSTALL_INIT_SYSTEMD
	$(INSTALL) -D -m 0640 $(@D)/init/systemd/attestation-service.service $(TARGET_DIR)/usr/lib/systemd/system/attestation-service.service
	$(INSTALL) -D -m 0750 $(@D)/init/systemd/attestation_setup.sh $(TARGET_DIR)/cocos_init/attestation_setup.sh
	# Disable CC attestation agent backend if not selected
	sed -i 's/USE_CC_ATTESTATION_AGENT=true/USE_CC_ATTESTATION_AGENT=false/' $(TARGET_DIR)/usr/lib/systemd/system/attestation-service.service
	sed -i '/Wants=attestation-agent.service/d' $(TARGET_DIR)/usr/lib/systemd/system/attestation-service.service
endef
endif

$(eval $(generic-package))
