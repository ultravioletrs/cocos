################################################################################
#
# attestation-service
#
################################################################################

ATTESTATION_SERVICE_VERSION = c28cefae0a5b51024a1c08e50e460e21866edcf6
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
	# Enable CC attestation agent backend
	sed -i 's/USE_CC_ATTESTATION_AGENT=false/USE_CC_ATTESTATION_AGENT=true/' $(TARGET_DIR)/usr/lib/systemd/system/attestation-service.service
endef
else
define ATTESTATION_SERVICE_INSTALL_INIT_SYSTEMD
	$(INSTALL) -D -m 0640 $(@D)/init/systemd/attestation-service.service $(TARGET_DIR)/usr/lib/systemd/system/attestation-service.service
	$(INSTALL) -D -m 0750 $(@D)/init/systemd/attestation_setup.sh $(TARGET_DIR)/cocos_init/attestation_setup.sh
	# Disable CC attestation agent backend
	sed -i 's/USE_CC_ATTESTATION_AGENT=true/USE_CC_ATTESTATION_AGENT=false/' $(TARGET_DIR)/usr/lib/systemd/system/attestation-service.service
	sed -i '/Wants=attestation-agent.service/d' $(TARGET_DIR)/usr/lib/systemd/system/attestation-service.service
endef
endif

$(eval $(generic-package))
