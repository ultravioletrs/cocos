################################################################################
#
# cc-attestation-agent
#
################################################################################

CC_ATTESTATION_AGENT_VERSION = v0.16.0
CC_ATTESTATION_AGENT_SITE = $(call github,confidential-containers,guest-components,$(CC_ATTESTATION_AGENT_VERSION))
CC_ATTESTATION_AGENT_LICENSE = Apache-2.0
CC_ATTESTATION_AGENT_LICENSE_FILES = LICENSE

CC_ATTESTATION_AGENT_DEPENDENCIES = host-rustc openssl protobuf

# Build the attestation-agent from the guest-components repository with gRPC support
define CC_ATTESTATION_AGENT_BUILD_CMDS
	cd $(@D)/attestation-agent && \
	$(TARGET_MAKE_ENV) \
	CARGO_HOME=$(@D)/.cargo \
	make ATTESTER=all-attesters ttrpc=false
endef

define CC_ATTESTATION_AGENT_INSTALL_TARGET_CMDS
	$(INSTALL) -D -m 0755 \
		$(@D)/target/$(RUSTC_TARGET_NAME)/release/attestation-agent \
		$(TARGET_DIR)/usr/bin/attestation-agent
endef

define CC_ATTESTATION_AGENT_INSTALL_INIT_SYSTEMD
	$(INSTALL) -D -m 0644 \
		$(BR2_EXTERNAL_COCOS_PATH)/package/cc-attestation-agent/cc-attestation-agent.service \
		$(TARGET_DIR)/usr/lib/systemd/system/attestation-agent.service
	$(INSTALL) -D -m 0750 \
		$(BR2_EXTERNAL_COCOS_PATH)/package/cc-attestation-agent/cc-attestation-agent-setup.sh \
		$(TARGET_DIR)/cocos_init/attestation_setup.sh
endef

$(eval $(generic-package))
