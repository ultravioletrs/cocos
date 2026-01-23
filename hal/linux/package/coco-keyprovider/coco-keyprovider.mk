################################################################################
#
# coco-keyprovider
#
################################################################################

COCO_KEYPROVIDER_VERSION = v0.11.0
COCO_KEYPROVIDER_SITE = $(call github,confidential-containers,guest-components,$(COCO_KEYPROVIDER_VERSION))
COCO_KEYPROVIDER_LICENSE = Apache-2.0
COCO_KEYPROVIDER_LICENSE_FILES = LICENSE

COCO_KEYPROVIDER_DEPENDENCIES = host-rustc

define COCO_KEYPROVIDER_BUILD_CMDS
	cd $(@D)/attestation-agent/coco_keyprovider && \
	$(TARGET_MAKE_ENV) $(TARGET_CONFIGURE_OPTS) \
	CARGO_HOME=$(HOST_DIR)/share/cargo \
	cargo build --release --target=$(RUSTC_TARGET_NAME)
endef

define COCO_KEYPROVIDER_INSTALL_TARGET_CMDS
	$(INSTALL) -D -m 0755 $(@D)/attestation-agent/coco_keyprovider/target/$(RUSTC_TARGET_NAME)/release/coco_keyprovider \
		$(TARGET_DIR)/usr/local/bin/coco_keyprovider
	$(INSTALL) -D -m 0644 $(BR2_EXTERNAL_COCOS_PATH)/package/coco-keyprovider/coco-keyprovider.service \
		$(TARGET_DIR)/etc/systemd/system/coco-keyprovider.service
	$(INSTALL) -D -m 0644 $(BR2_EXTERNAL_COCOS_PATH)/package/coco-keyprovider/coco-keyprovider.default \
		$(TARGET_DIR)/etc/default/coco-keyprovider
endef

$(eval $(generic-package))
