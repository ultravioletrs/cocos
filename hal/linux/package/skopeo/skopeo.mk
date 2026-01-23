################################################################################
#
# skopeo
#
################################################################################

SKOPEO_VERSION = v1.17.0
SKOPEO_SITE = $(call github,containers,skopeo,$(SKOPEO_VERSION))
SKOPEO_LICENSE = Apache-2.0
SKOPEO_LICENSE_FILES = LICENSE
SKOPEO_CPE_ID_VENDOR = linuxfoundation

SKOPEO_DEPENDENCIES = host-go libgpgme lvm2

SKOPEO_LDFLAGS = -X main.gitCommit=$(SKOPEO_VERSION)

SKOPEO_TAGS = containers_image_openpgp

define SKOPEO_BUILD_CMDS
	$(TARGET_MAKE_ENV) $(HOST_GO_TARGET_ENV) \
		CGO_ENABLED=1 \
		$(HOST_DIR)/bin/go build -v \
		-o $(@D)/bin/skopeo \
		-tags "$(SKOPEO_TAGS)" \
		-ldflags "$(SKOPEO_LDFLAGS)" \
		$(@D)/cmd/skopeo
endef

define SKOPEO_INSTALL_TARGET_CMDS
	$(INSTALL) -D -m 0755 $(@D)/bin/skopeo $(TARGET_DIR)/usr/bin/skopeo
endef

$(eval $(generic-package))
