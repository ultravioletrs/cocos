################################################################################
#
# cloud-init
#
################################################################################

CLOUD_INIT_VERSION = 24.4.1
CLOUD_INIT_SITE = https://github.com/canonical/cloud-init/archive/refs/tags
CLOUD_INIT_SOURCE = $(CLOUD_INIT_VERSION).tar.gz
CLOUD_INIT_LICENSE = Apache-2.0
# Dependencies: note that we need python3-venv to run "python3 -m venv"
CLOUD_INIT_DEPENDENCIES = host-python3 python3 python-pip python-setuptools

define CLOUD_INIT_BUILD_CMDS
	# Create a virtual environment (using the host’s python3)
	/usr/bin/python3 -m venv $(BUILD_DIR)/cloud-init-venv
	# Change directory to the package source so that relative paths work correctly.
	cd $(@D) && $(BUILD_DIR)/cloud-init-venv/bin/pip install -r requirements.txt
	cd $(@D) && $(BUILD_DIR)/cloud-init-venv/bin/pip install setuptools
	# Build cloud-init (the setup.py now finds its helper scripts like tools/read-dependencies)
	cd $(@D) && $(BUILD_DIR)/cloud-init-venv/bin/python setup.py build
endef

define CLOUD_INIT_INSTALL_TARGET_CMDS
	cd $(@D) && $(BUILD_DIR)/cloud-init-venv/bin/pip install --prefix=/usr --root=$(TARGET_DIR) .
	$(SED) '1 s|^#!.*python.*|#!/usr/bin/env python3|' $(TARGET_DIR)/usr/bin/cloud-init
endef



define CLOUD_INIT_INSTALL_INIT_SYSTEMD
	# Ensure that the target systemd directories exist.
	$(INSTALL) -d $(TARGET_DIR)/etc/systemd/system
	$(INSTALL) -d $(TARGET_DIR)/etc/systemd/system/multi-user.target.wants
	# Install all provided cloud-init systemd unit files.
	cd $(@D) && for unit in cloud-init.service cloud-config.service cloud-init-local.service cloud-final.service; do \
	    $(INSTALL) -m 644 packaging/systemd/$$unit $(TARGET_DIR)/etc/systemd/system/$$unit; \
	    ln -sf /etc/systemd/system/$$unit $(TARGET_DIR)/etc/systemd/system/multi-user.target.wants/$$unit; \
	done
endef

# Run the systemd hook after installation.
CLOUD_INIT_POST_INSTALL_TARGET_HOOKS += CLOUD_INIT_INSTALL_INIT_SYSTEMD

$(eval $(generic-package))
