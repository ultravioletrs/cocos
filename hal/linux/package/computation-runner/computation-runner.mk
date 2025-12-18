################################################################################
#
# computation-runner
#
################################################################################

COMPUTATION_RUNNER_VERSION = 0f18e10fdb1cc2547d6f1cd7c9d8fee4fc46a054
COMPUTATION_RUNNER_SITE = $(call github,sammyoina,cocos-ai,$(COMPUTATION_RUNNER_VERSION))

define COMPUTATION_RUNNER_BUILD_CMDS
	$(MAKE) -C $(@D) computation-runner
endef

define COMPUTATION_RUNNER_INSTALL_TARGET_CMDS
	$(INSTALL) -D -m 0750 $(@D)/build/cocos-computation-runner $(TARGET_DIR)/usr/bin/computation-runner
endef

define COMPUTATION_RUNNER_INSTALL_INIT_SYSTEMD
	$(INSTALL) -D -m 0640 $(@D)/init/systemd/computation-runner.service $(TARGET_DIR)/usr/lib/systemd/system/computation-runner.service
endef

$(eval $(generic-package))
