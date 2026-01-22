################################################################################
#
# computation-runner
#
################################################################################

COMPUTATION_RUNNER_VERSION = c28cefae0a5b51024a1c08e50e460e21866edcf6
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
