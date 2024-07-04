WASMTIME_SITE = https://wasmtime.dev/install.sh

define WASMTIME_BUILD_CMDS
    curl $(WASMTIME_SITE) -sSf | bash
endef

define WASMTIME_INSTALL_TARGET_CMDS
    $(INSTALL) -D -m 0755 ~/.wasmtime/bin/wasmtime $(TARGET_DIR)/usr/bin/wasmtime
endef

$(eval $(generic-package))
