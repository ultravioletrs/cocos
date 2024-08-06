WASMEDGE_DOWNLOAD_URL = https://raw.githubusercontent.com/WasmEdge/WasmEdge/master/utils/install.sh

define WASMEDGE_INSTALL_TARGET_CMDS
    curl -sSf $(WASMEDGE_DOWNLOAD_URL) | bash -s -- -p $(TARGET_DIR)/usr
    echo "source /usr/env" >> $(TARGET_DIR)/etc/profile
endef

$(eval $(generic-package))
