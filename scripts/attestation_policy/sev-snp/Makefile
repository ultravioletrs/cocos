CARGO = cargo
TARGET = target
BUILD_DIR = $(TARGET)/release
BIN_NAME = attestation_policy
OUTPUT_DIR ?= $(BUILD_DIR)

all: build

build:
	$(CARGO) build --release
	@if [ "$(OUTPUT_DIR)" != "$(BUILD_DIR)" ]; then \
		mkdir -p $(OUTPUT_DIR) && \
		cp $(BUILD_DIR)/$(BIN_NAME) $(OUTPUT_DIR)/$(BIN_NAME) && \
		echo "Copied $(BIN_NAME) to $(OUTPUT_DIR)/"; \
	fi

clean:
	$(CARGO) clean
	@if [ "$(OUTPUT_DIR)" != "$(BUILD_DIR)" ] && [ -f "$(OUTPUT_DIR)/$(BIN_NAME)" ]; then \
		rm -f $(OUTPUT_DIR)/$(BIN_NAME) && \
		echo "Removed $(BIN_NAME) from $(OUTPUT_DIR)/"; \
	fi

.PHONY: all build clean
