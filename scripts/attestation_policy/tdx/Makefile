GO = go
TARGET = target
BUILD_DIR = .
BIN_NAME = attestation_policy_tdx
OUTPUT_DIR ?= $(BUILD_DIR)

all: build

build:
	$(GO) build -o $(BUILD_DIR)/$(BIN_NAME) .
	@if [ "$(OUTPUT_DIR)" != "$(BUILD_DIR)" ]; then \
		mkdir -p $(OUTPUT_DIR) && \
		cp $(BUILD_DIR)/$(BIN_NAME) $(OUTPUT_DIR)/$(BIN_NAME) && \
		echo "Copied $(BIN_NAME) to $(OUTPUT_DIR)/"; \
	fi

clean:
	@if [ -f "$(BUILD_DIR)/$(BIN_NAME)" ]; then \
		rm -f $(BUILD_DIR)/$(BIN_NAME) && \
		echo "Removed $(BIN_NAME) from $(BUILD_DIR)/"; \
	fi
	@if [ "$(OUTPUT_DIR)" != "$(BUILD_DIR)" ] && [ -f "$(OUTPUT_DIR)/$(BIN_NAME)" ]; then \
		rm -f $(OUTPUT_DIR)/$(BIN_NAME) && \
		echo "Removed $(BIN_NAME) from $(OUTPUT_DIR)/"; \
	fi

.PHONY: all build clean
