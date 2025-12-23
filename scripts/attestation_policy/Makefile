OUTPUT_DIR ?= ../../build
PLATFORMS = sev-snp tdx
# Convert OUTPUT_DIR to absolute path
ABS_OUTPUT_DIR := $(shell cd $(OUTPUT_DIR) 2>/dev/null && pwd || mkdir -p $(OUTPUT_DIR) && cd $(OUTPUT_DIR) && pwd)

.PHONY: all build clean $(PLATFORMS)

all: $(PLATFORMS)

$(PLATFORMS):
	$(MAKE) -C $@ OUTPUT_DIR=$(ABS_OUTPUT_DIR)

clean:
	@for platform in $(PLATFORMS); do \
		$(MAKE) -C $$platform OUTPUT_DIR=$(ABS_OUTPUT_DIR) clean; \
	done
