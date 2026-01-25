ext_pkgs := $(sort $(wildcard $(BR2_EXTERNAL_COCOS_PATH)/package/*/*.mk))
ifneq ($(ext_pkgs),)
include $(ext_pkgs)
endif
