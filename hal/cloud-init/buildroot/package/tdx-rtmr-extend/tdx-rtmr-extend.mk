################################################################################
#
# tdx-rtmr-extend
#
################################################################################

TDX_RTMR_EXTEND_VERSION = 1.0
TDX_RTMR_EXTEND_SITE = $(BR2_EXTERNAL_COCOS_PATH)/package/tdx-rtmr-extend/src
TDX_RTMR_EXTEND_SITE_METHOD = local
TDX_RTMR_EXTEND_GOMOD = github.com/ultravioletrs/cocos/hal/cloud-init/buildroot/package/tdx-rtmr-extend
TDX_RTMR_EXTEND_BIN_NAME = tdx-rtmr-extend
TDX_RTMR_EXTEND_LDFLAGS = -s -w

$(eval $(golang-package))
