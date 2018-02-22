LOCAL_PATH := $(call my-dir)

DLKM_DIR := $(TOP)/device/qcom/common/dlkm
TMP_PWD := $(shell pwd)
LDISC_SYMVERS := vendor/broadcom/v4l2-driver/line_discipline_driver/Module.symvers
LDISC_EXPORT_SYMBOLS := $(TMP_PWD)/$(TARGET_OUT_INTERMEDIATES)/$(LDISC_SYMVERS)

KBUILD_OPTIONS := MODNAME=brcm_bt_drv
KBUILD_OPTIONS += BOARD_PLATFORM=$(TARGET_BOARD_PLATFORM)
KBUILD_OPTIONS += KBUILD_EXTRA_SYMBOLS=$(LDISC_EXPORT_SYMBOLS)

include $(CLEAR_VARS)
LOCAL_MODULE := brcm_bt_drv.ko
LOCAL_MODLUE_KBUILD_NAME := brcm_bt_drv.ko
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_PATH := $(TARGET_OUT)/lib/modules
include $(DLKM_DIR)/AndroidKernelModule.mk

TARGET_BTDRV := $(KBUILD_TARGET)
