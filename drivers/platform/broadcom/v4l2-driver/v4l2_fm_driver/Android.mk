LOCAL_PATH := $(call my-dir)

DLKM_DIR := $(TOP)/device/qcom/common/dlkm
TMP_PWD := $(shell pwd)
LDISC_SYMVERS := vendor/broadcom/v4l2-driver/line_discipline_driver/Module.symvers
LDISC_EXPORT_SYMBOLS := $(TMP_PWD)/$(TARGET_OUT_INTERMEDIATES)/$(LDISC_SYMVERS)

KBUILD_OPTIONS := MODNAME=fm_drv
KBUILD_OPTIONS += BOARD_PLATFORM=$(TARGET_BOARD_PLATFORM)
KBUILD_OPTIONS += KBUILD_EXTRA_SYMBOLS=$(LDISC_EXPORT_SYMBOLS)
ifeq (,$(filter $(SEMC_PLATFORM), shinano))
KBUILD_OPTIONS += CONFIG_SOMC_FM_AUDIO_PATH=FM_AUDIO_I2S
endif

include $(CLEAR_VARS)
LOCAL_MODULE := fm_drv.ko
LOCAL_MODLUE_KBUILD_NAME := fm_drv.ko
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_PATH := $(TARGET_OUT)/lib/modules
include $(DLKM_DIR)/AndroidKernelModule.mk

TARGET_FMDRV := $(KBUILD_TARGET)
