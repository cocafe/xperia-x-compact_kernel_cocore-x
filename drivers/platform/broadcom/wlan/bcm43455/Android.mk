ifneq ($(TARGET_BOARD_PLATFORM),)
WLAN_CHIPSET := bcm43455
WLAN_SELECT := CONFIG_BCMDHD=m CONFIG_BCMDHD_INSMOD_NO_FW_LOAD=y \
	CONFIG_BCM43455=m
ifneq (,$(filter $(SOMC_PLATFORM), loire))
# Loire platform
WLAN_SELECT += CONFIG_DHD_USE_SCHED_SCAN=y
endif
ifneq ($(SOMC_CFG_WLAN_BCN_TIMEOUT),)
WLAN_SELECT += CONFIG_SOMC_WLAN_BCN_TIMEOUT=$(SOMC_CFG_WLAN_BCN_TIMEOUT)
endif
ifneq ($(SOMC_CFG_WLAN_LISTEN_INTERVAL),)
WLAN_SELECT += CONFIG_SOMC_WLAN_LISTEN_INTERVAL=$(SOMC_CFG_WLAN_LISTEN_INTERVAL)
endif
ifneq ($(SOMC_CFG_WLAN_KEEP_ALIVE_SETTING),)
WLAN_SELECT += CONFIG_SOMC_WLAN_KEEP_ALIVE_SETTING=$(SOMC_CFG_WLAN_KEEP_ALIVE_SETTING)
endif
ifneq ($(SOMC_CFG_WLAN_SCAN_NPROBES),)
WLAN_SELECT += CONFIG_SOMC_WLAN_SCAN_NPROBES=$(SOMC_CFG_WLAN_SCAN_NPROBES)
endif
ifneq ($(SOMC_CFG_WLAN_NVRAM_PATH),)
WLAN_SELECT += CONFIG_SOMC_WLAN_NVRAM_PATH=$(SOMC_CFG_WLAN_NVRAM_PATH)
endif
ifneq ($(SOMC_CFG_WLAN_DISABLE_BCM_DLY),)
WLAN_SELECT += CONFIG_SOMC_WLAN_DISABLE_BCM_DLY=$(SOMC_CFG_WLAN_DISABLE_BCM_DLY)
endif
ifneq ($(SOMC_CFG_WLAN_CHANGE_SCAN_TIME),)
WLAN_SELECT += CONFIG_SOMC_CFG_WLAN_CHANGE_SCAN_TIME=$(SOMC_CFG_WLAN_CHANGE_SCAN_TIME)
endif
WLAN_BLD_DIR := vendor/broadcom/wlan/$(WLAN_CHIPSET)

LOCAL_PATH := $(call my-dir)/$(SOMC_PLATFORM)

DLKM_DIR := $(TOP)/device/qcom/common/dlkm

###########################################################
KBUILD_OPTIONS := WLAN_ROOT=../$(WLAN_BLD_DIR)
KBUILD_OPTIONS += MODNAME=wlan
KBUILD_OPTIONS += BOARD_PLATFORM=$(TARGET_BOARD_PLATFORM)
KBUILD_OPTIONS += $(WLAN_SELECT)

include $(CLEAR_VARS)
LOCAL_MODULE              := $(BOARD_WLAN_DEVICE).ko
LOCAL_MODULE_KBUILD_NAME  := wlan.ko
LOCAL_MODULE_TAGS         := optional
LOCAL_MODULE_PATH         := $(TARGET_OUT)/lib/modules
include $(DLKM_DIR)/AndroidKernelModule.mk
###########################################################
endif
