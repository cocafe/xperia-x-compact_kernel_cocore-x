# Copyright (C) 2015 Sony Mobile Communications Inc.
ifneq ($(BOARD_WLAN_DEVICE_REV),)
include $(call my-dir)/$(BOARD_WLAN_DEVICE_REV)/Android.mk
endif
