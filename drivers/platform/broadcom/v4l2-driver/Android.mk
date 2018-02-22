LOCAL_PATH := $(call my-dir)

include $(call all-makefiles-under, $(LOCAL_PATH))

# v4l2_ant_driver, v4l2_fm_driver, and bt_protocol_driver depends on line_discipline_driver
$(TARGET_BTDRV) : $(TARGET_LDISC)
$(TARGET_FMDRV) : $(TARGET_LDISC)
ifneq ($(BOARD_ANT_WIRELESS_DEVICE),)
$(TARGET_ANTDRV) : $(TARGET_LDISC)
endif
