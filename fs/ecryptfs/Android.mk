###
### ecryptfs.ko
###
LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

LOCAL_MODULE        := ecryptfs.ko
LOCAL_MODULE_CLASS  := DLKM
LOCAL_MODULE_TAGS   := optional
LOCAL_MODULE_PATH   := $(TARGET_OUT)/lib/modules
ECRYPTFS_BUILD_DIR  := $(OUT)/ecryptfs
ECRYPTFS_LOCAL_DIR  := $(LOCAL_PATH)

include $(BUILD_SYSTEM)/base_rules.mk

$(LOCAL_BUILT_MODULE): $(ECRYPTFS_BUILD_DIR)/$(LOCAL_MODULE) | $(ACP)
	@sh -c "\
	   KMOD_SIG_ALL=`cat $(OUT)/obj/KERNEL_OBJ/.config | grep CONFIG_MODULE_SIG_ALL | cut -d'=' -f2`; \
	   KMOD_SIG_HASH=`cat $(OUT)/obj/KERNEL_OBJ/.config | grep CONFIG_MODULE_SIG_HASH | cut -d'=' -f2 | sed 's/\"//g'`; \
	   if [ \"\$$KMOD_SIG_ALL\" = \"y\" ] && [ -n \"\$$KMOD_SIG_HASH\" ]; then \
	      echo \"Signing kernel module: \" `basename $<`; \
	      MODSECKEY=$(OUT)/obj/KERNEL_OBJ/signing_key.priv; \
	      MODPUBKEY=$(OUT)/obj/KERNEL_OBJ/signing_key.x509; \
	      cp $< $<.unsigned; \
	      perl $(TOP_DIR)./kernel/scripts/sign-file \$$KMOD_SIG_HASH \$$MODSECKEY \$$MODPUBKEY $<; \
	   fi; \
	"
	$(transform-prebuilt-to-target)

# Workaround for build error of mm command.
# KERNEL_CROSS_COMPILE and KERNEL_ARCH are empty when execute mm command.
# So, copied Define from kernel/AndroidKernel.mk to use mm command.
#
# WARNING!!!
# Check KERNEL_CROSS_COMPILE, KERNEL_ARCH and KERNEL_FLAGS value when platform is updated.
# This two value may be different on other platform.
TARGET_KERNEL_ARCH := $(strip $(TARGET_KERNEL_ARCH))
TARGET_KERNEL_CROSS_COMPILE_PREFIX := $(strip $(TARGET_KERNEL_CROSS_COMPILE_PREFIX))
ifeq ($(filter %64,$(TARGET_KERNEL_ARCH)),)
  KERNEL_CROSS_COMPILE := arm-eabi-
  KERNEL_ARCH := arm
  KERNEL_FLAGS :=
else
  KERNEL_CROSS_COMPILE := $(TARGET_KERNEL_CROSS_COMPILE_PREFIX)
  KERNEL_ARCH := $(TARGET_KERNEL_ARCH)
  KERNEL_CFLAGS := KCFLAGS=-mno-android
endif

$(ECRYPTFS_BUILD_DIR)/$(LOCAL_MODULE): $(TARGET_PREBUILT_INT_KERNEL) $(ECRYPTFS_LOCAL_DIR)
	$(hide) mkdir -p $(ECRYPTFS_BUILD_DIR) && \
	cp -f $(ECRYPTFS_LOCAL_DIR)/Makefile $(ECRYPTFS_LOCAL_DIR)/*.c $(ECRYPTFS_LOCAL_DIR)/*.h $(ECRYPTFS_BUILD_DIR) && \
	make -s -C kernel O=$(OUT)/obj/KERNEL_OBJ M=$(ECRYPTFS_BUILD_DIR) ARCH=$(KERNEL_ARCH) CROSS_COMPILE=$(KERNEL_CROSS_COMPILE) $(KERNEL_CFLAGS) modules
