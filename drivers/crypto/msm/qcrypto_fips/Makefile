ifdef CONFIG_COMPAT
	ifeq ($(CONFIG_CRYPTO_DEV_QCE), y)
	qcrypto_module-objs += compat_qcedev.o
	endif
endif

ifeq ($(CONFIG_CRYPTO_DEV_QCEDEV), y)
qcrypto_module-objs += blob_src/qcedev.o blob_src/qcedev_fips.o
endif

ifeq ($(CONFIG_CRYPTO_DEV_QCE50), y)
	qcrypto_module-objs += blob_src/qce50.o
else
	ifeq ($(CONFIG_CRYPTO_DEV_QCE40), y)
	else
		qcrypto_module-objs += blob_src/qce.o
	endif
endif

ifeq ($(CONFIG_CRYPTO_DEV_OTA_CRYPTO), y)
qcrypto_module-objs += ota_crypto.o
endif

ifeq ($(CONFIG_CRYPTO_DEV_QCRYPTO), y)
qcrypto_module-objs += 	blob_src/qcrypto.o 			\
			blob_src/qcrypto_fips.o			\
			qcrypto_wrapper.o
endif

obj-$(CONFIG_CRYPTO_DEV_QCRYPTO_FIPS) += qcrypto_module.o