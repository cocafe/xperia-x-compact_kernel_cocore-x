qdrbg_module-objs		:= msm_rng_wrapper.o
qdrbg_module-objs		+= blob_src/ctr_drbg.o 			\
				   blob_src/fips_drbg.o 		\
				   blob_src/msm_fips_selftest.o 	\
				   blob_src/msm_rng.o

obj-$(CONFIG_CRYPTO_DEV_QDRBG)	+= qdrbg_module.o