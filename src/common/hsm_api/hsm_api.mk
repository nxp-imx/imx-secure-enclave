# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2022-2023 NXP
#

HSM_API_SRC	+= \
		$(PLAT_COMMON_PATH)/hsm_api/hsm_handle.o \
		$(PLAT_COMMON_PATH)/hsm_api/hsm_utils.o \

ifneq (${MT_SAB_SESSION},0x0)
DEFINES		+=	-DHSM_SESSION
HSM_API_SRC	+= \
		$(PLAT_COMMON_PATH)/hsm_api/hsm_session.o
endif

ifneq (${MT_SAB_KEY_STORE},0x0)
DEFINES		+=	-DHSM_KEY_STORE
HSM_API_SRC	+= \
		$(PLAT_COMMON_PATH)/hsm_api/hsm_key_store.o
endif

ifneq (${MT_SAB_KEY_MANAGEMENT},0x0)
DEFINES		+=	-DHSM_KEY_MANAGEMENT
HSM_API_SRC	+= \
		$(PLAT_COMMON_PATH)/hsm_api/hsm_key_management.o
endif

ifneq (${MT_SAB_CIPHER},0x0)
DEFINES		+=	-DHSM_CIPHER
HSM_API_SRC	+= \
		$(PLAT_COMMON_PATH)/hsm_api/hsm_cipher.o
endif

ifneq (${MT_SAB_DATA_STORAGE},0x0)
DEFINES		+=	-DHSM_DATA_STORAGE
HSM_API_SRC	+= \
		$(PLAT_COMMON_PATH)/hsm_api/hsm_data_storage.o
endif

ifneq (${MT_SAB_MAC},0x0)
DEFINES		+=	-DHSM_MAC
HSM_API_SRC	+= \
		$(PLAT_COMMON_PATH)/hsm_api/hsm_mac.o
endif

ifneq (${MT_SAB_VERIFY_SIGN},0x0)
DEFINES		+=	-DHSM_VERIFY_SIGN
HSM_API_SRC	+= \
		$(PLAT_COMMON_PATH)/hsm_api/hsm_verify_sign.o
endif

ifneq (${MT_SAB_SIGN_GEN},0x0)
DEFINES		+=	-DHSM_SIGN_GEN
HSM_API_SRC	+= \
		$(PLAT_COMMON_PATH)/hsm_api/hsm_sign_gen.o
endif

ifneq (${MT_SAB_SIGN_PREPARE},0x0)
DEFINES		+=	-DHSM_SIGN_PREPARE
HSM_API_SRC	+= \
		$(PLAT_COMMON_PATH)/hsm_api/hsm_sign_prepare.o
endif

ifneq (${MT_SAB_RNG},0x0)
DEFINES		+=	-DHSM_RNG
HSM_API_SRC	+= \
		$(PLAT_COMMON_PATH)/hsm_api/hsm_rng.o
endif

ifneq (${MT_SAB_HASH_GEN},0x0)
DEFINES		+=	-DHSM_HASH_GEN
HSM_API_SRC	+= \
		$(PLAT_COMMON_PATH)/hsm_api/hsm_hash.o
endif

ifneq (${MT_SAB_KEY_GENERATE},0x0)
DEFINES		+=	-DHSM_KEY_GENERATE
HSM_API_SRC	+= \
		$(PLAT_COMMON_PATH)/hsm_api/hsm_key_generate.o
endif

ifneq (${MT_SAB_GC_AKEY_GEN},0x0)
DEFINES		+=	-DHSM_GC_AKEY_GEN
HSM_API_SRC	+= \
		$(PLAT_COMMON_PATH)/hsm_api/hsm_gc_akey_gen.o
endif

ifneq (${MT_SAB_GC_ACRYPTO},0x0)
DEFINES		+=	-DHSM_GC_ACRYPTO
HSM_API_SRC	+= \
		$(PLAT_COMMON_PATH)/hsm_api/hsm_gc_acrypto.o
endif

ifneq (${MT_SAB_KEY_GEN_EXT},0x0)
DEFINES		+=	-DHSM_KEY_GEN_EXT
HSM_API_SRC	+= \
		$(PLAT_COMMON_PATH)/hsm_api/hsm_key_gen_ext.o
endif

ifneq (${MT_SAB_IMPORT_KEY},0x0)
DEFINES		+=	-DHSM_IMPORT_KEY
HSM_API_SRC	+= \
		$(PLAT_COMMON_PATH)/hsm_api/hsm_importkey.o
endif

ifneq (${MT_SAB_DELETE_KEY},0x0)
DEFINES		+=	-DHSM_DELETE_KEY
HSM_API_SRC	+= \
		$(PLAT_COMMON_PATH)/hsm_api/hsm_delete_key.o
endif

ifneq (${MT_SAB_MANAGE_KEY},0x0)
DEFINES		+=	-DHSM_MANAGE_KEY
HSM_API_SRC	+= \
		$(PLAT_COMMON_PATH)/hsm_api/hsm_managekey.o
endif

ifneq (${MT_SAB_GET_KEY_ATTR},0x0)
DEFINES		+=	-DHSM_GET_KEY_ATTR
HSM_API_SRC	+= \
		$(PLAT_COMMON_PATH)/hsm_api/hsm_get_key_attr.o
endif

ifneq (${MT_SAB_LC_UPDATE},0x0)
DEFINES		+=	-DHSM_LC_UPDATE
HSM_API_SRC	+= \
		$(PLAT_COMMON_PATH)/hsm_api/hsm_lc_update.o
endif

ifneq (${MT_SAB_DEBUG_DUMP},0x0)
DEFINES		+=	-DHSM_DEBUG_DUMP
HSM_API_SRC	+= \
		$(PLAT_COMMON_PATH)/hsm_api/hsm_debug_dump.o
endif

ifneq (${MT_SAB_KEY_RECOVERY},0x0)
DEFINES		+=	-DHSM_KEY_RECOVERY
HSM_API_SRC	+= \
		$(PLAT_COMMON_PATH)/hsm_api/hsm_key_recovery.o
endif

ifneq (${MT_SAB_AUTH_ENC},0x0)
DEFINES		+=	-DHSM_AUTH_ENC
HSM_API_SRC	+= \
		$(PLAT_COMMON_PATH)/hsm_api/hsm_auth_enc.o
endif

ifneq (${MT_SAB_DEV_ATTEST},0x0)
DEFINES		+=	-DHSM_DEV_ATTEST
HSM_API_SRC	+= \
		$(PLAT_COMMON_PATH)/hsm_api/hsm_dev_attest.o
endif

ifneq (${MT_SAB_DEV_GETINFO},0x0)
DEFINES		+=	-DHSM_DEV_GETINFO
HSM_API_SRC	+= \
		$(PLAT_COMMON_PATH)/hsm_api/hsm_dev_getinfo.o
endif

ifneq (${MT_SAB_GET_INFO},0x0)
DEFINES		+=	-DHSM_GET_INFO
HSM_API_SRC	+= \
		$(PLAT_COMMON_PATH)/hsm_api/hsm_get_info.o
endif

OBJECTS		+= $(HSM_API_SRC)

INCLUDE_PATHS	+= \
		   -Iinclude/hsm \
		   -I${PLAT_COMMON_PATH}/hsm_api/include
