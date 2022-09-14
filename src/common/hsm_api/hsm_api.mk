# Copyright 2022 NXP
#
# NXP Confidential.
# This software is owned or controlled by NXP and may only be used strictly
# in accordance with the applicable license terms.  By expressly accepting
# such terms or by downloading, installing, activating and/or otherwise using
# the software, you are agreeing that you have read, and that you agree to
# comply with and are bound by, such license terms.  If you do not agree to be
# bound by the applicable license terms, then you may not retain, install,
# activate or otherwise use the software.
#

HSM_API_SRC	+= \
		$(PLAT_COMMON_PATH)/hsm_api/hsm_handle.o \
		$(PLAT_COMMON_PATH)/hsm_api/hsm_utils.o \
		$(PLAT_COMMON_PATH)/hsm_api/hsm_key.o \

ifneq (${MT_SAB_CIPHER},0x0)
DEFINES		+=	-DHSM_CIPHER
HSM_API_SRC	+= \
		$(PLAT_COMMON_PATH)/hsm_api/hsm_cipher.o
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

OBJECTS		+= $(HSM_API_SRC)

INCLUDE_PATHS	+= \
		   -Iinclude/hsm \
		   -I${PLAT_COMMON_PATH}/hsm_api/include
