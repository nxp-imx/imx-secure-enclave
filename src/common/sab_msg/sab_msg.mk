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

include $(PLAT_PATH)/sab_msg.def

SAB_MSG_SRC	+= \
		$(PLAT_COMMON_PATH)/sab_msg/sab_process_msg.o \
		$(PLAT_COMMON_PATH)/sab_msg/sab_init_proc_msg.o \

ifneq (${MT_SAB_SIGN_GEN},0x0)
DEFINES		+=	-DMT_SAB_SIGN_GEN=${MT_SAB_SIGN_GEN}
SAB_MSG_SRC	+= \
		$(PLAT_COMMON_PATH)/sab_msg/sab_sign_gen.o
endif

ifneq (${MT_SAB_VERIFY_SIGN},0x0)
DEFINES		+=	-DMT_SAB_VERIFY_SIGN=${MT_SAB_VERIFY_SIGN}
SAB_MSG_SRC	+= \
		$(PLAT_COMMON_PATH)/sab_msg/sab_verify_sign.o
endif

ifneq (${MT_SAB_DEBUG_DUMP},0x0)
DEFINES		+=	-DMT_SAB_DEBUG_DUMP=${MT_SAB_DEBUG_DUMP}
SAB_MSG_SRC	+= \
		$(PLAT_COMMON_PATH)/sab_msg/sab_debug_dump.o
endif

ifneq (${MT_SAB_DEV_ATTEST},0x0)
DEFINES		+=	-DMT_SAB_DEV_ATTEST=${MT_SAB_DEV_ATTEST}
SAB_MSG_SRC	+= \
		$(PLAT_COMMON_PATH)/sab_msg/sab_dev_attest.o
endif

ifneq (${MT_SAB_DEV_GETINFO},0x0)
DEFINES		+=	-DMT_SAB_DEV_GETINFO=${MT_SAB_DEV_GETINFO}
SAB_MSG_SRC	+= \
		$(PLAT_COMMON_PATH)/sab_msg/sab_dev_getinfo.o
endif

ifneq (${MT_SAB_MAC},0x0)
DEFINES		+=	-DMT_SAB_MAC=${MT_SAB_MAC}
SAB_MSG_SRC	+= \
		$(PLAT_COMMON_PATH)/sab_msg/sab_mac.o
endif

ifneq (${MT_SAB_CIPHER},0x0)
DEFINES		+=	-DMT_SAB_CIPHER=${MT_SAB_CIPHER}
SAB_MSG_SRC	+= \
		$(PLAT_COMMON_PATH)/sab_msg/sab_cipher.o
endif

ifneq (${MT_SAB_HASH_GEN},0x0)
DEFINES		+=	-DMT_SAB_HASH_GEN=${MT_SAB_HASH_GEN}
SAB_MSG_SRC	+= \
		$(PLAT_COMMON_PATH)/sab_msg/sab_hash.o
endif

ifneq (${MT_SAB_RNG},0x0)
DEFINES		+=	-DMT_SAB_RNG=${MT_SAB_RNG}
SAB_MSG_SRC	+= \
		$(PLAT_COMMON_PATH)/sab_msg/sab_rng.o
endif

ifneq (${MT_SAB_KEY_GENERATE},0x0)
DEFINES		+=	-DMT_SAB_KEY_GENERATE=${MT_SAB_KEY_GENERATE}
SAB_MSG_SRC	+= \
		$(PLAT_COMMON_PATH)/sab_msg/sab_key_generate.o
endif

ifneq (${MT_SAB_KEY_GEN_EXT},0x0)
DEFINES		+=	-DMT_SAB_KEY_GEN_EXT=${MT_SAB_KEY_GEN_EXT}
SAB_MSG_SRC	+= \
		$(PLAT_COMMON_PATH)/sab_msg/sab_key_gen_ext.o
endif

ifneq (${MT_SAB_IMPORT_KEY},0x0)
DEFINES		+=	-DMT_SAB_IMPORT_KEY=${MT_SAB_IMPORT_KEY}
SAB_MSG_SRC	+= \
		$(PLAT_COMMON_PATH)/sab_msg/sab_import_key.o
endif

ifneq (${MT_SAB_DELETE_KEY},0x0)
DEFINES		+=	-DMT_SAB_DELETE_KEY=${MT_SAB_DELETE_KEY}
SAB_MSG_SRC	+= \
		$(PLAT_COMMON_PATH)/sab_msg/sab_delete_key.o
endif

ifneq (${MT_SAB_MANAGE_KEY},0x0)
DEFINES		+=	-DMT_SAB_MANAGE_KEY=${MT_SAB_MANAGE_KEY}
SAB_MSG_SRC	+= \
		$(PLAT_COMMON_PATH)/sab_msg/sab_managekey.o
endif

ifneq (${MT_SAB_KEY_RECOVERY},0x0)
DEFINES		+=	-DMT_SAB_KEY_RECOVERY=${MT_SAB_KEY_RECOVERY}
SAB_MSG_SRC	+= \
		$(PLAT_COMMON_PATH)/sab_msg/sab_key_recovery.o
endif

OBJECTS		+= $(SAB_MSG_SRC) \
		   $(PLAT_COMMON_PATH)/sab_msg/sab_session.o

INCLUDE_PATHS	+= \
       		-I${PLAT_COMMON_PATH}/sab_msg/include
