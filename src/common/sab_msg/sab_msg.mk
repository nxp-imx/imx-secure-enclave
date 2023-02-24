# Copyright 2022-2023 NXP
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
SAB_RCVMSG_SRC	+= \
		$(PLAT_COMMON_PATH)/sab_msg/sab_process_msg.o \
		$(PLAT_COMMON_PATH)/sab_msg/sab_init_nvm_msg.o

ifneq (${MT_SAB_STORAGE_OPEN},0x0)
DEFINES		+=	-DMT_SAB_STORAGE_OPEN=${MT_SAB_STORAGE_OPEN}
SAB_RCVMSG_SRC	+= \
		$(PLAT_COMMON_PATH)/sab_msg/sab_storage_open.o
endif

ifneq (${MT_SAB_STORAGE_CLOSE},0x0)
DEFINES		+=	-DMT_SAB_STORAGE_CLOSE=${MT_SAB_STORAGE_CLOSE}
SAB_RCVMSG_SRC	+= \
		$(PLAT_COMMON_PATH)/sab_msg/sab_storage_close.o
endif

ifneq (${MT_SAB_STORAGE_MASTER_IMPORT},0x0)
DEFINES		+=	-DMT_SAB_STORAGE_MASTER_IMPORT=${MT_SAB_STORAGE_MASTER_IMPORT}
SAB_RCVMSG_SRC	+= \
		$(PLAT_COMMON_PATH)/sab_msg/sab_storage_master_import.o
endif

ifneq (${MT_SAB_STORAGE_MASTER_EXPORT_REQ},0x0)
DEFINES		+=	-DMT_SAB_STORAGE_MASTER_EXPORT_REQ=${MT_SAB_STORAGE_MASTER_EXPORT_REQ}
SAB_RCVMSG_SRC	+= \
		$(PLAT_COMMON_PATH)/sab_msg/sab_storage_master_export.o
endif

ifneq (${MT_SAB_STORAGE_EXPORT_FINISH_REQ},0x0)
DEFINES		+=	-DMT_SAB_STORAGE_EXPORT_FINISH_REQ=${MT_SAB_STORAGE_EXPORT_FINISH_REQ}
SAB_RCVMSG_SRC	+= \
		$(PLAT_COMMON_PATH)/sab_msg/sab_storage_export_finish.o
endif

SAB_MSG_SRC	+= \
		$(PLAT_COMMON_PATH)/sab_msg/sab_process_msg.o \
		$(PLAT_COMMON_PATH)/sab_msg/sab_init_proc_msg.o \

ifneq (${MT_SAB_STORAGE_CHUNK_GET_REQ},0x0)
DEFINES		+=	-DMT_SAB_STORAGE_CHUNK_GET_REQ=${MT_SAB_STORAGE_CHUNK_GET_REQ}
SAB_RCVMSG_SRC	+= \
		$(PLAT_COMMON_PATH)/sab_msg/sab_storage_get_chunk.o
endif

ifneq (${MT_SAB_STORAGE_CHUNK_GET_DONE_REQ},0x0)
DEFINES		+=	-DMT_SAB_STORAGE_CHUNK_GET_DONE_REQ=${MT_SAB_STORAGE_CHUNK_GET_DONE_REQ}
SAB_RCVMSG_SRC	+= \
		$(PLAT_COMMON_PATH)/sab_msg/sab_storage_get_chunk_done.o
endif

ifneq (${MT_SAB_STORAGE_CHUNK_EXPORT_REQ},0x0)
DEFINES		+=	-DMT_SAB_STORAGE_CHUNK_EXPORT_REQ=${MT_SAB_STORAGE_CHUNK_EXPORT_REQ}
SAB_RCVMSG_SRC	+= \
		$(PLAT_COMMON_PATH)/sab_msg/sab_storage_chunk_export.o
endif

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

ifneq (${MT_SAB_LC_UPDATE},0x0)
DEFINES		+=	-DMT_SAB_LC_UPDATE=${MT_SAB_LC_UPDATE}
SAB_MSG_SRC	+= \
		$(PLAT_COMMON_PATH)/sab_msg/sab_lc_update.o
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

ifneq (${MT_SAB_GET_INFO},0x0)
DEFINES		+=	-DMT_SAB_GET_INFO=${MT_SAB_GET_INFO}
SAB_MSG_SRC	+= \
		$(PLAT_COMMON_PATH)/sab_msg/sab_get_info.o
endif

ifneq (${MT_SAB_MAC},0x0)
DEFINES		+=	-DMT_SAB_MAC=${MT_SAB_MAC}
SAB_MSG_SRC	+= \
		$(PLAT_COMMON_PATH)/sab_msg/sab_mac.o
endif

ifneq (${MT_SAB_SESSION},0x0)
DEFINES		+=	-DMT_SAB_SESSION=${MT_SAB_SESSION}
SAB_MSG_SRC	+= \
		$(PLAT_COMMON_PATH)/sab_msg/sab_session.o
endif

ifneq (${MT_SAB_CIPHER},0x0)
DEFINES		+=	-DMT_SAB_CIPHER=${MT_SAB_CIPHER}
SAB_MSG_SRC	+= \
		$(PLAT_COMMON_PATH)/sab_msg/sab_cipher.o
endif

ifneq (${MT_SAB_DATA_STORAGE},0x0)
DEFINES		+=	-DMT_SAB_DATA_STORAGE=${MT_SAB_DATA_STORAGE}
SAB_MSG_SRC	+= \
		$(PLAT_COMMON_PATH)/sab_msg/sab_data_storage.o
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

ifneq (${MT_SAB_GET_KEY_ATTR},0x0)
DEFINES		+=	-DMT_SAB_GET_KEY_ATTR=${MT_SAB_GET_KEY_ATTR}
SAB_MSG_SRC	+= \
		$(PLAT_COMMON_PATH)/sab_msg/sab_get_key_attr.o
endif

ifneq (${MT_SAB_KEY_RECOVERY},0x0)
DEFINES		+=	-DMT_SAB_KEY_RECOVERY=${MT_SAB_KEY_RECOVERY}
SAB_MSG_SRC	+= \
		$(PLAT_COMMON_PATH)/sab_msg/sab_key_recovery.o
endif

ifneq (${MT_SAB_AUTH_ENC},0x0)
DEFINES		+=	-DMT_SAB_AUTH_ENC=${MT_SAB_AUTH_ENC}
SAB_MSG_SRC	+= \
		$(PLAT_COMMON_PATH)/sab_msg/sab_auth_enc.o
endif

OBJECTS		+= $(SAB_MSG_SRC) \
		$(PLAT_COMMON_PATH)/sab_msg/sab_session.o

INCLUDE_PATHS	+= \
       		-I${PLAT_COMMON_PATH}/sab_msg/include
