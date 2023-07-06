# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2022-2023 NXP
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

SHE_SAB_MSG_SRC	+= \
		$(PLAT_COMMON_PATH)/sab_msg/sab_process_msg.o \
		$(PLAT_COMMON_PATH)/sab_msg/sab_init_she_msg.o \

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

ifneq (${MT_SAB_STORAGE_KEY_DB_REQ}, 0x0)
DEFINES		+=	-DMT_SAB_STORAGE_KEY_DB_REQ=${MT_SAB_STORAGE_KEY_DB_REQ}
SAB_RCVMSG_SRC	+= \
		$(PLAT_COMMON_PATH)/sab_msg/sab_storage_key_db.o
endif

ifneq (${MT_SAB_SIGN_GEN},0x0)
DEFINES		+=	-DMT_SAB_SIGN_GEN=${MT_SAB_SIGN_GEN}
SAB_MSG_SRC	+= \
		$(PLAT_COMMON_PATH)/sab_msg/sab_sign_gen.o
endif

ifneq (${MT_SAB_SIGN_PREPARE},0x0)
DEFINES		+=	-DMT_SAB_SIGN_PREPARE=${MT_SAB_SIGN_PREPARE}
SAB_MSG_SRC	+= \
		$(PLAT_COMMON_PATH)/sab_msg/sab_sign_prepare.o
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
SHE_SAB_MSG_SRC	+= \
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
SHE_SAB_MSG_SRC	+= \
		$(PLAT_COMMON_PATH)/sab_msg/sab_session.o
endif

ifneq (${MT_SAB_KEY_STORE},0x0)
DEFINES		+=	-DMT_SAB_KEY_STORE=${MT_SAB_KEY_STORE}
SAB_MSG_SRC	+= \
		$(PLAT_COMMON_PATH)/sab_msg/sab_key_store.o
SHE_SAB_MSG_SRC	+= \
		$(PLAT_COMMON_PATH)/sab_msg/sab_key_store.o
endif

ifneq (${MT_SAB_KEY_MANAGEMENT},0x0)
DEFINES		+=	-DMT_SAB_KEY_MANAGEMENT=${MT_SAB_KEY_MANAGEMENT}
SAB_MSG_SRC	+= \
		$(PLAT_COMMON_PATH)/sab_msg/sab_key_management.o
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

ifneq (${MT_SAB_GC_AKEY_GEN},0x0)
DEFINES		+=	-DMT_SAB_GC_AKEY_GEN=${MT_SAB_GC_AKEY_GEN}
SAB_MSG_SRC	+= \
		$(PLAT_COMMON_PATH)/sab_msg/sab_gc_akey_gen.o
endif

ifneq (${MT_SAB_GC_ACRYPTO},0x0)
DEFINES		+=	-DMT_SAB_GC_ACRYPTO=${MT_SAB_GC_ACRYPTO}
SAB_MSG_SRC	+= \
		$(PLAT_COMMON_PATH)/sab_msg/sab_gc_acrypto.o
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

ifneq (${MT_SAB_SHARED_BUF},0x0)
DEFINES		+=	-DMT_SAB_SHARED_BUF=${MT_SAB_SHARED_BUF}
SHE_SAB_MSG_SRC	+= \
		$(PLAT_COMMON_PATH)/sab_msg/sab_shared_buf.o
endif

ifneq (${MT_SAB_OPEN_UTILS},0x0)
DEFINES		+=	-DMT_SAB_OPEN_UTILS=${MT_SAB_OPEN_UTILS}
SHE_SAB_MSG_SRC	+= \
		$(PLAT_COMMON_PATH)/sab_msg/sab_open_utils.o
endif

OBJECTS		+= $(SAB_MSG_SRC) \
		$(SAB_RCVMSG_SRC) \
		$(SHE_SAB_MSG_SRC) \
		$(PLAT_COMMON_PATH)/sab_msg/sab_session.o

INCLUDE_PATHS	+= \
       		-I${PLAT_COMMON_PATH}/sab_msg/include
