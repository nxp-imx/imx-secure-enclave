// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#include "sab_msg_def.h"
#include "sab_process_msg.h"

#if MT_SAB_LC_UPDATE
#include "sab_lc_update.h"
#endif

#if MT_SAB_DEBUG_DUMP
#include "sab_debug_dump.h"
#endif

#if MT_SAB_DEV_GETINFO
#include "sab_dev_getinfo.h"
#endif

#if MT_SAB_DEV_ATTEST
#include "sab_dev_attest.h"
#endif

#if MT_SAB_GET_INFO
#include "sab_get_info.h"
#endif

#if MT_SAB_KEY_GENERATE
#include "sab_key_generate.h"
#endif

#if MT_SAB_MANAGE_KEY_GROUP
#include "sab_manage_key_group.h"
#endif

#if MT_SAB_GC_AKEY_GEN
#include "sab_gc_akey_gen.h"
#endif

#if MT_SAB_GC_ACRYPTO
#include "sab_gc_acrypto.h"
#endif

#if MT_SAB_KEY_GEN_EXT
#include "sab_key_gen_ext.h"
#endif

#if MT_SAB_IMPORT_KEY
#include "sab_import_key.h"
#endif

#if MT_SAB_DELETE_KEY
#include "sab_delete_key.h"
#endif

#if MT_SAB_MANAGE_KEY
#include "sab_managekey.h"
#endif

#if MT_SAB_GET_KEY_ATTR
#include "sab_get_key_attr.h"
#endif

#if MT_SAB_HASH_GEN
#include "sab_hash.h"
#endif

#if MT_SAB_SIGN_GEN
#include "sab_sign_gen.h"
#endif

#if MT_SAB_SIGN_PREPARE
#include "sab_sign_prepare.h"
#endif

#if MT_SAB_VERIFY_SIGN
#include "sab_verify_sign.h"
#endif

#if MT_SAB_CIPHER
#include "sab_cipher.h"
#endif

#if MT_SAB_DATA_STORAGE
#include "sab_data_storage.h"
#endif

#if MT_SAB_MAC
#include "sab_mac.h"
#endif

#if MT_SAB_RNG
#include "sab_rng.h"
#endif

#if MT_SAB_KEY_RECOVERY
#include "sab_key_recovery.h"
#endif

#if MT_SAB_AUTH_ENC
#include "sab_auth_enc.h"
#endif

#if MT_SAB_KEY_GENERIC_CRYPTO
#include "sab_key_generic_crypto.h"
#endif

#if MT_SAB_ROOT_KEK_EXPORT
#include "sab_root_kek_export.h"
#endif

#if MT_SAB_PUB_KEY_DECOMPRESSION
#include "sab_pub_key_decompression.h"
#endif

#if MT_SAB_BUT
#include "sab_butterfly.h"
#endif

#if MT_SAB_ST_BUT
#include "sab_st_butterfly.h"
#endif

#if MT_SAB_ECIES
#include "sab_ecies.h"
#endif

#if MT_SAB_SM2_ECES
#include "sab_sm2_eces.h"
#endif

#if MT_SAB_SM2_GET_Z
#include "sab_sm2_get_z.h"
#endif

#if MT_SAB_KEY_EXCHANGE
#include "sab_key_exchange.h"
#endif

#if MT_SAB_SESSION
#include "sab_session.h"
#endif

#if MT_SAB_KEY_STORE
#include "sab_key_store.h"
#endif

#if MT_SAB_KEY_MANAGEMENT
#include "sab_key_management.h"
#endif

static int init_proc_sab_base_msg_engine(msg_type_t msg_type,
					 uint32_t msg_id)
{
	int ret = NOT_DONE;

	switch (msg_id) {
#if MT_SAB_DEBUG_DUMP
		case ROM_DEBUG_DUMP_REQ:
			if (msg_type == MT_SAB_DEBUG_DUMP) {
				ret = add_sab_msg_handler(msg_id, MT_SAB_DEBUG_DUMP,
						prepare_msg_debugdump,
						proc_msg_rsp_debugdump);
			}
			break;
#endif
#if MT_SAB_LC_UPDATE
		case ROM_DEV_FWD_LC_UPDATE:
			if (msg_type == MT_SAB_LC_UPDATE) {
				ret = add_sab_msg_handler(msg_id, MT_SAB_LC_UPDATE,
						prepare_msg_fwd_lc_update,
						proc_msg_rsp_fwd_lc_update);
			}
			break;
		case ROM_DEV_RET_LC_UPDATE:
			if (msg_type == MT_SAB_LC_UPDATE) {
				ret = add_sab_msg_handler(msg_id, MT_SAB_LC_UPDATE,
						prepare_msg_ret_lc_update,
						proc_msg_rsp_ret_lc_update);
			}
			break;
#endif
#if MT_SAB_DEV_GETINFO
		case ROM_DEV_GETINFO_REQ:
			if (msg_type == MT_SAB_DEV_GETINFO) {
				ret = add_sab_msg_handler(msg_id, MT_SAB_DEV_GETINFO,
						prepare_msg_dev_getinfo,
						proc_msg_rsp_dev_getinfo);
			}
			break;
#endif
#if MT_SAB_DEV_ATTEST
		case ROM_DEV_ATTEST_REQ:
			if (msg_type == MT_SAB_DEV_ATTEST) {
				ret = add_sab_msg_handler(msg_id, MT_SAB_DEV_ATTEST,
						prepare_msg_dev_attest,
						proc_msg_rsp_dev_attest);
			}
			break;
#endif
		default:
			break;
	}
	return ret;
}

static  int init_proc_sab_hsm_msg_engine(msg_type_t msg_type,
					 uint32_t msg_id)
{
	int ret = NOT_DONE;

	switch (msg_id) {
#if MT_SAB_GET_INFO
	case SAB_GET_INFO_REQ:
		if (msg_type == MT_SAB_GET_INFO) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_GET_INFO,
						  prepare_msg_get_info,
						  proc_msg_rsp_get_info);
		}
		break;
#endif
#if MT_SAB_KEY_GENERATE
	case SAB_KEY_GENERATE_REQ:
		if (msg_type == MT_SAB_KEY_GENERATE) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_KEY_GENERATE,
						  prepare_msg_generatekey,
						  proc_msg_rsp_generatekey);
		}
		break;
#endif
#if MT_SAB_MANAGE_KEY_GROUP
	case SAB_MANAGE_KEY_GROUP_REQ:
		if (msg_type == MT_SAB_MANAGE_KEY_GROUP) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_MANAGE_KEY_GROUP,
						  prepare_msg_manage_key_group,
						  proc_msg_rsp_manage_key_group);
		}
		break;
#endif
#if MT_SAB_GC_AKEY_GEN
	case SAB_GC_AKEY_GEN_REQ:
		if (msg_type == MT_SAB_GC_AKEY_GEN) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_GC_AKEY_GEN,
						  prepare_msg_gc_akey_gen,
						  proc_msg_gc_akey_gen);
		}
		break;
#endif
#if MT_SAB_GC_ACRYPTO
	case SAB_GC_ACRYPTO_REQ:
		if (msg_type == MT_SAB_GC_ACRYPTO) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_GC_ACRYPTO,
						  prepare_msg_gc_acrypto,
						  proc_msg_gc_acrypto);
		}
		break;
#endif
#if MT_SAB_KEY_GEN_EXT
	case SAB_KEY_GENERATE_EXT_REQ:
		if (msg_type == MT_SAB_KEY_GEN_EXT) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_KEY_GEN_EXT,
						  prepare_msg_gen_key_ext,
						  proc_msg_rsp_gen_key_ext);
		}
		break;
#endif
#if MT_SAB_IMPORT_KEY
	case SAB_IMPORT_KEY_REQ:
		if (msg_type == MT_SAB_IMPORT_KEY) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_IMPORT_KEY,
						  prepare_msg_importkey,
						  proc_msg_rsp_importkey);
		}
		break;
#endif
#if MT_SAB_DELETE_KEY
	case SAB_DELETE_KEY_REQ:
		if (msg_type == MT_SAB_DELETE_KEY) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_DELETE_KEY,
						  prepare_msg_del_key,
						  proc_msg_rsp_del_key);
		}
		break;
#endif
#if MT_SAB_MANAGE_KEY
	case SAB_MANAGE_KEY_REQ:
		if (msg_type == MT_SAB_MANAGE_KEY) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_MANAGE_KEY,
						  prepare_msg_managekey,
						  proc_msg_rsp_managekey);
		}
		break;
	case SAB_MANAGE_KEY_EXT_REQ:
		if (msg_type == MT_SAB_MANAGE_KEY) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_MANAGE_KEY,
						  prepare_msg_managekey_ext,
						  proc_msg_rsp_managekey);
		}
		break;
#endif
#if MT_SAB_GET_KEY_ATTR
	case SAB_GET_KEY_ATTR_REQ:
		if (msg_type == MT_SAB_GET_KEY_ATTR) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_GET_KEY_ATTR,
						  prepare_msg_get_key_attr,
						  proc_msg_rsp_get_key_attr);
		}
		break;
#endif
#if MT_SAB_RNG
#ifndef PSA_COMPLIANT
	case SAB_RNG_OPEN_REQ:
		if (msg_type == MT_SAB_RNG) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_RNG,
						  prepare_msg_rng_open_req,
						  proc_msg_rsp_rng_open_req);
		}
		break;
	case SAB_RNG_CLOSE_REQ:
		if (msg_type == MT_SAB_RNG) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_RNG,
						  prepare_msg_rng_close_req,
						  proc_msg_rsp_rng_close_req);
		}
		break;
#endif
	case SAB_RNG_GET_RANDOM:
		if (msg_type == MT_SAB_RNG) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_RNG,
						  prepare_msg_get_rng,
						  proc_msg_rsp_get_rng);
		}
		break;
#endif
#if MT_SAB_MAC
	case SAB_MAC_OPEN_REQ:
		if (msg_type == MT_SAB_MAC) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_MAC,
						  prepare_msg_mac_open_req,
						  proc_msg_rsp_mac_open_req);
		}
		break;
	case SAB_MAC_CLOSE_REQ:
		if (msg_type == MT_SAB_MAC) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_MAC,
						  prepare_msg_mac_close_req,
						  proc_msg_rsp_mac_close_req);
		}
		break;
	case SAB_MAC_ONE_GO_REQ:
		if (msg_type == MT_SAB_MAC) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_MAC,
						  prepare_msg_mac_one_go,
						  proc_msg_rsp_mac_one_go);
		}
		break;
#endif
#if MT_SAB_CIPHER
	case SAB_CIPHER_OPEN_REQ:
		if (msg_type == MT_SAB_CIPHER) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_CIPHER,
						  prepare_msg_cipher_open_req,
						  proc_msg_rsp_cipher_open_req);
		}
		break;
	case SAB_CIPHER_CLOSE_REQ:
		if (msg_type == MT_SAB_CIPHER) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_CIPHER,
						  prepare_msg_cipher_close_req,
						  proc_msg_rsp_cipher_close_req);
		}
		break;
	case SAB_CIPHER_ONE_GO_REQ:
		if (msg_type == MT_SAB_CIPHER) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_CIPHER,
						  prepare_msg_cipher_one_go,
						  proc_msg_rsp_cipher_one_go);
		}
		break;
#endif
#if MT_SAB_SESSION
	case SAB_SESSION_OPEN_REQ:
		if (msg_type == MT_SAB_SESSION) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_SESSION,
						  prepare_msg_session_open_req,
						  proc_msg_rsp_session_open_req);
		}
		break;
	case SAB_SESSION_CLOSE_REQ:
		if (msg_type == MT_SAB_SESSION) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_SESSION,
						  prepare_msg_session_close_req,
						  proc_msg_rsp_session_close_req);
		}
		break;
#endif
#if MT_SAB_KEY_STORE
	case SAB_KEY_STORE_OPEN_REQ:
		if (msg_type == MT_SAB_KEY_STORE) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_KEY_STORE,
						  prepare_msg_key_store_open_req,
						  proc_msg_rsp_key_store_open_req);
		}
		break;
	case SAB_KEY_STORE_CLOSE_REQ:
		if (msg_type == MT_SAB_KEY_STORE) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_KEY_STORE,
						  prepare_msg_key_store_close_req,
						  proc_msg_rsp_key_store_close_req);
		}
		break;
#endif
#if MT_SAB_KEY_MANAGEMENT
	case SAB_KEY_MANAGEMENT_OPEN_REQ:
		if (msg_type == MT_SAB_KEY_MANAGEMENT) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_KEY_MANAGEMENT,
						  prepare_msg_key_management_open_req,
						  proc_msg_rsp_key_management_open_req);
		}
		break;
	case SAB_KEY_MANAGEMENT_CLOSE_REQ:
		if (msg_type == MT_SAB_KEY_MANAGEMENT) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_KEY_MANAGEMENT,
						  prepare_msg_key_management_close_req,
						  proc_msg_rsp_key_management_close_req);
		}
		break;
#endif
#if MT_SAB_DATA_STORAGE
	case SAB_DATA_STORAGE_OPEN_REQ:
		if (msg_type == MT_SAB_DATA_STORAGE) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_DATA_STORAGE,
						  prepare_msg_data_storage_open_req,
						  proc_msg_rsp_data_storage_open_req);
		}
		break;
	case SAB_DATA_STORAGE_CLOSE_REQ:
		if (msg_type == MT_SAB_DATA_STORAGE) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_DATA_STORAGE,
						  prepare_msg_data_storage_close_req,
						  proc_msg_rsp_data_storage_close_req);
		}
		break;
	case SAB_DATA_STORAGE_REQ:
		if (msg_type == MT_SAB_DATA_STORAGE) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_DATA_STORAGE,
						  prepare_msg_data_storage,
						  proc_msg_rsp_data_storage);
		}
		break;
#if MT_SAB_ENC_DATA_STORAGE
	case SAB_ENC_DATA_STORAGE_REQ:
		if (msg_type == MT_SAB_ENC_DATA_STORAGE) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_ENC_DATA_STORAGE,
						  prepare_msg_enc_data_storage,
						  proc_msg_rsp_enc_data_storage);
		}
		break;
#endif
#endif
#if MT_SAB_HASH_GEN
#ifndef PSA_COMPLIANT
	case SAB_HASH_OPEN_REQ:
		if (msg_type == MT_SAB_HASH_GEN) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_HASH_GEN,
						  prepare_msg_hash_open_req,
						  proc_msg_rsp_hash_open_req);
		}
		break;
	case SAB_HASH_CLOSE_REQ:
		if (msg_type == MT_SAB_HASH_GEN) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_HASH_GEN,
						  prepare_msg_hash_close_req,
						  proc_msg_rsp_hash_close_req);
		}
		break;
#endif
	case SAB_HASH_ONE_GO_REQ:
		if (msg_type == MT_SAB_HASH_GEN) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_HASH_GEN,
						  prepare_msg_hash_one_go,
						  proc_msg_rsp_hash_one_go);
		}
		break;
#endif
#if MT_SAB_SIGN_GEN
	case SAB_SIGNATURE_GENERATION_OPEN_REQ:
		if (msg_type == MT_SAB_SIGN_GEN) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_SIGN_GEN,
						  prepare_msg_sign_gen_open,
						  proc_msg_rsp_sign_gen_open);
		}
		break;
	case SAB_SIGNATURE_GENERATION_CLOSE_REQ:
		if (msg_type == MT_SAB_SIGN_GEN) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_SIGN_GEN,
						  prepare_msg_sign_gen_close,
						  proc_msg_rsp_sign_gen_close);
		}
		break;
	case SAB_SIGNATURE_GENERATE_REQ:
		if (msg_type == MT_SAB_SIGN_GEN) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_SIGN_GEN,
						  prepare_msg_sign_generate,
						  proc_msg_rsp_sign_generate);
		}
		break;
#endif
#if MT_SAB_SIGN_PREPARE
	case SAB_SIGNATURE_PREPARE_REQ:
		if (msg_type == MT_SAB_SIGN_PREPARE) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_SIGN_PREPARE,
						  prepare_msg_prep_signature,
						  proc_msg_rsp_prep_signature);
		}
		break;
#endif
#if MT_SAB_VERIFY_SIGN
	case SAB_SIGNATURE_VERIFICATION_OPEN_REQ:
		if (msg_type == MT_SAB_VERIFY_SIGN) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_VERIFY_SIGN,
						  prepare_msg_verify_sign_open,
						  proc_msg_rsp_verify_sign_open);
		}
		break;
	case SAB_SIGNATURE_VERIFICATION_CLOSE_REQ:
		if (msg_type == MT_SAB_VERIFY_SIGN) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_VERIFY_SIGN,
						  prepare_msg_verify_sign_close,
						  proc_msg_rsp_verify_sign_close);
		}
		break;
	case SAB_SIGNATURE_VERIFY_REQ:
		if (msg_type == MT_SAB_VERIFY_SIGN) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_VERIFY_SIGN,
						  prepare_msg_verify_sign,
						  proc_msg_rsp_verify_sign);
		}
		break;
#endif
#if MT_SAB_ROOT_KEK_EXPORT
	case SAB_ROOT_KEK_EXPORT_REQ:
		if (msg_type == MT_SAB_ROOT_KEK_EXPORT) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_ROOT_KEK_EXPORT,
						  prepare_msg_root_kek_export,
						  proc_msg_rsp_root_kek_export);
		}
		break;
#endif
#if MT_SAB_KEY_RECOVERY
	case SAB_PUB_KEY_RECOVERY_REQ:
		if (msg_type == MT_SAB_KEY_RECOVERY) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_KEY_RECOVERY,
						  prepare_msg_key_recovery,
						  proc_msg_rsp_key_recovery);
		}
		break;
#endif
#if MT_SAB_AUTH_ENC
	case SAB_AUTH_ENC_REQ:
		if (msg_type == MT_SAB_AUTH_ENC) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_AUTH_ENC,
						  prepare_msg_auth_enc,
						  proc_msg_rsp_auth_enc);
		}
		break;
#endif
#if MT_SAB_KEY_GENERIC_CRYPTO
	case SAB_KEY_GENERIC_CRYPTO_SRV_OPEN_REQ:
		if (msg_type == MT_SAB_KEY_GENERIC_CRYPTO) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_KEY_GENERIC_CRYPTO,
						  prepare_msg_key_generic_crypto_open,
						  proc_msg_rsp_key_generic_crypto_open);
		}
		break;
	case SAB_KEY_GENERIC_CRYPTO_SRV_CLOSE_REQ:
		if (msg_type == MT_SAB_KEY_GENERIC_CRYPTO) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_KEY_GENERIC_CRYPTO,
						  prepare_msg_key_generic_crypto_close,
						  proc_msg_rsp_key_generic_crypto_close);
		}
		break;
	case SAB_KEY_GENERIC_CRYPTO_SRV_REQ:
		if (msg_type == MT_SAB_KEY_GENERIC_CRYPTO) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_KEY_GENERIC_CRYPTO,
						  prepare_msg_key_generic_crypto,
						  proc_msg_rsp_key_generic_crypto);
		}
		break;
#endif
#if MT_SAB_PUB_KEY_DECOMPRESSION
	case SAB_PUB_KEY_DECOMPRESSION_REQ:
		if (msg_type == MT_SAB_PUB_KEY_DECOMPRESSION) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_PUB_KEY_DECOMPRESSION,
						  prepare_msg_pub_key_decompression,
						  proc_msg_rsp_pub_key_decompression);
		}
		break;
#endif
#if MT_SAB_ST_BUT
	case SAB_ST_BUT_KEY_EXP_REQ:
		if (msg_type == MT_SAB_ST_BUT) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_ST_BUT,
						  prepare_msg_st_butterfly,
						  proc_msg_rsp_st_butterfly);
		}
		break;
#endif
#if MT_SAB_BUT
	case SAB_BUT_KEY_EXP_REQ:
		if (msg_type == MT_SAB_BUT) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_BUT,
						  prepare_msg_butterfly,
						  proc_msg_rsp_butterfly);
		}
		break;
#endif
#if MT_SAB_ECIES
	case SAB_ECIES_ENC_REQ:
		if (msg_type == MT_SAB_ECIES) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_ECIES,
						  prepare_msg_ecies_encryption,
						  proc_msg_rsp_ecies_encryption);
		}
		break;
	case SAB_CIPHER_ECIES_DECRYPT_REQ:
		if (msg_type == MT_SAB_ECIES) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_ECIES,
						  prepare_msg_ecies_decryption,
						  proc_msg_rsp_ecies_decryption);
		}
		break;
#endif
#if MT_SAB_SM2_ECES
	case SAB_SM2_ECES_DEC_OPEN_REQ:
		if (msg_type == MT_SAB_SM2_ECES) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_SM2_ECES,
						  prepare_msg_sm2_eces_open_req,
						  proc_msg_rsp_sm2_eces_open_req);
		}
		break;
	case SAB_SM2_ECES_DEC_CLOSE_REQ:
		if (msg_type == MT_SAB_SM2_ECES) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_SM2_GET_Z,
						  prepare_msg_sm2_eces_close_req,
						  proc_msg_rsp_sm2_eces_close_req);
		}
		break;
	case SAB_SM2_ECES_ENC_REQ:
		if (msg_type == MT_SAB_SM2_ECES) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_SM2_ECES,
						  prepare_msg_sm2_eces_encryption,
						  proc_msg_rsp_sm2_eces_encryption);
		}
		break;
	case SAB_SM2_ECES_DEC_REQ:
		if (msg_type == MT_SAB_SM2_ECES) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_SM2_ECES,
						  prepare_msg_sm2_eces_decryption,
						  proc_msg_rsp_sm2_eces_decryption);
		}
		break;
#endif
#if MT_SAB_SM2_GET_Z
	case SAB_SM2_GET_Z_REQ:
		if (msg_type == MT_SAB_SM2_GET_Z) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_SM2_GET_Z,
						  prepare_msg_sm2_get_z,
						  proc_msg_rsp_sm2_get_z);
		}
		break;
#endif
#if MT_SAB_KEY_EXCHANGE
	case SAB_KEY_EXCHANGE_REQ:
		if (msg_type == MT_SAB_KEY_EXCHANGE) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_KEY_EXCHANGE,
						  prepare_msg_key_exchange,
						  proc_msg_rsp_key_exchange);
		}
		break;
#endif
	default:
		break;
	}

	return ret;
}

void init_sab_hsm_msg_engine(msg_type_t msg_type)
{
	if ((msg_type > NOT_SUPPORTED) && (msg_type >= MAX_MSG_TYPE))
		return;

	switch (msg_type) {
	case 1:
		init_proc_sab_msg_cmd_eng(msg_type, SAB_MSG_MAX_ID,
					  init_proc_sab_base_msg_engine);
		break;
	case 2:
		init_proc_sab_msg_cmd_eng(msg_type, SAB_MSG_MAX_ID,
					  init_proc_sab_hsm_msg_engine);
		break;
	default: return;
	}
}
