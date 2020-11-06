/*
 * Copyright 2020 NXP
 *
 * NXP Confidential.
 * This software is owned or controlled by NXP and may only be used strictly
 * in accordance with the applicable license terms.  By expressly accepting
 * such terms or by downloading, installing, activating and/or otherwise using
 * the software, you are agreeing that you have read, and that you agree to
 * comply with and are bound by, such license terms.  If you do not agree to be
 * bound by the applicable license terms, then you may not retain, install,
 * activate or otherwise use the software.
 */

#include "hsm_api.h"
#include "seco_nvm.h"
#include <pthread.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>


static uint8_t  SM2_test_message[300] = {
    // Note that the first 32 Bytes are the "Z" value that can be retrieved with hsm_sm2_get_z()
    0xB2, 0xE1, 0x4C, 0x5C, 0x79, 0xC6, 0xDF, 0x5B, 0x85, 0xF4, 0xFE, 0x7E, 0xD8, 0xDB, 0x7A, 0x26,
    0x2B, 0x9D, 0xA7, 0xE0, 0x7C, 0xCB, 0x0E, 0xA9, 0xF4, 0x74, 0x7B, 0x8C, 0xCD, 0xA8, 0xA4, 0xF3,
    0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20, 0xB2, 0xE1, 0x4C, 0x5C, 0x79, 0xC6, 0xDF, 0x5B,
    0x85, 0xF4, 0xFE, 0x7E, 0xD8, 0xDB, 0x7A, 0x26, 0x2B, 0x9D, 0xA7, 0xE0, 0x7C, 0xCB, 0x0E, 0xA9,
    0xF4, 0x74, 0x7B, 0x8C, 0xCD, 0xA8, 0xA4, 0xF3, 0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20,
    0xB2, 0xE1, 0x4C, 0x5C, 0x79, 0xC6, 0xDF, 0x5B, 0x85, 0xF4, 0xFE, 0x7E, 0xD8, 0xDB, 0x7A, 0x26,
    0x2B, 0x9D, 0xA7, 0xE0, 0x7C, 0xCB, 0x0E, 0xA9, 0xF4, 0x74, 0x7B, 0x8C, 0xCD, 0xA8, 0xA4, 0xF3,
    0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20, 0xB2, 0xE1, 0x4C, 0x5C, 0x79, 0xC6, 0xDF, 0x5B,
    0x85, 0xF4, 0xFE, 0x7E, 0xD8, 0xDB, 0x7A, 0x26, 0x2B, 0x9D, 0xA7, 0xE0, 0x7C, 0xCB, 0x0E, 0xA9,
    0xF4, 0x74, 0x7B, 0x8C, 0xCD, 0xA8, 0xA4, 0xF3, 0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20,
    0xB2, 0xE1, 0x4C, 0x5C, 0x79, 0xC6, 0xDF, 0x5B, 0x85, 0xF4, 0xFE, 0x7E, 0xD8, 0xDB, 0x7A, 0x26,
    0x2B, 0x9D, 0xA7, 0xE0, 0x7C, 0xCB, 0x0E, 0xA9, 0xF4, 0x74, 0x7B, 0x8C, 0xCD, 0xA8, 0xA4, 0xF3,
    0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20, 0xB2, 0xE1, 0x4C, 0x5C, 0x79, 0xC6, 0xDF, 0x5B,
    0x85, 0xF4, 0xFE, 0x7E, 0xD8, 0xDB, 0x7A, 0x26, 0x2B, 0x9D, 0xA7, 0xE0, 0x7C, 0xCB, 0x0E, 0xA9,
    0xF4, 0x74, 0x7B, 0x8C, 0xCD, 0xA8, 0xA4, 0xF3, 0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20,
    0xB2, 0xE1, 0x4C, 0x5C, 0x79, 0xC6, 0xDF, 0x5B, 0x85, 0xF4, 0xFE, 0x7E, 0xD8, 0xDB, 0x7A, 0x26,
    0x2B, 0x9D, 0xA7, 0xE0, 0x7C, 0xCB, 0x0E, 0xA9, 0xF4, 0x74, 0x7B, 0x8C, 0xCD, 0xA8, 0xA4, 0xF3,
    0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20, 0xB2, 0xE1, 0x4C, 0x5C, 0x79, 0xC6, 0xDF, 0x5B,
    0x85, 0xF4, 0xFE, 0x7E, 0xD8, 0xDB, 0x7A, 0x26, 0x2B, 0x9D, 0xA7, 0xE0,
};

static uint8_t SM3_HASH[32] = {
    0x52, 0x1d, 0xa1, 0x93, 0x21, 0xcb, 0x3a, 0xfc, 0xb5, 0x13, 0x25, 0x45, 0x7f, 0x8f, 0x15, 0x89,
    0xdc, 0x60, 0xfa, 0xf0, 0x87, 0xf2, 0xcf, 0x8f, 0xf3, 0xe2, 0x8d, 0x8b, 0xde, 0x28, 0x97, 0x8e, 
};

static uint8_t ECDSA_SigVer_SM2_Q[64] = {
    0x09, 0xF9, 0xDF, 0x31, 0x1E, 0x54, 0x21, 0xA1, 0x50, 0xDD, 0x7D, 0x16, 0x1E, 0x4B, 0xC5, 0xC6,
    0x72, 0x17, 0x9F, 0xAD, 0x18, 0x33, 0xFC, 0x07, 0x6B, 0xB0, 0x8F, 0xF3, 0x56, 0xF3, 0x50, 0x20,
    0xCC, 0xEA, 0x49, 0x0C, 0xE2, 0x67, 0x75, 0xA5, 0x2D, 0xC6, 0xEA, 0x71, 0x8C, 0xC1, 0xAA, 0x60,
    0x0A, 0xED, 0x05, 0xFB, 0xF3, 0x5E, 0x08, 0x4A, 0x66, 0x32, 0xF6, 0x07, 0x2D, 0xA9, 0xAD, 0x13
};
 
static uint8_t SM2_IDENTIFIER[16] = {
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38
};

static uint8_t SM2_PUBK[64] = {
    0x09, 0xF9, 0xDF, 0x31, 0x1E, 0x54, 0x21, 0xA1, 0x50, 0xDD, 0x7D, 0x16, 0x1E, 0x4B, 0xC5, 0xC6,
    0x72, 0x17, 0x9F, 0xAD, 0x18, 0x33, 0xFC, 0x07, 0x6B, 0xB0, 0x8F, 0xF3, 0x56, 0xF3, 0x50, 0x20,
    0xCC, 0xEA, 0x49, 0x0C, 0xE2, 0x67, 0x75, 0xA5, 0x2D, 0xC6, 0xEA, 0x71, 0x8C, 0xC1, 0xAA, 0x60,
    0x0A, 0xED, 0x05, 0xFB, 0xF3, 0x5E, 0x08, 0x4A, 0x66, 0x32, 0xF6, 0x07, 0x2D, 0xA9, 0xAD, 0x13
};

static uint8_t SM2_Z[32] = {
    0xB2, 0xE1, 0x4C, 0x5C, 0x79, 0xC6, 0xDF, 0x5B, 0x85, 0xF4, 0xFE, 0x7E, 0xD8, 0xDB, 0x7A, 0x26,
    0x2B, 0x9D, 0xA7, 0xE0, 0x7C, 0xCB, 0x0E, 0xA9, 0xF4, 0x74, 0x7B, 0x8C, 0xCD, 0xA8, 0xA4, 0xF3
};

static uint8_t gcm_auth_data[16] = {
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38
};

static uint8_t iv_gcm[16] = {
    0x18, 0x33, 0x23, 0x01, 0xFF, 0x99, 0x72, 0x1A, 0xBB, 0xEF, 0xA3, 0x22
};

uint8_t ecies_input[16] = {
    0x91, 0x69, 0x15, 0x5B, 0x08, 0xB0, 0x76, 0x74, 0xCB, 0xAD, 0xF7, 0x5F, 0xB4, 0x6A, 0x7B, 0x0D
};

uint8_t ecies_p1[32] = {
    0xA6, 0xB7, 0xB5, 0x25, 0x54, 0xB4, 0x20, 0x3F, 0x7E, 0x3A, 0xCF, 0xDB, 0x3A, 0x3E, 0xD8, 0x67,
    0x4E, 0xE0, 0x86, 0xCE, 0x59, 0x06, 0xA7, 0xCA, 0xC2, 0xF8, 0xA3, 0x98, 0x30, 0x6D, 0x3B, 0xE9
};

uint8_t ecc_p256_pubk[2*32] = {
    0x1c, 0xcb, 0xe9, 0x1c, 0x07, 0x5f, 0xc7, 0xf4, 0xf0, 0x33, 0xbf, 0xa2, 0x48, 0xdb, 0x8f, 0xcc,
    0xd3, 0x56, 0x5d, 0xe9, 0x4b, 0xbf, 0xb1, 0x2f, 0x3c, 0x59, 0xff, 0x46, 0xc2, 0x71, 0xbf, 0x83,
    0xce, 0x40, 0x14, 0xc6, 0x88, 0x11, 0xf9, 0xa2, 0x1a, 0x1f, 0xdb, 0x2c, 0x0e, 0x61, 0x13, 0xe0,
    0x6d, 0xb7, 0xca, 0x93, 0xb7, 0x40, 0x4e, 0x78, 0xdc, 0x7c, 0xcd, 0x5c, 0xa8, 0x9a, 0x4c, 0xa9
};

uint8_t sm2_ke_input[2*64] = {
    // initiator static public key
    0x6A, 0xE8, 0x48, 0xC5, 0x7C, 0x53, 0xC7, 0xB1, 0xB5, 0xFA, 0x99, 0xEB, 0x22, 0x86, 0xAF, 0x07,
    0x8B, 0xA6, 0x4C, 0x64, 0x59, 0x1B, 0x8B, 0x56, 0x6F, 0x73, 0x57, 0xD5, 0x76, 0xF1, 0x6D, 0xFB,
    0xEE, 0x48, 0x9D, 0x77, 0x16, 0x21, 0xA2, 0x7B, 0x36, 0xC5, 0xC7, 0x99, 0x20, 0x62, 0xE9, 0xCD,
    0x09, 0xA9, 0x26, 0x43, 0x86, 0xF3, 0xFB, 0xEA, 0x54, 0xDF, 0xF6, 0x93, 0x05, 0x62, 0x1C, 0x4D,
    // initiator ephemeral public key
    0x16, 0x0E, 0x12, 0x89, 0x7D, 0xF4, 0xED, 0xB6, 0x1D, 0xD8, 0x12, 0xFE, 0xB9, 0x67, 0x48, 0xFB,
    0xD3, 0xCC, 0xF4, 0xFF, 0xE2, 0x6A, 0xA6, 0xF6, 0xDB, 0x95, 0x40, 0xAF, 0x49, 0xC9, 0x42, 0x32,
    0x4A, 0x7D, 0xAD, 0x08, 0xBB, 0x9A, 0x45, 0x95, 0x31, 0x69, 0x4B, 0xEB, 0x20, 0xAA, 0x48, 0x9D,
    0x66, 0x49, 0x97, 0x5E, 0x1B, 0xFC, 0xF8, 0xC4, 0x74, 0x1B, 0x78, 0xB4, 0xB2, 0x23, 0x00, 0x7F
};

uint8_t sm2_kdf_input[2*32] = {
    // Za
    0xB2, 0xE1, 0x4C, 0x5C, 0x79, 0xC6, 0xDF, 0x5B, 0x85, 0xF4, 0xFE, 0x7E, 0xD8, 0xDB, 0x7A, 0x26,
    0x2B, 0x9D, 0xA7, 0xE0, 0x7C, 0xCB, 0x0E, 0xA9, 0xF4, 0x74, 0x7B, 0x8C, 0xCD, 0xA8, 0xA4, 0xF3,
    // Zb
    0xB5 ,0x24 ,0xF5 ,0x52 ,0xCD ,0x82 ,0xB8 ,0xB0 ,0x28 ,0x47 ,0x6E ,0x00 ,0x5C ,0x37 ,0x7F ,0xB1,
    0x9A ,0x87 ,0xE6 ,0xFC ,0x68 ,0x2D ,0x48 ,0xBB ,0x5D ,0x42 ,0xE3 ,0xD9 ,0xB9 ,0xEF ,0xFE ,0x76,
};

uint8_t work_area[128] = {0};
uint8_t work_area2[128] = {0};
uint8_t work_area3[128] = {0};
uint8_t work_area4[128] = {0};

static uint32_t nvm_status;

static void *v2x_hsm_storage_thread(void *arg)
{
    seco_nvm_manager(NVM_FLAGS_V2X | NVM_FLAGS_HSM, &nvm_status);
}


typedef struct {
    char *tag;
    hsm_hdl_t key_mgmt_srv;
    hsm_hdl_t sig_gen_serv;
    hsm_hdl_t sig_ver_serv;
    uint8_t *sig_area;
    uint8_t *pubk_area;
} sig_thread_args_t;

static void *sig_loop_thread(void *arg)
{

    op_generate_sign_args_t sig_gen_args;
    op_verify_sign_args_t sig_ver_args;
    op_generate_key_args_t gen_key_args;
    uint32_t key_id = 0;
    hsm_verification_status_t status;
    hsm_err_t err;
    int i, success, failed;

    sig_thread_args_t *args = (sig_thread_args_t *)arg;
    if (!args)
        return NULL;

    success = 0;
    failed = 0;
    for (i=0 ; i<200; i++) {
        /* generate and verify a SM2 signature - use alternatively create and update flags. */
        gen_key_args.key_identifier = &key_id;
        gen_key_args.out_size = 64;
        gen_key_args.flags = ((i%4 == 0) ? HSM_OP_KEY_GENERATION_FLAGS_CREATE : HSM_OP_KEY_GENERATION_FLAGS_UPDATE);
        gen_key_args.key_type = HSM_KEY_TYPE_DSA_SM2_FP_256;
        gen_key_args.key_group = 12;
        gen_key_args.key_info = 0U;
        gen_key_args.out_key = args->pubk_area;
        err = hsm_generate_key(args->key_mgmt_srv, &gen_key_args);
        // printf("%s err: 0x%x hsm_generate_key err: hdl: 0x%08x\n", args->tag, err, args->key_mgmt_srv);

        sig_gen_args.key_identifier = key_id;
        sig_gen_args.message = SM2_test_message;
        sig_gen_args.signature = args->sig_area;
        sig_gen_args.message_size = 300;
        sig_gen_args.signature_size = 65;
        sig_gen_args.scheme_id = 0x43;
        sig_gen_args.flags = HSM_OP_GENERATE_SIGN_FLAGS_INPUT_MESSAGE; 
        err = hsm_generate_signature(args->sig_gen_serv, &sig_gen_args);
        // printf("%s err: 0x%x hsm_generate_signature hdl: 0x%08x\n", args->tag, err, args->sig_gen_serv);

        sig_ver_args.key = args->pubk_area;
        sig_ver_args.message = SM2_test_message;
        sig_ver_args.signature = args->sig_area;
        sig_ver_args.key_size = 64;
        sig_ver_args.signature_size = 65;
        sig_ver_args.message_size = 300;
        sig_ver_args.scheme_id = 0x43;
        sig_ver_args.flags = HSM_OP_PREPARE_SIGN_INPUT_MESSAGE;
        err = hsm_verify_signature(args->sig_ver_serv, &sig_ver_args, &status);
        // printf("%s err: 0x%x hsm_verify_signature hdl: 0x%08x status: 0x%x\n", args->tag, err, args->sig_ver_serv, status);
        if (status == HSM_VERIFICATION_STATUS_SUCCESS) {
            success++;
            // printf(" --> SUCCESS\n");
        } else {
            failed++;
            // printf(" --> FAILURE\n");
        }
    }
    printf("%s success: %d / failures: %d\n", args->tag, success, failed);

    pthread_exit(NULL);
    return NULL;
}

typedef struct {
    char *tag;
    hsm_hdl_t key_mgmt_srv;
    hsm_hdl_t cipher_hdl;
    uint8_t *cipher_area;
    uint8_t *clear_area;
} cipher_thread_args_t;

static void *cipher_loop_thread(void *arg)
{

    op_cipher_one_go_args_t cipher_args;
    op_generate_key_args_t gen_key_args;
    uint32_t key_id = 0;;
    hsm_verification_status_t status;
    hsm_err_t err;
    int i, success, failed;

    cipher_thread_args_t *args = (cipher_thread_args_t *)arg;
    if (!args)
        return NULL;

    success = 0;
    failed = 0;
    for (i=0 ; i<200; i++) {
        memset(args->cipher_area, 0, 128);
        memset(args->clear_area, 0, 128);
        /* generate and verify a SM2 signature - use alternatively create and update flags. */
        gen_key_args.key_identifier = &key_id;
        gen_key_args.out_size = 0;
        gen_key_args.flags = ((i%4 == 0) ? HSM_OP_KEY_GENERATION_FLAGS_CREATE : HSM_OP_KEY_GENERATION_FLAGS_UPDATE);
        gen_key_args.key_type = HSM_KEY_TYPE_SM4_128;
        gen_key_args.key_group = 14;
        gen_key_args.key_info = 0U;
        gen_key_args.out_key = NULL;
        err = hsm_generate_key(args->key_mgmt_srv, &gen_key_args);
        // printf("%s err: 0x%x hsm_generate_key hdl: 0x%08x\n", args->tag, err, args->key_mgmt_srv);
   
        cipher_args.key_identifier = key_id;
        cipher_args.iv = ((i%2 == 0) ? SM2_IDENTIFIER : NULL); // just need 16 bytes somewhere to be used as IV
        cipher_args.iv_size = ((i%2 == 0) ? 16 : 0);
        cipher_args.cipher_algo = ((i%2 == 0) ? HSM_CIPHER_ONE_GO_ALGO_SM4_CBC : HSM_CIPHER_ONE_GO_ALGO_SM4_ECB);
        cipher_args.flags = HSM_CIPHER_ONE_GO_FLAGS_ENCRYPT;
        cipher_args.input = SM2_test_message;
        cipher_args.output = args->cipher_area;
        cipher_args.input_size = 128;
        cipher_args.output_size = 128;
        hsm_cipher_one_go(args->cipher_hdl, &cipher_args);
        // printf("%s err: 0x%x hsm_cipher_one_go ENCRYPT hdl: 0x%08x\n", args->tag, err, args->cipher_hdl);

        cipher_args.flags = HSM_CIPHER_ONE_GO_FLAGS_DECRYPT;
        cipher_args.input = args->cipher_area;
        cipher_args.output = args->clear_area;
        // other args unchanged
        hsm_cipher_one_go(args->cipher_hdl, &cipher_args);
        // printf("%s err: 0x%x hsm_cipher_one_go DECRYPT hdl: 0x%08x\n", args->tag, err, args->cipher_hdl);

        if (memcmp(SM2_test_message, args->clear_area, 128) == 0) {
            success++;
            // printf(" --> SUCCESS\n");
        } else {
            failed++;
            // printf(" --> FAILURE\n");
        }
    }
    printf("%s success: %d / failures: %d\n", args->tag, success, failed);

    pthread_exit(NULL);
    return NULL;
}


int main(int argc, char *argv[])
{
    open_session_args_t args;

    open_svc_hash_args_t hash_srv_args;
    open_svc_key_store_args_t key_store_srv_args;
    open_svc_key_management_args_t key_mgmt_srv_args;
    open_svc_sign_gen_args_t sig_gen_srv_args;
    open_svc_sign_ver_args_t sig_ver_srv_args;
    open_svc_cipher_args_t cipher_srv_args;
    open_svc_rng_args_t rng_srv_args;

    op_hash_one_go_args_t hash_args;
    op_sm2_get_z_args_t get_z_args;
    op_sm2_eces_enc_args_t sm2_eces_enc_args;

    open_svc_sm2_eces_args_t sm2_eces_dec_svc_args;
    op_sm2_eces_dec_args_t sm2_eces_dec_args;
    op_get_random_args_t rng_get_random_args;
    op_auth_enc_args_t auth_enc_args;
    op_manage_key_args_t mng_key_args;
    op_ecies_enc_args_t op_ecies_enc_args;
    op_ecies_dec_args_t op_ecies_dec_args;

    hsm_hdl_t sg0_sess, sv0_sess;
    hsm_hdl_t sg1_sess, sv1_sess;
    hsm_hdl_t sg0_key_store_serv, sg0_sig_gen_serv, sg0_key_mgmt_srv, sg0_cipher_hdl;
    hsm_hdl_t sg1_key_store_serv, sg1_sig_gen_serv, sg1_key_mgmt_srv, sg1_cipher_hdl;
    hsm_hdl_t sv0_rng_serv, sv1_rng_serv, sg0_rng_serv, sg1_rng_serv;
    hsm_hdl_t sv0_sig_ver_serv;
    hsm_hdl_t sv1_sig_ver_serv;
    hsm_hdl_t hash_serv;
    hsm_hdl_t sg0_sm2_eces_hdl, sg1_sm2_eces_hdl;

    op_generate_key_args_t gen_key_args;
    uint32_t key_id = 0;
    uint32_t key_id_sm4 = 0;

    hsm_verification_status_t status;
    hsm_err_t err;
    int j;
    pthread_t tid, sig1, sig2;
    sig_thread_args_t args1, args2;
    cipher_thread_args_t cipher_args1, cipher_args2;
    op_pub_key_recovery_args_t pub_k_rec_args;

    op_key_exchange_args_t key_exch;
    op_cipher_one_go_args_t cipher_args;

    open_svc_mac_args_t mac_srv_args;
    hsm_hdl_t sg0_mac_hdl;
    op_mac_one_go_args_t mac_one_go;
    hsm_mac_verification_status_t mac_status;

    uint8_t recovered_key[256];
    uint8_t rng_out_buff[4096];

    srand (time (NULL));

    printf("\n---------------------------------------------------\n");
    printf("Starting storage manager \n");
    printf("---------------------------------------------------\n");
    nvm_status = NVM_STATUS_UNDEF;

    (void)pthread_create(&tid, NULL, v2x_hsm_storage_thread, NULL);

    /* Wait for the storage manager to be ready to receive commands from V2X. */
    while (nvm_status <= NVM_STATUS_STARTING) {
        usleep(1000);
    }
    /* Check if it ended because of an error. */
    if (nvm_status == NVM_STATUS_STOPPED) {
        printf("nvm manager failed to start\n");
        return 1;
    }
    printf("nvm manager started: status: 0x%x \n", nvm_status);


    // SG0
    printf("\n---------------------------------------------------\n");
    printf("Opening sessions \n");
    printf("---------------------------------------------------\n");
    args.session_priority = HSM_OPEN_SESSION_PRIORITY_HIGH;
    args.operating_mode = HSM_OPEN_SESSION_LOW_LATENCY_MASK;
    err = hsm_open_session(&args, &sg0_sess);
    printf("err: 0x%x SG0 hsm_open_session session_hdl: 0x%08x\n", err, sg0_sess);

    // SV0
    args.session_priority = HSM_OPEN_SESSION_PRIORITY_HIGH;
    args.operating_mode = HSM_OPEN_SESSION_LOW_LATENCY_MASK | HSM_OPEN_SESSION_NO_KEY_STORE_MASK;
    err = hsm_open_session(&args, &sv0_sess);
    printf("err: 0x%x SV0 hsm_open_session session_hdl: 0x%08x\n", err, sv0_sess);

    // SG1
    args.session_priority = HSM_OPEN_SESSION_PRIORITY_LOW;
    args.operating_mode = HSM_OPEN_SESSION_LOW_LATENCY_MASK;
    err = hsm_open_session(&args, &sg1_sess);
    printf("err: 0x%x SG1 hsm_open_session session_hdl: 0x%08x\n", err, sg1_sess);

    // //SV1
    args.session_priority = HSM_OPEN_SESSION_PRIORITY_LOW;
    args.operating_mode = HSM_OPEN_SESSION_LOW_LATENCY_MASK | HSM_OPEN_SESSION_NO_KEY_STORE_MASK;
    err = hsm_open_session(&args, &sv1_sess);
    printf("err: 0x%x SV1 hsm_open_session session_hdl: 0x%08x\n", err, sv1_sess);


    // opening services for signature generation/verif on SG0 and SG1

    key_store_srv_args.key_store_identifier = 1234;
    key_store_srv_args.authentication_nonce = 1234;
    key_store_srv_args.max_updates_number = 12;
    key_store_srv_args.flags = HSM_SVC_KEY_STORE_FLAGS_CREATE;
    key_store_srv_args.signed_message = NULL;
    key_store_srv_args.signed_msg_size = 0;
    err = hsm_open_key_store_service(sg0_sess, &key_store_srv_args, &sg0_key_store_serv);
    if (err != HSM_NO_ERROR) {
        /* key store may already exist. */
        key_store_srv_args.flags = 0U;
        err = hsm_open_key_store_service(sg0_sess, &key_store_srv_args, &sg0_key_store_serv);
    }
    printf("err: 0x%x hsm_open_key_store_service hdl: 0x%08x\n", err, sg0_key_store_serv);

    key_store_srv_args.key_store_identifier = 5678;
    key_store_srv_args.authentication_nonce = 5678;
    key_store_srv_args.flags = HSM_SVC_KEY_STORE_FLAGS_CREATE;
    err = hsm_open_key_store_service(sg1_sess, &key_store_srv_args, &sg1_key_store_serv);
    if (err != HSM_NO_ERROR) {
        /* key store may already exist. */
        key_store_srv_args.flags = 0U;
        err = hsm_open_key_store_service(sg1_sess, &key_store_srv_args, &sg1_key_store_serv);
    }
    printf("err: 0x%x hsm_open_key_store_service hdl: 0x%08x\n", err, sg1_key_store_serv);

    key_mgmt_srv_args.flags = 0;
    err = hsm_open_key_management_service(sg0_key_store_serv, &key_mgmt_srv_args, &sg0_key_mgmt_srv);
    printf("err: 0x%x hsm_open_key_management_service err: hdl: 0x%08x\n", err, sg0_key_mgmt_srv);
    err = hsm_open_key_management_service(sg1_key_store_serv, &key_mgmt_srv_args, &sg1_key_mgmt_srv);
    printf("err: 0x%x hsm_open_key_management_service err: hdl: 0x%08x\n", err, sg1_key_mgmt_srv);


    sig_gen_srv_args.flags = 0;
    err = hsm_open_signature_generation_service(sg0_key_store_serv, &sig_gen_srv_args, &sg0_sig_gen_serv);
    printf("err: 0x%x hsm_open_signature_generation_service err: hdl: 0x%08x\n", err, sg0_sig_gen_serv);
    err = hsm_open_signature_generation_service(sg1_key_store_serv, &sig_gen_srv_args, &sg1_sig_gen_serv);
    printf("err: 0x%x hsm_open_signature_generation_service err: hdl: 0x%08x\n", err, sg1_sig_gen_serv);

    sig_ver_srv_args.flags = 0;
    err = hsm_open_signature_verification_service(sv0_sess, &sig_ver_srv_args, &sv0_sig_ver_serv);
    printf("err: 0x%x hsm_open_signature_verification_service err: hdl: 0x%08x\n", err, sv0_sig_ver_serv);
    err = hsm_open_signature_verification_service(sv1_sess, &sig_ver_srv_args, &sv1_sig_ver_serv);
    printf("err: 0x%x hsm_open_signature_verification_service err: hdl: 0x%08x\n", err, sv1_sig_ver_serv);


    // SM2 signature test: generate a signature and verify it
    //
    printf("\n---------------------------------------------------\n");
    printf("SM2 signature generation and verification in parallel\n");
    printf("---------------------------------------------------\n");
    args1.tag = "HIGH_P";
    args1.key_mgmt_srv = sg0_key_mgmt_srv;
    args1.sig_gen_serv = sg0_sig_gen_serv;
    args1.sig_ver_serv = sv0_sig_ver_serv;
    args1.sig_area = work_area;
    args1.pubk_area = work_area2;
    (void)pthread_create(&sig1, NULL, sig_loop_thread, &args1);
    printf("started signature High prio thread\n");

    args2.tag = "LOW_P ";
    args2.key_mgmt_srv = sg1_key_mgmt_srv;
    args2.sig_gen_serv = sg1_sig_gen_serv;
    args2.sig_ver_serv = sv1_sig_ver_serv;
    args2.sig_area = work_area3;
    args2.pubk_area = work_area4;
    (void)pthread_create(&sig2, NULL, sig_loop_thread, &args2);
    printf("started signature Low prio thread\n");

    pthread_join(sig1, NULL);
    printf("completed signature High prio thread\n");

    pthread_join(sig2, NULL);
    printf("completed signature Low prio thread\n");

    // RNG srv tests
    printf("\n---------------------------------------------------\n");
    printf("RNG test\n");
    printf("---------------------------------------------------\n");
    rng_srv_args.flags = 0;
    err = hsm_open_rng_service(sv0_sess, &rng_srv_args, &sv0_rng_serv);
    printf("err: 0x%x hsm_open_rng_service hdl: 0x%08x\n", err, sv0_rng_serv);
    err = hsm_open_rng_service(sv1_sess, &rng_srv_args, &sv1_rng_serv);
    printf("err: 0x%x hsm_open_rng_service hdl: 0x%08x\n", err, sv1_rng_serv);
    err = hsm_open_rng_service(sg0_sess, &rng_srv_args, &sg0_rng_serv);
    printf("err: 0x%x hsm_open_rng_service hdl: 0x%08x\n", err, sg0_rng_serv);
    err = hsm_open_rng_service(sg1_sess, &rng_srv_args, &sg1_rng_serv);
    printf("err: 0x%x hsm_open_rng_service hdl: 0x%08x\n", err, sg1_rng_serv);

    rng_get_random_args.output = rng_out_buff;
    rng_get_random_args.random_size = 3;
    err =  hsm_get_random(sv0_rng_serv, &rng_get_random_args);
    printf("err: 0x%x hsm_get_random hdl: 0x%08x, rand size=0x%08x\n", err, sv0_rng_serv, rng_get_random_args.random_size);
    rng_get_random_args.random_size = 176;
    err =  hsm_get_random(sv1_rng_serv, &rng_get_random_args);
    printf("err: 0x%x hsm_get_random hdl: 0x%08x, rand size=0x%08x\n", err, sv1_rng_serv, rng_get_random_args.random_size);
    rng_get_random_args.random_size = 2050;
    err =  hsm_get_random(sg0_rng_serv, &rng_get_random_args);
    printf("err: 0x%x hsm_get_random hdl: 0x%08x, rand size=0x%08x\n", err, sg0_rng_serv, rng_get_random_args.random_size);
    rng_get_random_args.random_size = 4096;
    err =  hsm_get_random(sg1_rng_serv, &rng_get_random_args);
    printf("err: 0x%x hsm_get_random hdl: 0x%08x, rand size=0x%08x\n", err, sg1_rng_serv, rng_get_random_args.random_size);

    // SM3 hash test

    printf("\n---------------------------------------------------\n");
    printf("SM3 hash test\n");
    printf("---------------------------------------------------\n");
    hash_srv_args.flags = 0;
    err = hsm_open_hash_service(sv0_sess, &hash_srv_args, &hash_serv);
    printf("err: 0x%x hsm_open_hash_service hdl: 0x%08x\n", err, hash_serv);

    hash_args.input = SM2_test_message;
    hash_args.output = work_area;
    hash_args.input_size = sizeof(SM2_test_message);
    hash_args.output_size = 128;
    hash_args.algo = 0x11;
    hash_args.flags = 0;

    err = hsm_hash_one_go(hash_serv, &hash_args);
    printf("err: 0x%x hsm_hash_one_go hdl: 0x%08x\n", err, hash_serv);
    printf("SM3 output:\n");
    for (j=0; j<32; j++) {
        printf("0x%02x ", work_area[j]);
        if (j%16 == 15)
            printf("\n");
    }
    if (memcmp(SM3_HASH, work_area, sizeof(SM3_HASH)) == 0) {
        printf(" --> SUCCESS\n");
    } else {
        printf(" --> FAILURE\n");
    }

    printf("\n---------------------------------------------------\n");
    printf("SM2 get Z test\n");
    printf("---------------------------------------------------\n");
    get_z_args.public_key = SM2_PUBK;
    get_z_args.identifier = SM2_IDENTIFIER;
    get_z_args.z_value = work_area;
    get_z_args.public_key_size = 64;
    get_z_args.id_size = 16;
    get_z_args.z_size = 32;
    get_z_args.key_type = HSM_KEY_TYPE_DSA_SM2_FP_256;
    get_z_args.flags = 0;

    err = hsm_sm2_get_z(sv0_sess, &get_z_args);
    printf("err: 0x%x hsm_sm2_get_z hdl: 0x%08x\n", err, sv0_sess);
    printf("Z output:\n");
    for (j=0; j<32; j++) {
        printf("0x%02x ", work_area[j]);
        if (j%16 == 15)
            printf("\n");
    }
    if (memcmp(SM2_Z, work_area, sizeof(SM2_Z)) == 0) {
        printf(" --> SUCCESS\n");
    } else {
        printf(" --> FAILURE\n");
    }

    // SM4 test
    printf("\n---------------------------------------------------\n");
    printf("SM4 encrypt/decrypt test\n");
    printf("---------------------------------------------------\n");
    cipher_srv_args.flags = 0U;
    err = hsm_open_cipher_service(sg0_key_store_serv, &cipher_srv_args, &sg0_cipher_hdl);
    printf("err: 0x%x hsm_open_cipher_service err: hdl: 0x%08x\n", err, sg0_cipher_hdl);
    err = hsm_open_cipher_service(sg1_key_store_serv, &cipher_srv_args, &sg1_cipher_hdl);
    printf("err: 0x%x hsm_open_cipher_service err: hdl: 0x%08x\n", err, sg1_cipher_hdl);

    cipher_args1.tag = "HIGH_P";
    cipher_args1.key_mgmt_srv = sg0_key_mgmt_srv;
    cipher_args1.cipher_hdl = sg0_cipher_hdl;
    cipher_args1.cipher_area = work_area;
    cipher_args1.clear_area = work_area2;
    (void)pthread_create(&sig1, NULL, cipher_loop_thread, &cipher_args1);
    printf("started cipher High prio thread\n");

    cipher_args2.tag = "LOW_P ";
    cipher_args2.key_mgmt_srv = sg1_key_mgmt_srv;
    cipher_args2.cipher_hdl = sg1_cipher_hdl;
    cipher_args2.cipher_area = work_area3;
    cipher_args2.clear_area = work_area4;
    (void)pthread_create(&sig2, NULL, cipher_loop_thread, &cipher_args2);
    printf("started cipher Low prio thread\n");

    pthread_join(sig1, NULL);
    printf("completed cipher High prio thread\n");

    pthread_join(sig2, NULL);
    printf("completed cipher Low prio thread\n");

    // SM2 eces encrypt and decrypt
    printf("\n---------------------------------------------------\n");
    printf("SM2 ECES test\n");
    printf("---------------------------------------------------\n");

    sm2_eces_dec_svc_args.flags = 0U;
    err = hsm_open_sm2_eces_service(sg0_key_store_serv, &sm2_eces_dec_svc_args, &sg0_sm2_eces_hdl);
    printf("err: 0x%x hsm_open_sm2_eces_service err: hdl: 0x%08x\n", err, sg0_sm2_eces_hdl);
    err = hsm_open_sm2_eces_service(sg1_key_store_serv, &sm2_eces_dec_svc_args, &sg1_sm2_eces_hdl);
    printf("err: 0x%x hsm_open_sm2_eces_service err: hdl: 0x%08x\n", err, sg1_sm2_eces_hdl);

    gen_key_args.key_identifier = &key_id;
    gen_key_args.out_size = 64;
    gen_key_args.flags = HSM_OP_KEY_GENERATION_FLAGS_CREATE;
    gen_key_args.key_type = HSM_KEY_TYPE_DSA_SM2_FP_256;
    gen_key_args.key_group = 12;
    gen_key_args.key_info = 0U;
    gen_key_args.out_key = work_area2; // public key needed for the encryption
    err = hsm_generate_key(sg0_key_mgmt_srv, &gen_key_args);
    printf("err: 0x%x hsm_generate_key err: hdl: 0x%08x\n", err, sg0_key_mgmt_srv);

    sm2_eces_enc_args.input = SM2_test_message;
    sm2_eces_enc_args.output = work_area;
    sm2_eces_enc_args.pub_key = work_area2;
    sm2_eces_enc_args.input_size = 16;
    sm2_eces_enc_args.output_size = 128; // aligned with 32 bits - ciphertext size = align(plaintext_size + 97)
    sm2_eces_enc_args.pub_key_size = 64;
    sm2_eces_enc_args.key_type = HSM_KEY_TYPE_DSA_SM2_FP_256;
    sm2_eces_enc_args.flags = 0;

    err = hsm_sm2_eces_encryption(sg0_sess, &sm2_eces_enc_args);
    printf("err: 0x%x hsm_sm2_eces_encryption hdl: 0x%08x\n", err, sv0_sess);
    printf("output:\n"); // we need to decrypt it with the associated private key to check if the result is correct
    for (j=0; j<8; j++) {
        printf("0x%02x ", work_area[j]);
    }
    printf("\n");

    sm2_eces_dec_args.input = work_area;
    sm2_eces_dec_args.output = work_area3; //plaintext
    sm2_eces_dec_args.key_identifier = key_id;
    sm2_eces_dec_args.input_size = 113;
    sm2_eces_dec_args.output_size = 16;
    sm2_eces_dec_args.key_type = HSM_KEY_TYPE_DSA_SM2_FP_256;
    sm2_eces_dec_args.flags = 0;

    err = hsm_sm2_eces_decryption(sg0_sm2_eces_hdl, &sm2_eces_dec_args);
    printf("err: 0x%x hsm_sm2_eces_decryption hdl: 0x%08x\n", err, sg0_sm2_eces_hdl);

    if (memcmp(SM2_test_message, work_area3, 16) == 0) {
        printf(" --> SUCCESS\n");
    } else {
        printf(" --> FAILURE\n");
    }

    printf("\n---------------------------------------------------\n");
    printf("Public key recovery\n");
    printf("---------------------------------------------------\n");

    pub_k_rec_args.key_identifier = key_id;
    pub_k_rec_args.out_key = recovered_key;
    pub_k_rec_args.out_key_size = 64;
    pub_k_rec_args.key_type = HSM_KEY_TYPE_DSA_SM2_FP_256;
    pub_k_rec_args.flags = 0;

    err = hsm_pub_key_recovery(sg0_key_store_serv, &pub_k_rec_args);
    printf("err: 0x%x hsm_pub_key_recovery\n", err);
    if (memcmp(recovered_key, work_area2, 64) == 0) {
        printf(" --> SUCCESS\n");
    } else {
        printf(" --> FAILURE\n");
    }

    printf("\n---------------------------------------------------\n");
    printf("AES_128 auth encryption\n");
    printf("---------------------------------------------------\n");
    gen_key_args.key_identifier = &key_id;
    gen_key_args.out_size = 0;
    gen_key_args.flags = HSM_OP_KEY_GENERATION_FLAGS_CREATE;
    gen_key_args.key_type = HSM_KEY_TYPE_AES_128;
    gen_key_args.key_group = 12;
    gen_key_args.key_info = 0U;
    gen_key_args.out_key = NULL;

    err = hsm_generate_key(sg0_key_mgmt_srv, &gen_key_args);
    printf("err: 0x%x hsm_generate_key err: hdl: 0x%08x\n", err, sg0_key_mgmt_srv);

    // AUTH ENC KEY AES128 -> ENCRYPT
    auth_enc_args.key_identifier = key_id;
    auth_enc_args.iv = iv_gcm;
    auth_enc_args.iv_size = 12U;
    auth_enc_args.aad = gcm_auth_data;
    auth_enc_args.aad_size = 16U;
    auth_enc_args.ae_algo = HSM_AUTH_ENC_ALGO_AES_GCM;
    auth_enc_args.flags = HSM_AUTH_ENC_FLAGS_ENCRYPT;
    auth_enc_args.input = SM2_test_message;
    auth_enc_args.output = work_area;
    auth_enc_args.input_size = 64;
    auth_enc_args.output_size = 64 + 16;
    err = hsm_auth_enc(sg0_cipher_hdl, &auth_enc_args);
    printf("err: 0x%x hsm_auth data encrypt\n", err);

    // AUTH ENC KEY AES128 -> DECRYPT
    auth_enc_args.key_identifier = key_id;
    auth_enc_args.iv = iv_gcm;
    auth_enc_args.iv_size = 12U;
    auth_enc_args.aad = gcm_auth_data;
    auth_enc_args.aad_size = 16U;
    auth_enc_args.ae_algo = HSM_AUTH_ENC_ALGO_AES_GCM;
    auth_enc_args.flags = HSM_AUTH_ENC_FLAGS_DECRYPT;
    auth_enc_args.input = work_area;
    auth_enc_args.output = work_area2;
    auth_enc_args.input_size = 64 + 16;
    auth_enc_args.output_size = 64;
    err = hsm_auth_enc(sg0_cipher_hdl, &auth_enc_args);
    printf("err: 0x%x hsm_auth data encrypt\n", err);
    // CHECK DECRYPTED OUTPUT
    if (memcmp(SM2_test_message, work_area2, 64) == 0) {
        printf(" --> SUCCESS\n");
    } else {
        printf(" --> FAILURE\n");
    }
    
    // Close all services and sessions
    printf("\n---------------------------------------------------\n");
    printf("ḱey deletion test\n");
    printf("---------------------------------------------------\n");

    /* Test deletion of last generated key. */
    mng_key_args.key_identifier = &key_id;
    mng_key_args.kek_identifier = 0;
    mng_key_args.input_size = 0;
    mng_key_args.flags = HSM_OP_MANAGE_KEY_FLAGS_DELETE;
    mng_key_args.key_type = HSM_KEY_TYPE_DSA_SM2_FP_256;
    mng_key_args.key_group = 12;
    mng_key_args.key_info = 0;
    mng_key_args.input_data = NULL;

    err = hsm_manage_key(sg0_key_mgmt_srv, &mng_key_args);
    printf("err: 0x%x hsm_manage_key hdl: 0x%08x\n", err, sg0_key_mgmt_srv);

    /* Try to use again this key: an error is expected. */
    sm2_eces_dec_args.input = work_area;
    sm2_eces_dec_args.output = work_area3; //plaintext
    sm2_eces_dec_args.key_identifier = key_id;
    sm2_eces_dec_args.input_size = 113;
    sm2_eces_dec_args.output_size = 16;
    sm2_eces_dec_args.key_type = HSM_KEY_TYPE_DSA_SM2_FP_256;
    sm2_eces_dec_args.flags = 0;

    err = hsm_sm2_eces_decryption(sg0_sm2_eces_hdl, &sm2_eces_dec_args);
    printf("err: 0x%x hsm_sm2_eces_decryption hdl: 0x%08x\n", err, sg0_sm2_eces_hdl);
    if (err == HSM_UNKNOWN_ID) {
        printf("error expected --> SUCCESS\n");
    } else {
        printf("unexpected error code --> FAILURE\n");
    }

    printf("\n---------------------------------------------------\n");
    printf("ecies test\n");
    printf("---------------------------------------------------\n");

    gen_key_args.key_identifier = &key_id;
    gen_key_args.out_size = 64;
    gen_key_args.flags = HSM_OP_KEY_GENERATION_FLAGS_CREATE;
    gen_key_args.key_type = HSM_KEY_TYPE_ECDSA_NIST_P256;
    gen_key_args.key_group = 12;
    gen_key_args.key_info = 0U;
    gen_key_args.out_key = work_area2; // public key needed for the encryption
    err = hsm_generate_key(sg0_key_mgmt_srv, &gen_key_args);
    printf("err: 0x%x hsm_generate_key err: hdl: 0x%08x\n", err, sg0_key_mgmt_srv);

    op_ecies_enc_args.input = ecies_input;
    op_ecies_enc_args.pub_key = work_area2;
    op_ecies_enc_args.p1 = ecies_p1;
    op_ecies_enc_args.p2 = NULL;
    op_ecies_enc_args.output = work_area;
    op_ecies_enc_args.input_size = 16;
    op_ecies_enc_args.p1_size = 32;
    op_ecies_enc_args.p2_size = 0;
    op_ecies_enc_args.pub_key_size = 2*32;
    op_ecies_enc_args.mac_size = 16;
    op_ecies_enc_args.out_size = 3*32;
    op_ecies_enc_args.key_type = HSM_KEY_TYPE_ECDSA_NIST_P256;
    op_ecies_enc_args.flags = 0u;
    op_ecies_enc_args.reserved= 0u;
    err = hsm_ecies_encryption(sg0_sess, &op_ecies_enc_args);
    printf("err: 0x%x hsm_ecies_encryption err: hdl: 0x%08x\n", err, sg0_key_mgmt_srv);
    printf("output:\n"); // we need to decrypt it with the associated private key to check if the result is correct
    for (j=0; j<3*32; j++) {
        printf("0x%02x ", work_area[j]);
        if (j%16 == 15) printf("\n");
    }
    printf("\n");

    op_ecies_dec_args.key_identifier = key_id;
    op_ecies_dec_args.input = work_area;
    op_ecies_dec_args.p1 = ecies_p1;
    op_ecies_dec_args.p2 = NULL;
    op_ecies_dec_args.output = work_area3;
    op_ecies_dec_args.input_size = 3*32;
    op_ecies_dec_args.output_size = 16;
    op_ecies_dec_args.p1_size = 32;
    op_ecies_dec_args.p2_size = 0;
    op_ecies_dec_args.mac_size = 16;
    op_ecies_dec_args.key_type = HSM_KEY_TYPE_ECDSA_NIST_P256;
    op_ecies_dec_args.flags = 0;
    err = hsm_ecies_decryption(sg0_cipher_hdl, &op_ecies_dec_args);
    printf("err: 0x%x hsm_ecies_decryption err: hdl: 0x%08x\n", err, sg0_cipher_hdl);

    if (memcmp(ecies_input, work_area3, 16) == 0) {
        printf(" --> SUCCESS\n");
    } else {
        printf(" --> FAILURE\n");
    }


    // Key exchange to create a KEK
    printf("\n---------------------------------------------------\n");
    printf("Key exchange KEK derivation \n");
    printf("---------------------------------------------------\n");
    key_exch.key_identifier =0;
    key_exch.shared_key_identifier_array = work_area2;
    key_exch.ke_input = ecc_p256_pubk;
    key_exch.ke_output = work_area3;
    key_exch.kdf_input = 0;
    key_exch.kdf_output = 0;
    key_exch.shared_key_group = 32;
    key_exch.shared_key_info = HSM_KEY_INFO_KEK;
    key_exch.shared_key_type = HSM_KEY_TYPE_AES_256;
    key_exch.initiator_public_data_type = HSM_KEY_TYPE_ECDSA_NIST_P256;
    key_exch.key_exchange_scheme = HSM_KE_SCHEME_ECDH_NIST_P256;
    key_exch.kdf_algorithm = HSM_KDF_ONE_STEP_SHA_256;
    key_exch.ke_input_size = 64;
    key_exch.ke_output_size = 64;
    key_exch.shared_key_identifier_array_size = 4;
    key_exch.kdf_input_size = 0;
    key_exch.kdf_output_size = 0;
    key_exch.flags = HSM_OP_KEY_EXCHANGE_FLAGS_CREATE | HSM_OP_KEY_EXCHANGE_FLAGS_USE_EPHEMERAL;

    err = hsm_key_exchange(sg0_key_mgmt_srv, &key_exch);
    printf("err: 0x%x hsm_key_exchange err hdl: 0x%08x\n", err, sg0_key_mgmt_srv);

    printf("Receiver pubk:\n");
    for (j=0; j<64; j++) {
        printf("0x%02x ", work_area3[j]);
        if (j%16 == 15)
            printf("\n");
    }


    // SM2 Key exchange
    printf("\n---------------------------------------------------\n");
    printf("SM2 Key exchange \n");
    printf("---------------------------------------------------\n");

    gen_key_args.key_identifier = &key_id;
    gen_key_args.out_size = 64;
    gen_key_args.flags = HSM_OP_KEY_GENERATION_FLAGS_CREATE;
    gen_key_args.key_type = HSM_KEY_TYPE_DSA_SM2_FP_256;
    gen_key_args.key_group = 12;
    gen_key_args.key_info = 0U;
    gen_key_args.out_key = work_area2;
    err = hsm_generate_key(sg0_key_mgmt_srv, &gen_key_args);
    printf("err: 0x%x hsm_generate_key err: hdl: 0x%08x\n", err, sg0_key_mgmt_srv);

    key_exch.key_identifier = key_id;
    key_exch.shared_key_identifier_array = (uint8_t *)&key_id_sm4;
    key_exch.ke_input = sm2_ke_input;
    key_exch.ke_output = work_area3;
    key_exch.kdf_input = sm2_kdf_input; // Za|| Zb
    key_exch.kdf_output = 0;
    key_exch.shared_key_group = 12;
    key_exch.shared_key_info = 0;
    key_exch.shared_key_type = HSM_KEY_TYPE_SM4_128;
    key_exch.initiator_public_data_type = HSM_KEY_TYPE_DSA_SM2_FP_256;
    key_exch.key_exchange_scheme = HSM_KE_SCHEME_SM2_FP_256;
    key_exch.kdf_algorithm = HSM_KDF_ALG_FOR_SM2;
    key_exch.ke_input_size = 64 *2;
    key_exch.ke_output_size = 64 * 2;
    key_exch.shared_key_identifier_array_size = 4;
    key_exch.kdf_input_size = 32*2;
    key_exch.kdf_output_size = 0;
    key_exch.flags = HSM_OP_KEY_EXCHANGE_FLAGS_CREATE;

    err = hsm_key_exchange(sg0_key_mgmt_srv, &key_exch);
    printf("err: 0x%x hsm_key_exchange err hdl: 0x%08x\n", err, sg0_key_mgmt_srv);

    printf("Receiver pubk:\n");
    for (j=0; j<64; j++) {
        printf("0x%02x ", work_area3[j]);
        if (j%16 == 15)
            printf("\n");
    }

    printf("Derived key_id 0x%08x\n", key_id_sm4);

    // SM4 test with the derived key
    printf("\n---------------------------------------------------\n");
    printf("SM4 encrypt test with derived key \n");
    printf("---------------------------------------------------\n");
    cipher_srv_args.flags = 0U;
    err = hsm_open_cipher_service(sg0_key_store_serv, &cipher_srv_args, &sg0_cipher_hdl);
    printf("err: 0x%x hsm_open_cipher_service err: hdl: 0x%08x\n", err, sg0_cipher_hdl);

    cipher_args.key_identifier = key_id_sm4;
    cipher_args.iv = 0;
    cipher_args.iv_size = 0;
    cipher_args.cipher_algo = HSM_CIPHER_ONE_GO_ALGO_SM4_ECB;
    cipher_args.flags = HSM_CIPHER_ONE_GO_FLAGS_ENCRYPT;
    cipher_args.input = SM2_test_message;
    cipher_args.output = work_area3;
    cipher_args.input_size = 16;
    cipher_args.output_size = 16;
    err = hsm_cipher_one_go(sg0_cipher_hdl, &cipher_args);
    printf("err: 0x%x hsm_cipher_one_go SM4 ENCRYPT hdl: 0x%08x\n", err, sg0_cipher_hdl);

    key_exch.key_identifier = key_id;
    key_exch.shared_key_identifier_array = work_area2;
    key_exch.ke_input = sm2_ke_input;
    key_exch.ke_output = work_area3;
    key_exch.kdf_input = sm2_kdf_input; // Za|| Zb
    key_exch.kdf_output = 0;
    key_exch.shared_key_group = 12;
    key_exch.shared_key_info = 0;
    key_exch.shared_key_type = HSM_KEY_TYPE_DSA_SM2_FP_256;
    key_exch.initiator_public_data_type = HSM_KEY_TYPE_DSA_SM2_FP_256;
    key_exch.key_exchange_scheme = HSM_KE_SCHEME_SM2_FP_256;
    key_exch.kdf_algorithm = HSM_KDF_ALG_FOR_SM2;
    key_exch.ke_input_size = 64 *2;
    key_exch.ke_output_size = 64 * 2;
    key_exch.shared_key_identifier_array_size = 4;
    key_exch.kdf_input_size = 32*2;
    key_exch.kdf_output_size = 0;
    key_exch.flags = HSM_OP_KEY_EXCHANGE_FLAGS_CREATE | HSM_OP_KEY_EXCHANGE_FLAGS_STRICT_OPERATION;

    err = hsm_key_exchange(sg0_key_mgmt_srv, &key_exch);
    printf("err: 0x%x hsm_key_exchange err hdl: 0x%08x\n", err, sg0_key_mgmt_srv);

    printf("Receiver pubk:\n");
    for (j=0; j<64; j++) {
        printf("0x%02x ", work_area3[j]);
        if (j%16 == 15)
            printf("\n");
    }

    // mac test
    printf("\n---------------------------------------------------\n");
    printf("MAC ONE GO Test \n");
    printf("---------------------------------------------------\n");
    mac_srv_args.flags = 0u;
    err = hsm_open_mac_service(sg0_key_store_serv, &mac_srv_args, &sg0_mac_hdl);
    printf("err: 0x%x hsm_open_mac_service err: hdl: 0x%08x\n", err, sg0_mac_hdl);

    gen_key_args.key_identifier = &key_id;
    gen_key_args.out_size = 0U;
    gen_key_args.flags = HSM_OP_KEY_GENERATION_FLAGS_CREATE;
    gen_key_args.key_type = HSM_KEY_TYPE_AES_256;
    gen_key_args.key_group = 12;
    gen_key_args.key_info = 0U;
    gen_key_args.out_key = NULL;
    err = hsm_generate_key(sg0_key_mgmt_srv, &gen_key_args);
    printf("err: 0x%x hsm_generate_key err: hdl: 0x%08x\n", err, sg0_key_mgmt_srv);

    mac_one_go.key_identifier = key_id;
    mac_one_go.algorithm = HSM_OP_MAC_ONE_GO_ALGO_AES_CMAC;
    mac_one_go.flags = HSM_OP_MAC_ONE_GO_FLAGS_MAC_GENERATION;
    mac_one_go.payload = SM2_test_message;
    mac_one_go.mac = work_area2;
    mac_one_go.payload_size = 32u;
    mac_one_go.mac_size = 16u;
    err = hsm_mac_one_go(sg0_mac_hdl, &mac_one_go, &mac_status);
    printf("err: 0x%x hsm_mac_one_go GEN hdl: 0x%08x\n", err, sg0_mac_hdl);

    mac_one_go.key_identifier = key_id;
    mac_one_go.algorithm = HSM_OP_MAC_ONE_GO_ALGO_AES_CMAC;
    mac_one_go.flags = HSM_OP_MAC_ONE_GO_FLAGS_MAC_VERIFICATION;
    mac_one_go.payload = SM2_test_message;
    mac_one_go.mac = work_area2;
    mac_one_go.payload_size = 32u;
    mac_one_go.mac_size = 8u;
    err = hsm_mac_one_go(sg0_mac_hdl, &mac_one_go, &mac_status);
    printf("err: 0x%x hsm_mac_one_go VER hdl: 0x%08x\n", err, sg0_mac_hdl);

    if (mac_status == HSM_MAC_VERIFICATION_STATUS_SUCCESS) {
        printf(" --> SUCCESS\n");
    } else {
        printf(" --> FAILURE\n");
    }

    // Close all services and sessions
    printf("\n---------------------------------------------------\n");
    printf("Closing services and sessions\n");
    printf("---------------------------------------------------\n");

    err = hsm_close_hash_service(hash_serv);
    printf("err: 0x%x hsm_close_hash_service hdl: 0x%08x\n", err, hash_serv);

    err = hsm_close_signature_verification_service(sv0_sig_ver_serv);
    printf("err: 0x%x hsm_close_signature_verification_service hdl: 0x%08x\n", err, sv0_sig_ver_serv);
    err = hsm_close_signature_verification_service(sv1_sig_ver_serv);
    printf("err: 0x%x hsm_close_signature_verification_service hdl: 0x%08x\n", err, sv1_sig_ver_serv);

    err = hsm_close_signature_generation_service(sg0_sig_gen_serv);
    printf("err: 0x%x hsm_close_signature_generation_service hdl: 0x%08x\n", err, sg0_sig_gen_serv);
    err = hsm_close_signature_generation_service(sg1_sig_gen_serv);
    printf("err: 0x%x hsm_close_signature_generation_service hdl: 0x%08x\n", err, sg1_sig_gen_serv);

    err = hsm_close_sm2_eces_service(sg0_sm2_eces_hdl);
    printf("err: 0x%x hsm_close_sm2_eces_service hdl: 0x%08x\n", err, sg0_sm2_eces_hdl);
    err = hsm_close_sm2_eces_service(sg1_sm2_eces_hdl);
    printf("err: 0x%x hsm_close_sm2_eces_service hdl: 0x%08x\n", err, sg1_sm2_eces_hdl);

    err = hsm_close_mac_service(sg0_mac_hdl);
    printf("err: 0x%x hsm_close_mac_service hdl: 0x%x\n", err, sg0_mac_hdl);

    err = hsm_close_key_management_service(sg0_key_mgmt_srv);
    printf("err: 0x%x hsm_close_key_management_service hdl: 0x%x\n", err, sg0_key_mgmt_srv);
    err = hsm_close_key_management_service(sg1_key_mgmt_srv);
    printf("err: 0x%x hsm_close_key_management_service hdl: 0x%x\n", err, sg1_key_mgmt_srv);

    err = hsm_close_key_store_service(sg0_key_store_serv);
    printf("err: 0x%x hsm_close_key_store_service hdl: 0x%08x\n", err, sg0_key_store_serv);
    err = hsm_close_key_store_service(sg1_key_store_serv);
    printf("err: 0x%x hsm_close_key_store_service hdl: 0x%08x\n", err, sg1_key_store_serv);

    err = hsm_close_rng_service(sv0_rng_serv);
    printf("err: 0x%x hsm_close_rng_service hdl: 0x%x\n", err, sv0_rng_serv);
    err = hsm_close_rng_service(sv1_rng_serv);
    printf("err: 0x%x hsm_close_rng_service hdl: 0x%x\n", err, sv1_rng_serv);

    err = hsm_close_rng_service(sg0_rng_serv);
    printf("err: 0x%x hsm_close_rng_service hdl: 0x%x\n", err, sg0_rng_serv);
    err = hsm_close_rng_service(sg1_rng_serv);
    printf("err: 0x%x hsm_close_rng_service hdl: 0x%x\n", err, sg1_rng_serv);

    err = hsm_close_session(sg0_sess);
    printf("err: 0x%x SG hsm_close_session hdl: 0x%x\n", err, sg0_sess);

    err = hsm_close_session(sv0_sess);
    printf("err: 0x%x SV hsm_close_session hdl: 0x%x\n", err, sv0_sess);

    err = hsm_close_session(sg1_sess);
    printf("err: 0x%x SG hsm_close_session hdl: 0x%x\n", err, sg1_sess);

    err = hsm_close_session(sv1_sess);
    printf("err: 0x%x SV hsm_close_session hdl: 0x%x\n", err, sv1_sess);

    if (nvm_status != NVM_STATUS_STOPPED) {
        pthread_cancel(tid);
    }
    seco_nvm_close_session();

    return 0;
}
