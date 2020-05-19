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


uint8_t work_area[128] = {0};

static uint32_t nvm_status;

static void *v2x_hsm_storage_thread(void *arg)
{
    seco_nvm_manager(NVM_FLAGS_V2X | NVM_FLAGS_HSM, &nvm_status);
}


int main(int argc, char *argv[])
{
    open_session_args_t args;
    open_svc_sign_ver_args_t sv_args;
    open_svc_hash_args_t hash_srv_args;
    open_svc_key_store_args_t key_store_srv_args;
    open_svc_sign_gen_args_t sig_gen_srv_args;
    op_generate_sign_args_t sig_gen_args;
    open_svc_sign_ver_args_t sig_ver_srv_args;
    op_verify_sign_args_t sig_ver_args;
    op_hash_one_go_args_t hash_args;
    op_sm2_get_z_args_t get_z_args;

    hsm_hdl_t sg0_sess, sg1_sess, sv0_sess, sv1_sess;
    hsm_hdl_t key_store_serv, sig_ver_serv, sig_gen_serv, hash_serv;

    hsm_verification_status_t status;
    hsm_err_t err;
    int j;
    pthread_t tid;

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


    // Open session on all MUs (even if all are not really used here)

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

    //SV1
    args.session_priority = HSM_OPEN_SESSION_PRIORITY_LOW;
    args.operating_mode = HSM_OPEN_SESSION_LOW_LATENCY_MASK | HSM_OPEN_SESSION_NO_KEY_STORE_MASK;
    err = hsm_open_session(&args, &sv1_sess);
    printf("err: 0x%x SV1 hsm_open_session session_hdl: 0x%08x\n", err, sv1_sess);


    // SM2 signature test: generate a signature and verify it
    //
    // Note that V2X currently uses an hardcoded private key
    // Corresponding public key is used here for verification
    printf("\n---------------------------------------------------\n");
    printf("SM2 signature generation and verification\n");
    printf("---------------------------------------------------\n");
    key_store_srv_args.key_store_identifier = 0;
    key_store_srv_args.authentication_nonce = 0;
    key_store_srv_args.max_updates_number = 0;
    key_store_srv_args.flags = 0;
    key_store_srv_args.signed_message = NULL;
    key_store_srv_args.signed_msg_size = 0;
    err = hsm_open_key_store_service(sg0_sess, &key_store_srv_args, &key_store_serv);
    printf("err: 0x%x hsm_open_key_store_service hdl: 0x%08x\n", err, key_store_serv);

    sig_gen_srv_args.flags = 0;
    err = hsm_open_signature_generation_service(key_store_serv, &sig_gen_srv_args, &sig_gen_serv);
    printf("err: 0x%x hsm_open_signature_generation_service err: hdl: 0x%08x\n", err, sig_gen_serv);

    sig_ver_srv_args.flags = 0;
    err = hsm_open_signature_verification_service(sv0_sess, &sig_ver_srv_args, &sig_ver_serv);
    printf("err: 0x%x hsm_open_signature_verification_service err: hdl: 0x%08x\n", err, sig_ver_serv);

    sig_gen_args.key_identifier = 0;
    sig_gen_args.message = SM2_test_message;
    sig_gen_args.signature = work_area;
    sig_gen_args.message_size = 300;
    sig_gen_args.signature_size = 65;
    sig_gen_args.scheme_id = 0x43;
    sig_gen_args.flags = HSM_OP_GENERATE_SIGN_FLAGS_INPUT_MESSAGE; 
    err = hsm_generate_signature(sig_gen_serv, &sig_gen_args);
    printf("err: 0x%x hsm_generate_signature hdl: 0x%08x\n", err, sig_gen_serv);

    printf("signature:\n");
    for (j=0; j<64; j++) {
        printf("0x%02x ", work_area[j]);
        if (j%16 == 15)
            printf("\n");
    }

    sig_ver_args.key = ECDSA_SigVer_SM2_Q;
    sig_ver_args.message = SM2_test_message;
    sig_ver_args.signature = work_area;
    sig_ver_args.key_size = 64;
    sig_ver_args.signature_size = 64;
    sig_ver_args.message_size = 300;
    sig_ver_args.scheme_id = 0x43;
    sig_ver_args.flags = HSM_OP_PREPARE_SIGN_INPUT_MESSAGE;
    // printf("%s hsm_verify_signature iteration %d  hdl: 0x%08x\n", mu_name[i], j, serv_hdl[i]);
    err = hsm_verify_signature(sig_ver_serv, &sig_ver_args, &status);
    printf("err: 0x%x hsm_verify_signature hdl: 0x%08x status: 0x%x\n", err, sig_ver_serv, status);
    if (status == HSM_VERIFICATION_STATUS_SUCCESS) {
        printf(" --> SUCCESS\n");
    } else {
        printf(" --> FAILURE\n");
    }

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
    // Close all services and sessions

    printf("\n---------------------------------------------------\n");
    printf("Closing services and sessions\n");
    printf("---------------------------------------------------\n");

    err = hsm_close_hash_service(hash_serv);
    printf("err: 0x%x hsm_close_hash_service hdl: 0x%08x\n", err, hash_serv);

    err = hsm_close_signature_verification_service(sig_ver_serv);
    printf("err: 0x%x hsm_close_signature_verification_service hdl: 0x%08x\n", err, sig_ver_serv);

    err = hsm_close_signature_generation_service(sig_gen_serv);
    printf("err: 0x%x hsm_close_signature_generation_service hdl: 0x%08x\n", err, sig_gen_serv);

    err = hsm_close_key_store_service(key_store_serv);
    printf("err: 0x%x hsm_close_key_store_service hdl: 0x%08x\n", err, key_store_serv);

    err = hsm_close_session(sg0_sess);
    printf("err: 0x%x SG0 hsm_close_session hdl: 0x%x\n", err, sg0_sess);

    err = hsm_close_session(sv0_sess);
    printf("err: 0x%x SV0 hsm_close_session hdl: 0x%x\n", err, sv0_sess);

    err = hsm_close_session(sg1_sess);
    printf("err: 0x%x SG1 hsm_close_session hdl: 0x%x\n", err, sg1_sess);

    err = hsm_close_session(sv1_sess);
    printf("err: 0x%x SV1 hsm_close_session hdl: 0x%x\n", err, sv1_sess);
 

    if (nvm_status != NVM_STATUS_STOPPED) {
        pthread_cancel(tid);
    }
    seco_nvm_close_session();

    return 0;
}
