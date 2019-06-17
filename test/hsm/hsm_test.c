/*
 * Copyright 2019 NXP
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

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "hsm_api.h"
#include "seco_nvm.h"

// input  Qx||lsb_Qy
static uint8_t ECC_P256_Qx[32+1] =
{ 0xCE, 0x4D, 0xCF, 0xA7, 0x38, 0x4C, 0x83, 0x44, 0x3A, 0xCE, 0x0F, 0xB8, 0x2C, 0x4A, 0xC1, 0xAD,
  0xFA, 0x10, 0x0A, 0x9B, 0x2C, 0x7B, 0xF0, 0x9F, 0x09, 0x3F, 0x8B, 0x6D, 0x08, 0x4E, 0x50, 0xC2, 0x00};

static uint8_t ECC_BRAINPOOL_R1_256_Qx[32+1] =
{ 0x7D, 0x91, 0x41, 0xD7, 0x4A, 0xCB, 0x3F, 0xD8, 0x65, 0xF0, 0xB4, 0xE2, 0x92, 0x16, 0x67, 0x37,
  0x96, 0x04, 0xAB, 0xE6, 0x6E, 0x25, 0x5A, 0x37, 0x71, 0x63, 0x99, 0xE4, 0x5A, 0x51, 0xB9, 0xCB, 0x00};

static uint8_t ECC_BRAINPOOL_T1_256_Qx[32+1] =
{ 0x9F, 0xAB, 0x97, 0xD2, 0x7E, 0x84, 0x9C, 0x64, 0xD7, 0xC0, 0x20, 0xC6, 0xAE, 0xDD, 0x90, 0x8B,
  0x47, 0xF6, 0x5F, 0x86, 0xCA, 0x32, 0xB1, 0x66, 0x26, 0x71, 0xDB, 0x45, 0x59, 0x6A, 0x8F, 0xB5 , 0x00};


static void public_key_test(hsm_hdl_t hsm_session_hdl)
{
    hsm_op_pub_key_rec_args_t hsm_op_pub_key_rec_args;
    hsm_op_pub_key_dec_args_t hsm_op_pub_key_dec_args;
    uint8_t out[32];
    uint32_t i;
    hsm_err_t err;

    // Dummy values just to test API call
    hsm_op_pub_key_rec_args.pub_rec = out;
    hsm_op_pub_key_rec_args.hash = out;
    hsm_op_pub_key_rec_args.ca_key = out;
    hsm_op_pub_key_rec_args.out_key = out;
    hsm_op_pub_key_rec_args.pub_rec_size = 32;
    hsm_op_pub_key_rec_args.hash_size = 32;
    hsm_op_pub_key_rec_args.ca_key_size = 32;
    hsm_op_pub_key_rec_args.out_key_size =32;
    hsm_op_pub_key_rec_args.key_type = HSM_KEY_TYPE_ECDSA_NIST_P256;
    hsm_op_pub_key_rec_args.flags = 0u;
    hsm_op_pub_key_rec_args.reserved = 0u;

    err = hsm_pub_key_reconstruction(hsm_session_hdl, &hsm_op_pub_key_rec_args);

    printf("hsm_pub_key_reconstruction ret:0x%x\noutput:\n", err);
    /* P256 */
    hsm_op_pub_key_dec_args.key = ECC_P256_Qx;
    hsm_op_pub_key_dec_args.out_key = out;
    hsm_op_pub_key_dec_args.key_size = 33;
    hsm_op_pub_key_dec_args.out_key_size = 32;
    hsm_op_pub_key_dec_args.key_type = HSM_KEY_TYPE_ECDSA_NIST_P256;
    hsm_op_pub_key_dec_args.flags = 0u;

    err = hsm_pub_key_decompression(hsm_session_hdl, &hsm_op_pub_key_dec_args);

    printf("hsm_pub_key_decompression ret:0x%x\noutput:\n", err);
    for (i=0; i<32; i++) {
        printf("0x%x ", out[i]);
        if (i%8 == 7) {
            printf("\n");
        }
    }

    /* Brainpool R1 256 */
    hsm_op_pub_key_dec_args.key = ECC_BRAINPOOL_R1_256_Qx;
    hsm_op_pub_key_dec_args.out_key = out;
    hsm_op_pub_key_dec_args.key_size = 33;
    hsm_op_pub_key_dec_args.out_key_size = 32;
    hsm_op_pub_key_dec_args.key_type = HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_256;
    hsm_op_pub_key_dec_args.flags = 0u;

    err = hsm_pub_key_decompression(hsm_session_hdl, &hsm_op_pub_key_dec_args);

    printf("hsm_pub_key_decompression ret:0x%x\noutput:\n", err);
    for (i=0; i<32; i++) {
        printf("0x%x ", out[i]);
        if (i%8 == 7) {
            printf("\n");
        }
    }

    /* Brainpool T1 256 */
    hsm_op_pub_key_dec_args.key = ECC_BRAINPOOL_T1_256_Qx;
    hsm_op_pub_key_dec_args.out_key = out;
    hsm_op_pub_key_dec_args.key_size = 33;
    hsm_op_pub_key_dec_args.out_key_size = 32;
    hsm_op_pub_key_dec_args.key_type = HSM_KEY_TYPE_ECDSA_BRAINPOOL_T1_256;
    hsm_op_pub_key_dec_args.flags = 0u;

    err = hsm_pub_key_decompression(hsm_session_hdl, &hsm_op_pub_key_dec_args);

    printf("hsm_pub_key_decompression ret:0x%x\noutput:\n", err);
    for (i=0; i<32; i++) {
        printf("0x%x ", out[i]);
        if (i%8 == 7) {
            printf("\n");
        }
    }

}

static void signature_tests(hsm_hdl_t hsm_session_hdl)
{
    hsm_hdl_t sig_verif_hdl;
    open_svc_sign_ver_args_t open_svc_sign_ver_args;
    op_verify_sign_args_t op_verify_sign_args;
    op_import_public_key_args_t op_import_public_key_args;
    uint8_t out[32];
    hsm_verification_status_t verif_status;
    uint32_t key_ref;
    hsm_err_t err;

    open_svc_sign_ver_args.flags = 0;
    err = hsm_open_signature_verification_service(hsm_session_hdl, &open_svc_sign_ver_args, &sig_verif_hdl);
    printf("hsm_open_signature_verification_service ret:0x%x\n", err);

    op_verify_sign_args.key = out;
    op_verify_sign_args.message = out;
    op_verify_sign_args.signature = out;
    op_verify_sign_args.key_size = 32;
    op_verify_sign_args.signature_size = 32;
    op_verify_sign_args.message_size = 32;
    op_verify_sign_args.scheme_id = 0u;
    op_verify_sign_args.flags = 0u;

    err = hsm_verify_signature(sig_verif_hdl, &op_verify_sign_args, &verif_status);
    printf("hsm_verify_signature ret:0x%x status:0x%x\n", err, verif_status);


    op_import_public_key_args.key = out;
    op_import_public_key_args.key_size = 32;
    op_import_public_key_args.key_type = 0;
    op_import_public_key_args.flags = 0;

    err = hsm_import_public_key(sig_verif_hdl, &op_import_public_key_args, &key_ref);
    printf("hsm_import_public_key ret:0x%x key_ref:0x%x\n", err, key_ref);

    err = hsm_close_signature_verification_service(sig_verif_hdl);
    printf("hsm_close_signature_verification_service ret:0x%x\n", err);
}


/* Test entry function. */
int main(int argc, char *argv[])
{
    hsm_hdl_t hsm_session_hdl;
    hsm_hdl_t key_store_hdl;

    open_session_args_t open_session_args;
    open_svc_key_store_args_t open_svc_key_store_args;

    uint32_t nvm_status;

    hsm_err_t err;

    do {
        nvm_status = NVM_STATUS_UNDEF;
        seco_nvm_manager(NVM_FLAGS_HSM, &nvm_status);

        /* Wait for the storage manager to be ready to receive commands from SECO. */
        while (nvm_status <= NVM_STATUS_STARTING) {
            usleep(1000);
        }
        /* Check if it ended because of an error. */
        if (nvm_status == NVM_STATUS_STOPPED) {
            printf("nvm manager failed to start\n");
            /* Currently tolerate this error since not supported by SECO and not absolutely needed by APIs tested below. */
            // break;
        }

        open_session_args.session_priority = 0;
        open_session_args.operating_mode = 0;
        err = hsm_open_session(&open_session_args,
                                    &hsm_session_hdl);
        if (err != HSM_NO_ERROR) {
            printf("hsm_open_session failed err:0x%x\n", err);
            break;
        }
        printf("hsm_open_session PASS\n");

        open_svc_key_store_args.key_store_identifier = 0xABCD;
        open_svc_key_store_args.authentication_nonce = 0x1234;
        open_svc_key_store_args.max_updates_number   = 100;
        open_svc_key_store_args.flags                = 0;
        err = hsm_open_key_store_service(hsm_session_hdl, &open_svc_key_store_args, &key_store_hdl);
        printf("hsm_open_key_store_service ret:0x%x\n", err);


        err = hsm_close_key_store_service(key_store_hdl);
        printf("hsm_close_key_store_service ret:0x%x\n", err);

        public_key_test(hsm_session_hdl);

        signature_tests(hsm_session_hdl);


        err = hsm_close_session(hsm_session_hdl);

        printf("hsm_close_session ret:0x%x\n", err);

    } while (0);
    return 0;
}
