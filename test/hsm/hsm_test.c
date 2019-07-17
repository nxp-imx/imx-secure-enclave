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
  0xFA, 0x10, 0x0A, 0x9B, 0x2C, 0x7B, 0xF0, 0x9F, 0x09, 0x3F, 0x8B, 0x6D, 0x08, 0x4E, 0x50, 0xC2, 0x01};

static uint8_t ECC_BRAINPOOL_R1_256_Qx[32+1] =
{ 0x7D, 0x91, 0x41, 0xD7, 0x4A, 0xCB, 0x3F, 0xD8, 0x65, 0xF0, 0xB4, 0xE2, 0x92, 0x16, 0x67, 0x37,
  0x96, 0x04, 0xAB, 0xE6, 0x6E, 0x25, 0x5A, 0x37, 0x71, 0x63, 0x99, 0xE4, 0x5A, 0x51, 0xB9, 0xCB, 0x01};

static uint8_t ECC_P384_Qx[48+1] =
{ 0xCB, 0x90, 0x8B, 0x1F, 0xD5, 0x16, 0xA5, 0x7B, 0x8E, 0xE1, 0xE1, 0x43, 0x83, 0x57, 0x9B, 0x33,
  0xCB, 0x15, 0x4F, 0xEC, 0xE2, 0x0C, 0x50, 0x35, 0xE2, 0xB3, 0x76, 0x51, 0x95, 0xD1, 0x95, 0x1D,
  0x75, 0xBD, 0x78, 0xFB, 0x23, 0xE0, 0x0F, 0xEF, 0x37, 0xD7, 0xD0, 0x64, 0xFD, 0x9A, 0xF1, 0x44,0x01 };

/* ECIES test vectors */
static uint8_t ecies_input[16] = {0x91, 0x69, 0x15, 0x5B, 0x08, 0xB0, 0x76, 0x74,
                            0xCB, 0xAD, 0xF7, 0x5F, 0xB4, 0x6A, 0x7B, 0x0D};

static uint8_t ecies_p1[32] = {0xA6, 0xB7, 0xB5, 0x25, 0x54, 0xB4, 0x20, 0x3F,
                               0x7E, 0x3A, 0xCF, 0xDB, 0x3A, 0x3E, 0xD8, 0x67,
                               0x4E, 0xE0, 0x86, 0xCE, 0x59, 0x06, 0xA7, 0xCA,
                               0xC2, 0xF8, 0xA3, 0x98, 0x30, 0x6D, 0x3B, 0xE9 };

static uint8_t ecies_pubk[2*32] = {
    0x1c, 0xcb, 0xe9, 0x1c, 0x07, 0x5f, 0xc7, 0xf4, 0xf0, 0x33, 0xbf, 0xa2, 0x48, 0xdb, 0x8f, 0xcc,
    0xd3, 0x56, 0x5d, 0xe9, 0x4b, 0xbf, 0xb1, 0x2f, 0x3c, 0x59, 0xff, 0x46, 0xc2, 0x71, 0xbf, 0x83,
    0xce, 0x40, 0x14, 0xc6, 0x88, 0x11, 0xf9, 0xa2, 0x1a, 0x1f, 0xdb, 0x2c, 0x0e, 0x61, 0x13, 0xe0,
    0x6d, 0xb7, 0xca, 0x93, 0xb7, 0x40, 0x4e, 0x78, 0xdc, 0x7c, 0xcd, 0x5c, 0xa8, 0x9a, 0x4c, 0xa9
};

static void public_key_test(hsm_hdl_t hsm_session_hdl)
{
    hsm_op_pub_key_rec_args_t hsm_op_pub_key_rec_args;
    hsm_op_pub_key_dec_args_t hsm_op_pub_key_dec_args;
    uint8_t out[64];
    uint8_t out_384[96];
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
    hsm_op_pub_key_dec_args.out_key_size = 2*32;
    hsm_op_pub_key_dec_args.key_type = HSM_KEY_TYPE_ECDSA_NIST_P256;
    hsm_op_pub_key_dec_args.flags = 0u;

    err = hsm_pub_key_decompression(hsm_session_hdl, &hsm_op_pub_key_dec_args);

    printf("hsm_pub_key_decompression ret:0x%x\noutput:\n", err);
    for (i=0; i<64; i++) {
        printf("0x%x ", out[i]);
        if (i%8 == 7) {
            printf("\n");
        }
    }

    /* Brainpool R1 256 */
    hsm_op_pub_key_dec_args.key = ECC_BRAINPOOL_R1_256_Qx;
    hsm_op_pub_key_dec_args.out_key = out;
    hsm_op_pub_key_dec_args.key_size = 33;
    hsm_op_pub_key_dec_args.out_key_size = 2*32;
    hsm_op_pub_key_dec_args.key_type = HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_256;
    hsm_op_pub_key_dec_args.flags = 0u;

    err = hsm_pub_key_decompression(hsm_session_hdl, &hsm_op_pub_key_dec_args);

    printf("hsm_pub_key_decompression ret:0x%x\noutput:\n", err);
    for (i=0; i<64; i++) {
        printf("0x%x ", out[i]);
        if (i%8 == 7) {
            printf("\n");
        }
    }

    /* P384 */
    hsm_op_pub_key_dec_args.key = ECC_P384_Qx;
    hsm_op_pub_key_dec_args.out_key = out_384;
    hsm_op_pub_key_dec_args.key_size = 49;
    hsm_op_pub_key_dec_args.out_key_size = 96;
    hsm_op_pub_key_dec_args.key_type = HSM_KEY_TYPE_ECDSA_NIST_P384;
    hsm_op_pub_key_dec_args.flags = 0u;

    err = hsm_pub_key_decompression(hsm_session_hdl, &hsm_op_pub_key_dec_args);

    printf("hsm_pub_key_decompression ret:0x%x\noutput:\n", err);
    for (i=0; i<96; i++) {
        printf("0x%x ", out_384[i]);
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

static void ecies_tests(hsm_hdl_t hsm_session_hdl,  hsm_hdl_t key_store_hdl)
{
    hsm_op_ecies_enc_args_t op_ecies_enc_args;
    hsm_op_ecies_dec_args_t op_ecies_dec_args;
    uint8_t out[3*32]; //VCT
    uint8_t key_plain[16];
    hsm_err_t err;

    op_ecies_enc_args.input = ecies_input;
    op_ecies_enc_args.pub_key = ecies_pubk;
    op_ecies_enc_args.p1 = ecies_p1;
    op_ecies_enc_args.p2 = NULL;
    op_ecies_enc_args.output = out;
    op_ecies_enc_args.input_size = 16;
    op_ecies_enc_args.p1_size = 32;
    op_ecies_enc_args.p2_size = 0;
    op_ecies_enc_args.pub_key_size = 2*32;
    op_ecies_enc_args.mac_size = 16;
    op_ecies_enc_args.out_size = 3*32;
    op_ecies_enc_args.key_type = HSM_KEY_TYPE_ECDSA_NIST_P256;
    op_ecies_enc_args.flags = 0u;
    op_ecies_enc_args.reserved= 0u;

    err = hsm_ecies_encryption(hsm_session_hdl, &op_ecies_enc_args);
    printf("hsm_ecies_encrypt ret:0x%x \n", err);

    printf("hsm_ecies_encrypt output:\n");
    for (uint32_t i=0; i<96; i++) {
        printf("0x%x ", out[i]);
        if (i%8 == 7) {
            printf("\n");
        }
    }

    op_ecies_dec_args.key_identifier = 0;  // to be modified when the HSM stroage is in place
    op_ecies_dec_args.input = out;
    op_ecies_dec_args.p1 = ecies_p1;
    op_ecies_dec_args.p2 = NULL;
    op_ecies_dec_args.output = key_plain;
    op_ecies_dec_args.input_size = 3*32;
    op_ecies_dec_args.output_size = 16;
    op_ecies_dec_args.p1_size = 32;
    op_ecies_dec_args.p2_size = 0;
    op_ecies_dec_args.mac_size = 16;
    op_ecies_dec_args.key_type = HSM_KEY_TYPE_ECDSA_NIST_P256;
    op_ecies_dec_args.flags = 0u;

    err = hsm_ecies_decryption(key_store_hdl, &op_ecies_dec_args);
    printf("hsm_ecies_decrypt ret:0x%x \n", err);

    printf("hsm_ecies_dec output:\n");
    for (uint32_t i=0; i<16; i++) {
        printf("0x%x ", key_plain[i]);  // key_plain should be the same as ecies_input
        if (i%8 == 7) {
            printf("\n");
        }
    }

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

        public_key_test(hsm_session_hdl);

        signature_tests(hsm_session_hdl);

        ecies_tests(hsm_session_hdl, key_store_hdl);

        err = hsm_close_key_store_service(key_store_hdl);
        printf("hsm_close_key_store_service ret:0x%x\n", err);

        err = hsm_close_session(hsm_session_hdl);

        printf("hsm_close_session ret:0x%x\n", err);

    } while (0);
    return 0;
}
