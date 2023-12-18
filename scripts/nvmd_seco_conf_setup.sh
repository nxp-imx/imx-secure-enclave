#!/bin/bash

# SPDX-License-Identifier: BSD-3-Clause
#
# Copyright 2023 NXP

set -eu

nvm_conf_fpath="/etc/nvmd_seco.conf"

function nvmd_config_setup()
{
  local nvmd_config_storage_filename="/^NVMD_STORAGE_FILENAME=/c\NVMD_STORAGE_FILENAME=$1"
  local nvmd_config_storage_dirname="/^NVMD_STORAGE_DIRNAME=/c\NVMD_STORAGE_DIRNAME=${2}"
  local nvmd_config_mu_session_flag="/^NVMD_MU_SESSION_FLAG=/c\NVMD_MU_SESSION_FLAG=$3"

  #Change/Replace the line beginning with given string, with the intended one
  sed -i ${nvmd_config_storage_dirname} ${nvm_conf_fpath}
  sed -i ${nvmd_config_storage_filename} ${nvm_conf_fpath}
  sed -i ${nvmd_config_mu_session_flag} ${nvm_conf_fpath}
}

function imx8dxlevk_nvmd_config()
{
    local loc_config_id=$1

    case ${loc_config_id} in
        0)
            nvmd_config_setup "/etc/hsm/seco_hsm_master" "/etc/hsm/" "0"
            ;;

        1)
            nvmd_config_setup "/etc/she/seco_she_master" "/etc/she/" "1"
            ;;

        2)
            nvmd_config_setup "/etc/v2x_hsm/v2x_hsm_master" "/etc/v2x_hsm/" "2"
            ;;

        3)
            nvmd_config_setup "/etc/v2x_she/v2x_she_master" "/etc/v2x_she/" "3"
            ;;

        *)
            printf "Unsupported NVM-D config opted.\n"
            ;;
    esac
}

function imx95evk_nvmd_config()
{
    local loc_config_id=$1

    case ${loc_config_id} in

        2)
            nvmd_config_setup "/etc/v2x_hsm/v2x_hsm_master" "/etc/v2x_hsm/" "2"
            ;;

        3)
            nvmd_config_setup "/etc/v2x_she/v2x_she_master" "/etc/v2x_she/" "3"
            ;;

        *)
            printf "Unsupported NVM-D config opted.\n"
            ;;
    esac
}

function usage()
{
    printf "\n"
    printf "*******************************************\n"
    printf "NVM-D config script: Usage:\n"
    printf "*******************************************\n"

    printf "\nNVM_CONFIG_IDs/NVM Flags (config_id):\n"

    printf "\tNVMD_MU_SESSION_FLAG=NVM_FLAGS_HSM (0)\n"
    printf "\tNVMD_MU_SESSION_FLAG=NVM_FLAGS_SHE (1)\n"
    printf "\tNVMD_MU_SESSION_FLAG=NVM_FLAGS_HSM | NVM_FLAGS_V2X (2)\n"
    printf "\tNVMD_MU_SESSION_FLAG=NVM_FLAGS_SHE | NVM_FLAGS_V2X (3)\n\n"

    printf "Usage:\n\t./nvmd_conf_setup.sh plat=PLATFORM config_id=NVM_CONFIG_ID\n\n"
    printf "\tPLATFORM: imx8dxlevk, imx95evk\n"
    printf "\tNVM_CONFIG_IDs:\n"
    printf "\t\t0 : Not Supported i.MX95\n"
    printf "\t\t1 : Not Supported i.MX95\n"
    printf "\t\t2 :\n"
    printf "\t\t3 :\n"

    exit
}


if [[ $# -lt 2 ]]; then
    usage
fi

opt_plat=
opt_config_id=

for arg in "$@"
do
    case ${arg} in
	plat=*)
	    opt_plat="${arg#*=}"
	    ;;

	config_id=*)
	     opt_config_id="${arg#*=}"
	     ;;

	*)
	    printf "Unknown argument \"${arg}\"\n"
	    usage
	    ;;

    esac

    shift
done

#based on platform (iMX8DXL/iMX95), choose function for NVM-D config update
case ${opt_plat} in
    imx8dxlevk)
        imx8dxlevk_nvmd_config ${opt_config_id}
        ;;

    imx95evk)
        imx95evk_nvmd_config ${opt_config_id}
        ;;

    *)
        printf "ERROR: Unknown platform: \"${opt_plat}\"\n"
        usage
        ;;
esac
