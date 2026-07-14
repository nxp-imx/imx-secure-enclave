#!/bin/bash

# SPDX-License-Identifier: BSD-3-Clause
#
# Copyright 2023-2025 NXP

set -eu

nvmd_conf_fpath="/etc/nvmd.conf"
nvmd_v2x_she_conf_fpath="/etc/nvmd_v2x_she.conf"
nvmd_v2x_hsm_conf_fpath="/etc/nvmd_v2x_hsm.conf"

function nvmd_config_setup()
{
  local nvmd_conf_target=${nvmd_conf_fpath}
  local nvmd_config_storage_filename="/^NVMD_STORAGE_FILENAME=/c\NVMD_STORAGE_FILENAME=$1"
  local nvmd_config_storage_dirname="/^NVMD_STORAGE_DIRNAME=/c\NVMD_STORAGE_DIRNAME=${2}"
  local nvmd_config_mu_session_flag="/^NVMD_MU_SESSION_FLAG=/c\NVMD_MU_SESSION_FLAG=$3"

  if [[ $4 == "V2X SHE" ]]; then
	nvmd_conf_target=${nvmd_v2x_she_conf_fpath}
  elif [[ $4 == "V2X HSM" ]]; then
	nvmd_conf_target=${nvmd_v2x_hsm_conf_fpath}
  fi

  #Change/Replace the line beginning with given string, with the intended one
  sed -i ${nvmd_config_storage_dirname} ${nvmd_conf_target}
  sed -i ${nvmd_config_storage_filename} ${nvmd_conf_target}
  sed -i ${nvmd_config_mu_session_flag} ${nvmd_conf_target}
}

function custom_path_function()
{
  local filename=
  local dir_name=
  local flag=
  local conf_type=

  for arg in "$@"
  do
    case ${arg} in
     dir_name=*)
             filename="${arg#*=}"
             ;;

     filename=*)
             dir_name="${arg#*=}"
             ;;

     flag=*)
             flag="${arg#*=}"
             ;;
     type=*)
	     conf_type="${arg#*=}"
	     ;;
    esac
  done


  if [[ -z "${filename}" || -z $"${dir_name}" || -z "${conf_type}" ]]; then
	  echo "Missing filename or dir_name, or conf_type argument"
	  exit 1
  fi

  nvmd_config_setup "${dir_name}" "${filename}" "${flag}" "${conf_type}"
}


function imx8dxlevk_nvmd_config()
{
    local loc_config_id=$1

    case ${loc_config_id} in
        0x80 | "HSM_NVM" | "hsm_nvm")
            nvmd_config_setup "/etc/hsm/seco_hsm_master" "/etc/hsm/" "0x80" "SECO"
            ;;

        0x88 | "SHE_NVM" | "she_nvm")
            nvmd_config_setup "/etc/she/seco_she_master" "/etc/she/" "0x88" "SECO"
            ;;

        0xD0 | 0xd0 | "V2X_HSM_NVM" | "v2x_hsm_nvm")
            nvmd_config_setup "/etc/v2x_hsm/v2x_hsm_master" "/etc/v2x_hsm/" "0xD0" "V2X HSM"
            ;;

        0xC8 | 0xc8 | "V2X_SHE_NVM" | "v2x_she_nvm")
            nvmd_config_setup "/etc/v2x_she/v2x_she_master" "/etc/v2x_she/" "0xC8" "V2X SHE"
            ;;

        *)
            printf "Unsupported NVM-D config opted.\n"
            ;;
    esac
}

function imx8qxpmek_nvmd_config()
{
    local loc_config_id=$1

    case ${loc_config_id} in
        0x80 | "HSM_NVM" | "hsm_nvm")
            nvmd_config_setup "/etc/hsm/seco_hsm_master" "/etc/hsm/" "0x80" "SECO"
            ;;

        0x88 | "SHE_NVM" | "she_nvm")
            nvmd_config_setup "/etc/she/seco_she_master" "/etc/she/" "0x88" "SECO"
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

        0xD0 | 0xd0 | "V2X_HSM_NVM" | "v2x_hsm_nvm")
            nvmd_config_setup "/etc/v2x_hsm/v2x_hsm_master" "/etc/v2x_hsm/" "0xD0" "V2X HSM"
            ;;

        0xC8 | 0xc8 | "V2X_SHE_NVM" | "v2x_she_nvm")
            nvmd_config_setup "/etc/v2x_she/v2x_she_master" "/etc/v2x_she/" "0xC8" "V2X SHE"
            ;;

        0xE0 | 0xe0 | "V2X_SHE_DEBUG_MU_NVM" | "v2x_she_debug_mu_nvm")
            nvmd_config_setup "/etc/v2x_she/v2x_she_master" "/etc/v2x_she/" "0xE0" "V2X SHE"
            ;;

        *)
            printf "Unsupported NVM-D config opted.\n"
            ;;
    esac
}

function imx94evk_nvmd_config()
{
    local loc_config_id=$1

    case ${loc_config_id} in

        0xD0 | 0xd0 | "V2X_HSM_NVM" | "v2x_hsm_nvm")
            nvmd_config_setup "/etc/v2x_hsm/v2x_hsm_master" "/etc/v2x_hsm/" "0xD0" "V2X HSM"
            ;;

        0xC8 | 0xc8 | "V2X_SHE_NVM" | "v2x_she_nvm")
            nvmd_config_setup "/etc/v2x_she/v2x_she_master" "/etc/v2x_she/" "0xC8" "V2X SHE"
            ;;

        0xC9 | 0xc9 | "V2X_SHE1_NVM" | "v2x_she1_nvm")
            nvmd_config_setup \
	    "/etc/v2x_she1/v2x_she1_master" "/etc/v2x_she1/" "0xC9" "V2X SHE"
            ;;

        0xE0 | 0xe0 | "V2X_SHE_DEBUG_MU_NVM" | "v2x_she_debug_mu_nvm")
            printf "Unsupported NVM-D config opted for iMX94x.\n"
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

    printf "\tNVMD_MU_SESSION_FLAG=0x80 / HSM_NVM\n"
    printf "\tNVMD_MU_SESSION_FLAG=0xc8 / V2X_SHE_NVM\n"
    printf "\tNVMD_MU_SESSION_FLAG=0xc9 / V2X_SHE1_NVM\n"
    printf "\tNVMD_MU_SESSION_FLAG=0xe0 / V2X_SHE_DEBUG_MU_NVM\n"
    printf "\tNVMD_MU_SESSION_FLAG=0xd0 / V2X_HSM_NVM\n"
    printf "\tNVMD_MU_SESSION_FLAG=0x88 / SHE_NVM\n\n"

    printf "Usage:\n"
    printf "\t./nvmd_conf_setup.sh config_id=NVM_CONFIG_ID\n"
    printf "\t./nvmd_conf_setup.sh custom filename=FILE_PATH "
    printf "dir_name=DIR_PATH flag=FLAG_VALUE type=TYPE\n\n"

    printf "\tCUSTOM Mode Usage Example:\n"
    printf "\t\tReplace FILE_PATH with the desired filename,\n"
    printf "\t\tDIR_PATH with the desired directory path,\n"
    printf "\t\tFLAG_VALUE with the desired flag value.\n"
    printf "\t\tand TYPE with ELE, SECO, or V2X.\n"

    exit
}


if [[ $# -lt 1 ]]; then
    usage
fi

opt_plat=$(cat /sys/devices/soc0/soc_id)
opt_config_id=

for arg in "$@"
do
    case ${arg} in
	config_id=*)
	     opt_config_id="${arg#*=}"
	     ;;

	custom)
             custom_path_function "$@"
	     exit 0
             ;;

	*)
	    printf "Unknown argument \"${arg}\"\n"
	    usage
	    ;;

    esac

    shift
done

#based on platform (iMX8DXL/i.MX8QXP/iMX95), choose function for NVM-D config update
case ${opt_plat} in
    i.MX8DXL)
        imx8dxlevk_nvmd_config ${opt_config_id}
        ;;

    i.MX8QXP)
        imx8qxpmek_nvmd_config ${opt_config_id}
        ;;

    i.MX95|i.MX952)
        imx95evk_nvmd_config ${opt_config_id}
        ;;

    i.MX943|i.MX942|i.MX941)
        imx94evk_nvmd_config ${opt_config_id}
        ;;

    *)
        printf "ERROR: Unknown platform: \"${opt_plat}\"\n"
        usage
        ;;
esac
