#!/bin/bash
set -e

function usage()
{
    cat << EOF

    *******************************************************
    * Usage of Secure Enclave build configure script *
    *******************************************************

    Script is configuring the Secure Enclave project enabling
    all modules and setuping the external dependencies.
    Let build type as default Release type.

    CAUTION: We assume this script is executed from the Secure-Enclave
    top level source code directory where the output build directory
     <dir> will be created.

    $(basename "$0") <dir> <arch> <platform>
      <dir>      : Mandatory output build directory
      <arch>     : Mandatory architecture aarch32 or aarch64
      <platform> : Mandatory i.MX platform name

EOF
    exit 1
}

if [[ $# -lt 3 ]]; then
    usage
fi

out=$1
arch="arch=$2"
platform="$3"
opt_cov_scan=$4

#
# Convert platform to optee platform
#
optee_plat=
opt_seco=0
opt_ele=0
case ${platform} in
    imx8dxlevk)
        optee_plat="imx-mx8dxlevk"
        opt_seco=1
	;;

    imx8ulpevk)
        optee_plat="imx-mx8ulpevk"
        opt_ele=1
	;;

    imx93evk)
        optee_plat="imx-mx93evk"
        opt_ele=1
	;;

    *)
	echo "ERROR Unknown plaform: \"${platform}\""
        ;;
esac

optee_plat="platform=${optee_plat}"

toolpath="toolpath=/opt/toolchains"
export="${out}/export"
ta_export="${export}/export-ta_arm""${arch//[^0-9]/}"
tee_build="../build_arm""${arch//[^0-9]/}"
psaarchtests_src_path="../psa-arch-tests"


#
# Build/Prepare external dependencies
#
eval "./scripts/se_build.sh toolchain ${arch} ${toolpath}"

if [[ ${opt_seco} -eq 1 ]]; then
eval "./scripts/se_build.sh seco export=${export} \
      src=../secure_enclave cov_scan=$opt_cov_scan ${arch} ${toolpath}"
fi

if [[ ${opt_ele} -eq 1 ]]; then
eval "./scripts/se_build.sh ele export=${export} \
      src=../secure_enclave cov_scan=$opt_cov_scan ${arch} ${toolpath}"
fi


#
# Define common configuration option
#
conf_opts="${arch} ${toolpath}"

# Enable seco/hsm if supported
if [[ ${opt_seco} -eq 1 ]]; then
    #conf_opts="${conf_opts} zlib=${export}/usr seco=${export}"
    conf_opts="${conf_opts} seco=${export}"
fi

# Enable ELE if supported
if [[ ${opt_ele} -eq 1 ]]; then
    #conf_opts="${conf_opts} zlib=${export}/usr ele=${export}"
    conf_opts="${conf_opts} ele=${export}"
fi


# Enable optee
#conf_opts="${conf_opts} teec=${export} tadevkit=${ta_export}"
# Enable tests
#conf_opts="${conf_opts} jsonc=${export}"
# Enable PSA Architecture tests
#conf_opts="${conf_opts} psaarchtests=${psaarchtests_src_path}"

#
# Configure build targets
#
eval "./scripts/se_build.sh configure out=${out} ${conf_opts}"
