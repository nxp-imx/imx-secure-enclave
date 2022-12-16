#!/bin/bash
set -eE
trap 'error ${LINENO}' ERR

#
# Default build options
#
opt_build=all
opt_jsonc_lib=
opt_coverage="-DCODE_COVERAGE=OFF"
opt_buildtype="-DCMAKE_BUILD_TYPE=Release"
opt_verbose="-DVERBOSE=0"
opt_format="-DFORMAT=html"
opt_psa="-DENABLE_PSA_DEFAULT_ALT=OFF"
opt_tls12="-DENABLE_TLS12=OFF"
opt_cmake_ver="3.10"

#
# Get script name and path
#
script_name=$0
script_full=$(realpath "${script_name}")
script_dir=$(dirname "${script_full}")

function pr_err()
{
    printf "\033[1;31m\n"
    printf "%s" "$@"
    printf "\033[0m\n"
}

function check_cmake_version()
{
    #
    # Check if cmake is installed and minimum version is expected
    #
    if [[ ! -x $(command -v cmake) ]]; then
        pr_err "cmake not installed\n"
        pr_err "cmake version required is minimum ${opt_cmake_ver}\n"
        exit 1
    fi

    # Get the current cmake version installed
    cmake_ver=$(cmake -version 2>&1 | grep -Eo "cmake version [0-9]\.[0-9]+")
    cmake_ver=$(echo "${cmake_ver}" | grep -Eo '[0-9]\.[0-9]+')

    IFS='.' read -ra acmake_ver <<< "${cmake_ver}"
    IFS='.' read -ra aexp_ver <<< "${opt_cmake_ver}"

    match=${#aexp_ver[@]}
    if [[ ${#acmake_ver[@]} -eq ${#aexp_ver[@]} ]]; then
        for (( i=0; i<${#aexp_ver[@]}; i++ )); do
            if [[ ${acmake_ver[$i]} -lt ${aexp_ver[$i]} ]]; then
                break;
            fi
            match=$((match-1))
        done
    fi

    if [[ ${match} -ne 0 ]]; then
        printf "Bad cmake version got %s expected %s or newer\n" \
               "${cmake_ver}" "${opt_cmake_ver}"
        exit 1
    fi
}

function get_cmakecache()
{
    local pattern="$2"

    while read -r line
    do
        case $line in
            ${pattern}*)
                IFS='=' read -ra split_line <<< "$line"
                break
                ;;
        esac
    done < "${opt_out}/CMakeCache.txt"

    if [[ ${#split_line[@]} -ge 2 ]]; then
        eval "$1=${split_line[1]}"
    else
        pr_err "${pattern} not found in ${opt_out}/CMakeCache.txt"
    fi
}

function get_cmakecache_err()
{
    get_cmakecache "$1" "$2"

    if [[ -z "${!1}" ]]; then
         exit 1
    fi
}

function check_directory()
{
    declare -n mydir=$1
    mydir="${mydir/\~/$HOME}"

    if [[ ! -d "${mydir}" ]]; then
        pr_err "${mydir} is not a directory"
    fi
}

function toolchain()
{
    cmd_script="cmake -DFORCE_TOOLCHAIN_INSTALL=True"
    cmd_script="${cmd_script} ${opt_toolpath} ${opt_toolname}"

    printf "\033[0;32m\n"
    printf "***************************************\n"
    printf " Install toolchain %s\n" "${opt_arch}"
    printf "***************************************\n"
    printf "\033[0m\n"

    cmd_script="${cmd_script} -P ${toolchain_script}"
    printf "Execute %s\n" "${cmd_script}"
    eval "${cmd_script}"
}

function zlib()
{
    cmd_script="cmake ${opt_toolchain}"
    zlib_script="${script_dir}/build_zlib.cmake"

    printf "\033[0;32m\n"
    printf "***************************************\n"
    printf " Install zlib to %s\n" "${opt_export}"
    printf "***************************************\n"
    printf "\033[0m\n"

    if [[ -z ${opt_export} ]]; then
        usage_zlib
        exit 1
    fi

    if [[ -n ${opt_src} ]]; then
        cmd_script="${cmd_script} -DZLIB_SRC_PATH=${opt_src}"
    fi

    cmd_script="${cmd_script} -DZLIB_ROOT=${opt_export} -P ${zlib_script}"

    printf "Execute %s\n" "${cmd_script}"
    eval "${cmd_script}"
}

function seco()
{
    cmd_script="cmake ${opt_toolchain} ${opt_zlib}"
    seco_script="${script_dir}/build_seco.cmake"

    printf "\033[0;32m\n"
    printf "***************************************\n"
    printf " Install SECO to %s\n" "${opt_export}"
    printf "***************************************\n"
    printf "\033[0m\n"

    if [[ -z ${opt_export} || -z ${opt_src} ]]; then
        usage_seco
        exit 1
    fi

    cmd_script="${cmd_script} -DSECO_SRC_PATH=${opt_src}"
    cmd_script="${cmd_script} -DSECO_ROOT=${opt_export} -P ${seco_script}"

    printf "Execute %s\n" "${cmd_script}"
    eval "${cmd_script}"
}

function ele()
{
    cmd_script="cmake ${opt_toolchain} ${opt_zlib}"
    ele_script="${script_dir}/build_ele.cmake"

    printf "\033[0;32m\n"
    printf "***************************************\n"
    printf " Install EdgeLock Enclave (ELE) to %s\n" "${opt_export}"
    printf "***************************************\n"
    printf "\033[0m\n"

    if [[ -z ${opt_export} || -z ${opt_src} ]]; then
        usage_ele
        exit 1
    fi

    cmd_script="${cmd_script} -DELE_SRC_PATH=${opt_src}"
    cmd_script="${cmd_script} -DELE_ROOT=${opt_export} -P ${ele_script}"

    printf "Execute %s\n" "${cmd_script}"
    eval "${cmd_script}"
}


function teec()
{
    cmd_script="cmake ${opt_toolchain} ${opt_builddir}"
    teec_script="${script_dir}/build_teec.cmake"

    printf "\033[0;32m\n"
    printf "***************************************\n"
    printf " Install OPTEE Client to %s\n" "${opt_export}"
    printf "***************************************\n"
    printf "\033[0m\n"

    if [[ -z ${opt_export} || -z ${opt_src} ]]; then
        usage_teec
        exit 1
    fi

    cmd_script="${cmd_script} -DTEEC_SRC_PATH=${opt_src}"
    cmd_script="${cmd_script} ${opt_libuuid_config}"
    cmd_script="${cmd_script} -DTEEC_ROOT=${opt_export} -P ${teec_script}"

    printf "Execute %s\n" "${cmd_script}"
    eval "${cmd_script}"
}

function tadevkit()
{
    cmd_script="cmake ${opt_toolchain} ${opt_platform} ${opt_builddir}"
    tadevkit_script="${script_dir}/build_tadevkit.cmake"

    printf "\033[0;32m\n"
    printf "***************************************************\n"
    printf " Install OPTEE TA Development Kit to %s\n" "${opt_export}"
    printf "***************************************************\n"
    printf "\033[0m\n"

    if [[ -z ${opt_export} || -z ${opt_src} ]]; then
        usage_tadevkit
        exit 1
    fi

    cmd_script="${cmd_script} -DOPTEE_OS_SRC_PATH=${opt_src}"
    cmd_script="${cmd_script} -DTA_DEV_KIT_ROOT=${opt_export}"
    cmd_script="${cmd_script} -P ${tadevkit_script}"

    printf "Execute %s\n" "${cmd_script}"
    eval "${cmd_script}"
}

function psaarchtests()
{
    cmd_script="cmake"
    psaarchtests_script="${script_dir}/fetch_psaarchtests.cmake"

    printf "\033[0;32m\n"
    printf "***************************************************\n"
    printf " Fetch PSA Architecture Tests repo to %s\n" "${opt_src}"
    printf "***************************************************\n"
    printf "\033[0m\n"

    if [[ -z ${opt_src} ]]; then
        usage_psaarchtests
        exit 1
    fi

    cmd_script="${cmd_script} -DPSA_ARCH_TESTS_SRC_PATH=${opt_src}"
    cmd_script="${cmd_script} -P ${psaarchtests_script}"

    printf "Execute %s\n" "${cmd_script}"
    eval "${cmd_script}"
}

function configure()
{
    printf "\033[0;32m\n"
    printf "***************************************\n"
    printf " Configure in Secure Enclave not supported\n"
    printf "***************************************\n"
    printf "\033[0m\n"

    if [[ -z ${opt_out} ]]; then
        usage_configure
        exit 1
    fi

    cmd_script="cmake -S . -B ${opt_out} ${opt_toolchain}"
    cmd_script="${cmd_script} ${opt_coverage}"
    cmd_script="${cmd_script} ${opt_buildtype} ${opt_verbose}"
    cmd_script="${cmd_script} ${opt_zlib} ${opt_seco} ${opt_ele}"
    cmd_script="${cmd_script} ${opt_teec} ${opt_tadevkit}"
    cmd_script="${cmd_script} ${opt_jsonc} ${opt_psaarchtests}"
    cmd_script="${cmd_script} ${opt_psa}"
    cmd_script="${cmd_script} ${opt_tls12}"

    printf "Not Executing %s\n" "${cmd_script}"
    #eval "${cmd_script}"
}

function build_tests()
{
    if [[ -n ${opt_jsonc} ]]; then
        eval "cmake ${opt_out} ${opt_jsonc}"
    else
        get_cmakecache_err opt_jsonc_lib "JSONC_LIBRARY"
    fi

    eval "make -C ${opt_out} build_tests"
}

function build_docs()
{
    if [[ -n ${opt_format} ]]; then
        eval "cmake ${opt_out} ${opt_format}"
    fi

    eval "make -C ${opt_out} docs"
}

function build()
{
    printf "\033[0;32m\n"
    printf "***************************************\n"
    printf " Build Secure-Enclave (%s) to %s\n" "${opt_build}" "${opt_out}"
    printf "***************************************\n"
    printf "\033[0m\n"

    if [[ -z ${opt_out} ]]; then
        usage_build
        exit 1
    fi

    cmd_make="make -C ${opt_out}"

    case ${opt_build} in
        all)
            eval "${cmd_make}"
            eval "${cmd_make} smw_pkcs11"
            build_tests
            ;;
        smw)
            eval "${cmd_make}"
            ;;
        pkcs11)
            eval "${cmd_make} smw_pkcs11"
            ;;
        tests)
            build_tests
            ;;
        docs)
            build_docs
            ;;
        *)
            pr_err "Unknwon build option: \"${opt_build}\""
            usage_build
            exit 1
            ;;
    esac
}

function install()
{
    printf "\033[0;32m\n"
    printf "***************************************\n"
    printf " Install SMW to %s\n" "${opt_dest}"
    printf "***************************************\n"
    printf "\033[0m\n"

    if [[ -z ${opt_out} ]]; then
        usage_install
        exit 1
    fi

    cmd_make="make -C ${opt_out}"

    get_cmakecache opt_jsonc_lib "JSONC_LIBRARY"

    cmd_script=""
    if [[ -n ${opt_dest} ]]; then
        cmd_script="DESTDIR=${opt_dest}"
    fi
    eval "${cmd_make} install ${cmd_script}"

    if [[ -n ${opt_jsonc_lib} ]]; then
        eval "${cmd_make} install_tests ${cmd_script}"
    fi
}

function se_package()
{
    local package_name="libse_package.tar.gz"

    printf "\033[0;32m\n"
    printf "***************************************\n"
    printf " Package Secure Enclave(SE) in %s\n" "${opt_out}/${package_name}"
    printf "***************************************\n"
    printf "\033[0m\n"

    if [[ -z ${opt_out} ]]; then
        usage_se_package
        exit 1
    fi

    opt_dest="${opt_out}"

    eval "cd ${opt_dest} && tar -czf ../${package_name} . && mv ../${package_name} ."
    rm -rf "${opt_dest}"
}

function package()
{
    local package_name="libse_package.tar.gz"
    local tmp_inst_dir="tmp_install"

    printf "\033[0;32m\n"
    printf "***************************************\n"
    printf " Package SMW in %s\n" "${opt_out}/${package_name}"
    printf "***************************************\n"
    printf "\033[0m\n"

    if [[ -z ${opt_out} ]]; then
        usage_package
        exit 1
    fi

    # First do the installation
    opt_dest="${tmp_inst_dir}"
    install

    opt_dest="${opt_out}/${opt_dest}"

    if [[ -n ${opt_jsonc_lib} ]]; then
        eval "cp -P ${opt_jsonc_lib}.* ${opt_dest}/usr/lib/."
    fi

    eval "cd ${opt_dest} && tar -czf ../${package_name} ."
    rm -rf "${opt_dest}"
}

function jsonc()
{
    cmd_script="cmake ${opt_toolchain}"
    jsonc_script="${script_dir}/build_jsonc.cmake"

    printf "\033[0;32m\n"
    printf "***************************************\n"
    printf " Install json-c to %s\n" "${opt_export}"
    printf "***************************************\n"
    printf "\033[0m\n"

    if [[ -z ${opt_export} || -z ${opt_src} ]]; then
        usage_jsonc
        exit 1
    fi

    cmd_script="${cmd_script} -DJSONC_SRC_PATH=${opt_src}"
    cmd_script="${cmd_script} -DJSONC_ROOT=${opt_export} -P ${jsonc_script}"

    if [[ ${opt_version} && ${opt_hash} ]]; then
        cmd_script="${cmd_script} -DJSONC_VERSION=${opt_version}"
        cmd_script="${cmd_script} -DJSONC_HASH=${opt_hash}"
    fi

    printf "Execute %s\n" "${cmd_script}"
    eval "${cmd_script}"
}

function usage_toolchain()
{
    printf "\n"
    printf "To install the toolchain aarch32 or aarch64\n"
    printf "  %s toolchain arch=[arch] toolpath=[dir] " "${script_name}"
    printf "toolname=[name]\n"
    printf "    arch     = Toolchain architecture (aarch32|aarch64)\n"
    printf "    toolpath = [optional] Toolchain path where installed\n"
    printf "    toolname = [optional] Toolchain name\n"
    printf "\n"
}

function usage_zlib()
{
    printf "\n"
    printf "To build and install the ZLIB Library\n"
    printf "  %s zlib export=[dir] src=[dir] arch=[arch] " "${script_name}"
    printf "toolpath=[dir] toolname=[name]\n"
    printf "    export   = Export directory\n"
    printf "    src      = [optional] Temporary directory where install sources\n"
    printf "    arch     = [optional] Toolchain architecture (aarch32|aarch64)\n"
    printf "    toolpath = [optional] Toolchain path where installed\n"
    printf "    toolname = [optional] Toolchain name\n"
    printf "\n"
}

function usage_seco()
{
    printf "\n"
    printf "To build and install the SECO libraries\n"
    printf "  %s seco export=[dir] src=[dir] zlib=[root] " "${script_name}"
    printf "arch=[arch] toolpath=[dir] toolname=[name]\n"
    printf "    export   = Export directory\n"
    printf "    src      = Source directory\n"
    printf "    zlib     = [optional] ZLIB library root directory\n"
    printf "    arch     = [optional] Toolchain architecture (aarch32|aarch64)\n"
    printf "    toolpath = [optional] Toolchain path where installed\n"
    printf "    toolname = [optional] Toolchain name\n"
    printf "\n"
}

function usage_ele()
{
    printf "\n"
    printf "To build and install the EdgeLock Enclave libraries\n"
    printf "  %s ele export=[dir] src=[dir] zlib=[root] " "${script_name}"
    printf "arch=[arch] toolpath=[dir] toolname=[name]\n"
    printf "    export   = Export directory\n"
    printf "    src      = Source directory\n"
    printf "    zlib     = [optional] ZLIB library root directory\n"
    printf "    arch     = [optional] Toolchain architecture (aarch32|aarch64)\n"
    printf "    toolpath = [optional] Toolchain path where installed\n"
    printf "    toolname = [optional] Toolchain name\n"
    printf "\n"
}


function usage_teec()
{
    printf "\n"
    printf "To build and install the OPTEE Client libraries\n"
    printf "  %s teec export=[dir] src=[dir] out=[dir] " "${script_name}"
    printf "libuuid_config=[dir]"
    printf "arch=[arch] toolpath=[dir] toolname=[name]\n"
    printf "    export         = Export directory\n"
    printf "    src            = Source directory\n"
    printf "    out            = [optional] Build root directory\n"
    printf "    libuuid_config = [optional] Library UUID configuration path\n"
    printf "    arch           = [optional] Toolchain architecture (aarch32|aarch64)\n"
    printf "    toolpath       = [optional] Toolchain path where installed\n"
    printf "    toolname       = [optional] Toolchain name\n"
    printf "\n"
}

function usage_tadevkit()
{
    printf "\n"
    printf "To build and install the OPTEE TA Development Kit\n"
    printf "  %s tadevkit export=[dir] src=[dir] out=[dir] " "${script_name}"
    printf "platform=[platforn] arch=[arch] toolpath=[dir] toolname=[name]\n"
    printf "    export   = Export directory\n"
    printf "    src      = Source directory\n"
    printf "    out      = [optional] Build root directory\n"
    printf "    platform = [optional] Not use if OPTEE doesn't have to be built\n"
    printf "    arch     = [optional] Toolchain architecture (aarch32|aarch64)\n"
    printf "    toolpath = [optional] Toolchain path where installed\n"
    printf "    toolname = [optional] Toolchain name\n"
    printf "\n"
}

function usage_psaarchtests()
{
    printf "\n"
    printf "To fetch the PSA Architecture Tests repo\n"
    printf "  %s psaarchtests src=[dir] " "${script_name}"
    printf "    src = Source directory\n"
    printf "\n"
}

function usage_configure()
{
    printf "\n"
    printf "To configure the Secure Middleware\n"
    printf " - Note: all dependencies must be present\n"
    printf "  %s configure out=[dir] coverage debug " "${script_name}"
    printf "verbose=[lvl] zlib=[dir] seco=[dir] "
    printf "ele=[dir] "
    printf "teec=[dir] tadevkit=[dir] "
    printf "arch=[arch] toolpath=[dir] toolname=[name] jsonc=[dir] "
    printf "psaarchtests=[dir]"
    printf "format=[name] ...\n"
    printf "    out      = Build directory\n"
    printf "    coverage = [optional] if set enable code coverage tool\n"
    printf "    debug    = [optional] if set build type to debug\n"
    printf "    arch     = [optional] Toolchain architecture (aarch32|aarch64)\n"
    printf "    toolpath = [optional] Toolchain path where installed\n"
    printf "    toolname = [optional] Toolchain name\n"
    printf "    format   = [optional] Documentation format\n"
    printf "  To enable HSM subsystem [optional]\n"
    printf "    zlib     = ZLIB library root directory\n"
    printf "    seco     = SECO export directory\n"
    printf "  To enable ELE subsystem [optional]\n"
    printf "    zlib     = ZLIB library root directory\n"
    printf "    ele      = ELE export directory\n"
    printf "  To enable TEE subsystem [optional]\n"
    printf "    teec     = OPTEE Client export directory\n"
    printf "    tadevkit = OPTEE TA Development Kit export directory\n"
    printf "  To enable tests [optionnal]\n"
    printf "    jsonc = JSON-C export directory\n"
    printf "  To enable PSA Architecture tests [optionnal]\n"
    printf "    psaarchtests = psa-arch-tests sources directory\n"
    printf "  To enable library option off by default\n"
    printf "    all_options     = [optional] Enable all options described below\n"
    printf "    tls12           = [optional] Enable TLS1.2\n"
    printf "    psa_default_alt = [optional] Enable PSA interface\n"
    printf "\n"
}

function usage_build()
{
    printf "\n"
    printf "To build the Secure Middleware\n"
    printf " - Note: Project must have been configure first\n"
    printf " (ref. %s configure)\n" "${script_name}"
    printf "\n"
    printf "  %s build [option] out=[dir] jsonc=[dir] " "${script_name}"
    printf "format=[name]\n"
    printf "    out    = Build directory\n"
    printf "    jsonc  = [optional] JSON-C export directory (tests build)\n"
    printf "    format = [optional] Documentation format (default is HTML) (docs)\n"
    printf "\n"
    printf "Note:\n"
    printf "  - If no [option] specified, build all SMW component\n"
    printf "  - the JSON-C export directory could have been set "
    printf "while configuring the Security Middleware\n"
    printf "\n"
    printf " Option:\n"
    printf "  smw      Build SMW library only\n"
    printf "  pkcs11   Build PKCS11 library\n"
    printf "  tests    Build all tests (smw and pkcs11)\n"
    printf "  docs     Build all documentations\n"
    printf "  all      Build all projects including pksc11 and tests (default)\n"
    printf "\n"
}

function usage_jsonc()
{
    printf "\n"
    printf "To build and install the JSON-C Library\n"
    printf "  %s jsonc export=[dir] src=[dir] arch=[arch] " "${script_name}"
    printf "toolpath=[dir] toolname=[name]\n"
    printf "    export   = Export directory\n"
    printf "    src      = Temporary directory where install sources\n"
    printf "    arch     = [optional] Toolchain architecture (aarch32|aarch64)\n"
    printf "    toolpath = [optional] Toolchain path where installed\n"
    printf "    toolname = [optional] Toolchain name\n"
    printf "    version  = [optional] JSON-C Version to upload\n"
    printf "    hash     = [optional] JSON-C Hash of archive to upload\n"
    printf "\n"
}

function usage_install()
{
    printf "\n"
    printf "To install the Security Middleware objects\n"
    printf "  %s install out=[dir] dest=[dir]\n" "${script_name}"
    printf "    out      = Build directory\n"
    printf "    dest     = [optional] Installation directory\n"
    printf "\n"
}

function usage_package()
{
    printf "\n"
    printf "To package the Security Middleware objects\n"
    printf "  %s package out=[dir]\n" "${script_name}"
    printf "    out      = Build directory\n"
    printf "\n"
}

function usage_se_package()
{
    printf "\n"
    printf "To package the Secure Enclave objects\n"
    printf "  %s package out=[dir]\n" "${script_name}"
    printf "    out      = Build directory\n"
    printf "\n"
}

function usage()
{
    printf "\n"
    printf "*******************************************\n"
    printf " Usage of Security Middleware build script \n"
    printf "*******************************************\n"
    usage_toolchain
    usage_zlib
    usage_seco
    usage_ele
    usage_teec
    usage_tadevkit
    usage_psaarchtests
    usage_jsonc
    usage_configure
    usage_build
    usage_install
    usage_package
    usage_se_package

    exit 1
}

check_cmake_version

if [[ $# -eq 0 ]]; then
    usage
fi

opt_action="$1"
shift

for arg in "$@"
do
    case ${arg} in
        arch=*)
            opt_arch="${arg#*=}"
            toolchain_script="${script_dir}/${opt_arch}_toolchain.cmake"
            if [[ ! -e "$toolchain_script" ]]; then
                pr_err "Unknown toolchain ${opt_arch}"
                usage
            fi

            opt_toolscript="-DCMAKE_TOOLCHAIN_FILE=${toolchain_script}"
            ;;

        toolpath=*)
            opt_toolpath="${arg#*=}"
            check_directory opt_toolpath
            opt_toolpath="-DTOOLCHAIN_PATH=${opt_toolpath}"
            ;;

        toolname=*)
            opt_toolname="${arg#*=}"
            opt_toolname="-DTOOLCHAIN_NAME=${opt_toolname}"
            ;;

        export=*)
            opt_export="${arg#*=}"
            check_directory opt_export
            ;;

        src=*)
            opt_src="${arg#*=}"
            check_directory opt_src
            ;;

        zlib=*)
            opt_zlib="${arg#*=}"
            check_directory opt_zlib
            opt_zlib="-DZLIB_ROOT=${opt_zlib}"
            ;;

        platform=*)
            opt_platform="${arg#*=}"
            opt_platform="-DPLATFORM=${opt_platform}"
            ;;

        out=*)
            opt_out="${arg#*=}"
            opt_builddir="-DBUILD_DIR=${opt_out}"
            ;;

        dest=*)
            opt_dest="${arg#*=}"
            ;;

        seco=*)
            opt_seco="${arg#*=}"
            opt_seco="-DSECO_ROOT=${opt_seco}"
            ;;

        ele=*)
            opt_ele="${arg#*=}"
            opt_ele="-DELE_ROOT=${opt_ele}"
            ;;

        teec=*)
            opt_teec="${arg#*=}"
            check_directory opt_teec
            opt_teec="-DTEEC_ROOT=${opt_teec}"
            ;;

        libuuid_config=*)
            opt_libuuid_config="${arg#*=}"
            check_directory opt_libuuid_config
            opt_libuuid_config="-DLIBUUID_CONFIG_ROOT=${opt_libuuid_config}"
            ;;

        tadevkit=*)
            opt_tadevkit="${arg#*=}"
            check_directory opt_tadevkit
            opt_tadevkit="-DTA_DEV_KIT_ROOT=${opt_tadevkit}"
            ;;

        coverage)
            opt_coverage="-DCODE_COVERAGE=ON"
            ;;

        debug)
            opt_buildtype="-DCMAKE_BUILD_TYPE=Debug"
            ;;

        verbose=*)
            opt_verbose="${arg#*=}"
            opt_verbose="-DVERBOSE=${opt_verbose}"
            ;;

        jsonc=*)
            opt_jsonc="${arg#*=}"
            check_directory opt_jsonc
            opt_jsonc="-DJSONC_ROOT=${opt_jsonc}"
            ;;

        version=*)
            opt_version="${arg#*=}"
            ;;

        hash=*)
            opt_hash="${arg#*=}"
            ;;

        format=*)
            opt_format="${arg#*=}"
            opt_format="-DFORMAT=${opt_format}"
            ;;

        psaarchtests=*)
            opt_psaarchtests="${arg#*=}"
            check_directory opt_psaarchtests
            opt_psaarchtests="-DPSA_ARCH_TESTS_SRC_PATH=${opt_psaarchtests}"
            ;;

        psa_default_alt)
            opt_psa="-DENABLE_PSA_DEFAULT_ALT=ON"
            ;;

        tls12)
            opt_tls12="-DENABLE_TLS12=ON"
            ;;

        all_options)
            opt_psa="-DENABLE_PSA_DEFAULT_ALT=ON"
            opt_tls12="-DENABLE_TLS12=ON"
            ;;

        #
        # Build option
        #
        all)
            opt_build="all"
            ;;
        smw)
            opt_build="smw"
            ;;
        pkcs11)
            opt_build="pkcs11"
            ;;
        tests)
            opt_build="tests"
            ;;
        docs)
            opt_build="docs"
            ;;

        *)
            pr_err "Unknown argument \"${arg}\""
            usage
            ;;
    esac

    shift
done

opt_toolchain="${opt_toolname} ${opt_toolpath} ${opt_toolscript}"

case ${opt_action} in
    toolchain)
        toolchain
        ;;

    zlib)
        zlib
        ;;

    seco)
        seco
        ;;

    ele)
        ele
        ;;

    teec)
        teec
        ;;

    tadevkit)
        tadevkit
        ;;

    psaarchtests)
        psaarchtests
        ;;

    configure)
        configure
        ;;

    build)
        build
        ;;

    jsonc)
        jsonc
        ;;

    install)
        install
        ;;

    package)
        package
        ;;

    se_package)
        se_package
        ;;
    *)
        usage
        ;;
esac
