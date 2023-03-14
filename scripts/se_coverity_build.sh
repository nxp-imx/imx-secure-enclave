#!/bin/bash
set -e

function usage()
{
	    cat << EOF

    ******************************************************
    * Usage of Security Middleware Coverity build script *
    ******************************************************

    Script is cleaning first the SMW targets and then
    rebuild all targets configured in given directory.

    It is assumed that projects have been configured before calling
    this script and dependencies built as well.

    $(basename "$0") <dir>
      <dir> : Mandatory build directory

EOF
    exit 1
}

if [[ $# -ne 3 ]]; then
	    usage
fi

echo $1

# Clean build targets first
eval "make PLAT=$1 clean; rm -rf $3"

# Rebuild targets
echo "*****************se_coverity_build.sh**********************\n"
eval "./scripts/se_build.sh $1 cov_scan="1" arch=$2 src=./ export=$3"
echo "*****************se_coverity_build.sh**********************\n"
