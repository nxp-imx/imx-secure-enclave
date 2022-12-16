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
eval "./scripts/se_build.sh zlib arch=$2 src=zlib export=zlib"
eval "./scripts/se_build.sh $1 arch=$2 src=./ zlib=./zlib export=$3"
