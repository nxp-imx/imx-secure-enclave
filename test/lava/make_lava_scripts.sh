#!/bin/bash

containsElement () {
  local e match="$1"
  shift
  for e; do [[ "$e" == "$match" ]] && return 0; done
  return 1
}

if [ "2" != $# ]
then
    echo "Usage: $0 <artifactUrl> <submitter>"
    exit -1
fi

artifactUrl=$1
submitter=$2

thisDir=`realpath $0 | xargs dirname`

echo Artifact URL: ${artifactUrl}
echo Submitter: ${submitter}

# Exported variables are replaced in the lava script by <envsubst>

export SUBMITTER=${submitter}
export TEST_PACKAGE_PATH=${artifactUrl}/she_test.tar.bz2/she_test.tar.bz2
export BOOTIMG_PATH=${artifactUrl}/bootimg.qm.bin/bootimg.bin
export KERNEL_PATH=${artifactUrl}/Image/Image
export MODULES_PATH=${artifactUrl}/modules.tar.bz2/modules.tar.bz2
export DTB_PATH=${artifactUrl}/fsl-imx8qm-lpddr4-arm2.dtb/fsl-imx8qm-lpddr4-arm2.dtb
export RAMDISK_PATH=${artifactUrl}/rootfs.cpio.gz/rootfs.cpio.gz

## Read the contents of the test package to obtain the list of tests to run
tests=(`wget -q -O - ${TEST_PACKAGE_PATH} | tar tjf - | grep '\.shx$' | sort`)

# Make a directory for lava files
mkdir -p lava

cd lava
echo "# LAVA Launch script: ${submitter} - ${artifactUrl}" > launch_tests
chmod +x launch_tests

echo "touch LAVA_JOBS" >> launch_tests

# Deploy a new uboot
export JOB_NAME="STEC SECO FW Test - SHE - Deploy bootimage.bin (${submitter})"
export RUN_TEST="wget --no-check-certificate ${BOOTIMG_PATH} && ls -l && dd if=bootimg.bin of=/dev/mmcblk1 bs=1 seek=32k conv=sync,noerror"
cat ${thisDir}/l_rd_runtest.json | envsubst > deploy_bootimg.json || exit -2
echo 'lavacli --identity $1'" jobs submit deploy_bootimg.json | tee -a LAVA_JOBS" >> launch_tests

# Set up lava jobs to run all of the tests -- for each directory, a new lava job is created, which causes a device reboot
testdir=""
lavafile=""

# Get the list of test suites to execute (one suite per lava job)
testsuites=`dirname ${tests[@]} | uniq`

for testsuite in ${testsuites}
do
    echo "Creating lava file for: ${testsuite}"

    export JOB_NAME="STEC SECO FW Test - SHE - ${thisdirname} (${submitter})"
    export RUN_TEST="wget --no-check-certificate -O - ${TEST_PACKAGE_PATH} | bunzip2 -c | tar xvf - "
    export RUN_TEST="${RUN_TEST} && ./run_tests ${testsuite}"

    # Build a lava file for each test, replacing variables with values from the environment
    mkdir -p ${testsuite}
    lavafile="${testsuite}/runtests.json"
    cat ${thisDir}/l_rd_runtest.json | envsubst > ${lavafile} || exit -2

    # Add this file to the lava launch script
    echo 'lavacli --identity $1'" jobs submit ${lavafile} | tee -a LAVA_JOBS" >> launch_tests
done

# Copy status scripts to the output directory
cp $thisDir/*sh .

echo "Query status at http://lava-master.sw.nxp.com/results/query/+custom?entity=testsuite&conditions=namedtestattribute__submitter__exact__${SUBMITTER}"

echo "http://lava-master.sw.nxp.com/results/query/+custom?entity=testsuite&conditions=namedtestattribute__submitter__exact__${SUBMITTER}" > query_status

cd ..

