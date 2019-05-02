#!/bin/bash

jobs=`cat LAVA_JOBS`

total_fails=0
total_passes=0

for jobid in $jobs
do
    echo "-----------------------------------------------------------------"
    echo ${jobid} - http://lava-master.sw.nxp.com/scheduler/job/${jobid}
    echo "-----------------------------------------------------------------"

    # Fetch the log for this job
    if [ ! -f ${jobid}.log ]
    then
        lavacli --identity $1 jobs logs ${jobid} > ${jobid}.log
    fi
    test=`sed -E -n "/<test>/,/<\/test>/p" ${jobid}.log`

    if [ -z "$test" ]
    then

        # For a non-test, print just the portions bounded by <LAVA_SIGNAL_STARTRUN ... <..ENDRUN
        output=`sed -E -n "/<LAVA_SIGNAL_STARTRUN/,/<LAVA_SIGNAL_ENDRUN/p" ${jobid}.log`
        echo "$output"

    else

        # For a test, print just the portions bounded by <test> ... </test>
        echo "${test}" | awk '{print $0; if (/<\/test>|Segmentation fault|Cleaning after the job/) { print ""; print "TEST RESULT: "fail" F "pass" P"; print ""; pass=0; fail=0} else if (/PASS/) {pass++} else if (/FAIL/) {fail++} }'

        # Count PASS and FAIL markers
        fails=`echo "${test}" | grep -c '> FAIL'`
        passes=`echo "${test}" | grep -c '> PASS'`
#        echo "RESULT: ${fails} F  ${passes} P"

        # Accumulate PASS and FAIL counts
        total_fails=$((total_fails + fails))
        total_passes=$((total_passes + passes))

    fi

    echo ""
done

echo "TOTALS:  ${total_fails} F  ${total_passes} P"

# Exit with the total number of fails, so that any fail makes the script return a non-zero value (fail code)
exit $total_fails
