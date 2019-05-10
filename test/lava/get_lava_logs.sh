#!/bin/bash

jobs=`cat LAVA_JOBS`

for jobid in $jobs
do
    echo "-----------------------------------------------------------------"
    echo ${jobid} - http://lava-master.sw.nxp.com/scheduler/job/${jobid}
    echo "-----------------------------------------------------------------"
    lavacli --identity $1 jobs logs ${jobid} | tee ${jobid}.log | sed -n "/<LAVA_SIGNAL_STARTRUN /,/<LAVA_SIGNAL_ENDRUN /p"
done

