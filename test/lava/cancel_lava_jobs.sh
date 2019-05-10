#!/bin/bash

jobs=`cat LAVA_JOBS`

joblist=`lavacli --identity master.stec jobs list --limit 100`

for jobid in $jobs
do
    if [[ $joblist != *"${jobid}: Finished"* ]]
    then
        echo Cancelling ${jobid} - http://lava-master.sw.nxp.com/scheduler/job/${jobid}
        lavacli --identity $1 jobs cancel ${jobid}
    fi
done

