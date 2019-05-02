#!/bin/bash

jobs=`cat LAVA_JOBS`

for jobid in $jobs
do
    echo "-----------------------------------------------------------------"
    echo ${jobid}
    echo "-----------------------------------------------------------------"
    lavacli --identity $1 jobs logs ${jobid} > ${jobid}.log
    sed -n "/<test>/,/<\/test>/p" ${jobid}.log
done

