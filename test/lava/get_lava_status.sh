#!/bin/bash

#lavacli --identity $1 jobs list --limit 100 | grep -f LAVA_JOBS

jobs=`cat LAVA_JOBS`

for jobid in $jobs
do
    lavacli --identity $1 jobs show ${jobid} | awk '
            { split($0,p," *: "); vars[p[1]] = p[2]; }
            END { print vars["id"]": "vars["state"]","vars["Health"]" ["vars["submitter"]"] " vars["description"]" - "vars["device"]}
            '
done

