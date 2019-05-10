#!/bin/bash
#
# Get a specific list of lava jobs and their current status
#
# This will work at any time, as long as the jobs are still in the lava database.
#
# If no ids are specified, read the ids from a file, LAVA_JOBS
#

identity=$1
shift

if [ "0" != $# ]
then
    jobs=$@
else
    jobs=`cat LAVA_JOBS`
fi

for jobid in $jobs
do
    lavacli --identity $identity jobs show ${jobid} | awk '
            { split($0,p," *: "); vars[p[1]] = p[2]; }
            END { print vars["id"]": "vars["state"]","vars["Health"]" ["vars["submitter"]"] " vars["description"]" - "vars["device"]}
            '
done

