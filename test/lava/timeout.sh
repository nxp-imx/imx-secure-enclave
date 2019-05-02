#!/bin/bash

# 
# Execute a command and kill it if it takes too long
#

# Implement a timeout of 30 seconds by default
timeout=${TIMEOUT:=30}

if [ "$#" == "0" ]
then
    echo "Execute a command and timeout after a given time in seconds."
    echo "The timeout value is "${timeout}" seconds."
    echo ""
    echo "Usage:"
    echo "    [TIMEOUT=seconds] $0 <executable command>"
    exit -1
fi

# Execute the specified command in the background, and get its pid
$@ &

target_pid=$!

while [ "${timeout}" -gt 0 ]
do
    sleep 1
    ((timeout--))
    kill -0 $target_pid >& /dev/null
    if [ "0" != "$?" ]
    then
        timeout=0
    fi
done

kill -0 $target_pid >& /dev/null

if [ "0" == "$?" ]
then
    echo "--> FAIL   --  Timed out"
    kill ${target_pid} >& /dev/null
    sleep 1
    kill -9 ${target_pid} >& /dev/null
fi

