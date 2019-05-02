#!/bin/bash

$@ &

target_pid=$!

timeout=${TIMEOUT:=30}

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

#echo $target_pid

kill -0 $target_pid >& /dev/null

#echo $?

if [ "0" == "$?" ]
then
    echo "--> FAIL   --  Timed out"
    kill ${target_pid} >& /dev/null
    sleep 1
    kill -9 ${target_pid} >& /dev/null
fi

