#!/bin/bash

exec_dir=`dirname $0 | xargs realpath`

data=`${exec_dir}/accumulate_lava_results.sh $@ | grep -P '^\S+ <|TEST RESULT' | grep -vP '<test>|<\/test>|<LAVA_SIGNAL'`

echo "$data"

#requirements=[]

#echo "$data" | awk 'BEGIN { } { if (/TEST RESULT/) { print ; reqs="" } }'

