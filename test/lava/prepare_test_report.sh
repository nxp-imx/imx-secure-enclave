#!/bin/bash

exec_dir=`dirname $0 | xargs realpath`

data=`${exec_dir}/accumulate_lava_results.sh $@ | grep -P '^\S+ <|TEST RESULT' | grep -vP '<test>|<\/test>|<LAVA_SIGNAL' | grep -oP '<.+|TEST RESULT.+'`

#echo "$data"
#requirements=[]

fields=[]
line=[]

echo "$data" | awk '
  BEGIN { }
  {
      if (/TEST RESULT/)
      {
          print ; reqs=""
      }
      else
      {
          print
      }
  }
  END { print "DONE" }
'

