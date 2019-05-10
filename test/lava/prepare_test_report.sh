#!/bin/bash

exec_dir=`dirname $0 | xargs realpath`

data=`${exec_dir}/accumulate_lava_results.sh $@ | grep -P '^\S+ <|TEST RESULT' | grep -vP '<test>|<\/test>|<LAVA_SIGNAL' | grep -oP '<.+|TEST RESULT.+'`

echo "$data" | awk '
  BEGIN {
     RS="<[^>]+>"
     print "filename\trequirements\tdescription\tF\tP"
  }
  {
      gsub(/\n/,"",$0)
      if (/TEST RESULT/)
      {
          patsplit($0, v, ": *", seps)
          patsplit(seps[1], v, " ", pf)
          vars[pf[1]]=pf[0]
          vars[pf[3]]=pf[2]
          print vars["filename"] "\t" vars["requirement"] "\t" vars["description"] "\t" vars["F"] "\t" vars["P"]
          delete vars
      }
      else
      {
          patsplit(RT, v, "</|>", seps);
          if (length(seps)>1)
          {
              if (seps[1] in vars) { vars[seps[1]] = vars[seps[1]] ", " }
              vars[seps[1]] = vars[seps[1]] $0
          }
      }
  }
'

