#!/bin/bash

CDIR=$(pwd)
pattern_c='*.c'
pattern_h='*.h'
pattern_mk='*.mk'
pattern_make='Makefile'
pattern3='mainpage.h'
for i in $(ls ../ -R | grep :)
do
	DIR=${i%:}
	cd $DIR
	for FILE in *
	do
		if [[ -f $FILE ]]
		then
			check_data=`cat $FILE | grep "SPDX-License-Identifier: BSD-3-Clause"`
			[ -z "$check_data" ] && {
				if [[ $FILE != $pattern3 && \
				    ( $FILE == $pattern_c ||\
				      $FILE == $pattern_h ||\
				      $FILE == $pattern_mk ||\
				      $FILE == $pattern_make ) ]]
				then
					sed -i '/./,$!d' $FILE
					sed -i '3,11d;' $FILE
					if [[ $FILE == $pattern_c ||\
					      $FILE == $pattern_h ]]
					then
						sed -i '1s;^;
						// SPDX-License-Identifier:\
						 BSD-3-Clause\n;' $FILE
					fi
					if [[ $FILE == $pattern_mk ||\
					      $FILE == $pattern_make ]]
					then
						sed -i '1s;^;
						# SPDX-License-Identifier:\
						 BSD-3-Clause\n;' $FILE
					fi

				fi
			}
		fi
	done
	cd $CDIR
done
