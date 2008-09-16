#!/bin/bash

# "man 1 time" for details
export TIME="%U seconds"

add()
{
	if ! dc -e ""; then
	        echo you do not have dc, so I cannot add these numbers...
	        exit 1
	fi

	n=0
	tot=0

	while read n; do
	        tot=`dc -e "$n $tot + pop" 2> /dev/null`
	done

	echo $tot seconds
}

extract()
{
	if [ -r $1 ] && [ -f $1 ]; then
#		echo Interpreting argument as a file name... > /dev/stderr
		cat $1 | grep -v ^$ | grep -v ^# | tail -1
	else
		echo > /dev/stderr
		echo Argument is not a readable file, so interpreting it as a regexp string... > /dev/stderr
		echo $1
	fi
}

if [ ! $2 ]; then
	echo Syntax: ./timeit.sh patternfile all\|print\|real [data_files]
	echo \"all\" tests against all characters, 
	echo \"print\" only against printable ones,
	echo \"real\" against some real data.
	echo In real mode, if data files are specified, they are used,
	echo otherwise, all files in data/ are used.
	exit 1
fi

if [ -x ./randchars ] && [ -x ./randprintable ] && [ -x ./test_speed ]; then
	true
else
	echo Can\'t find randchars, randprintable or test_speed.
	echo They should be in this directory.  Did you say \"make\"?
	exit 1
fi

echo

echo Timing $1
if [ $2 == "all" ]; then
	echo Using all characters
	./randchars | time ./test_speed "`extract $1`" verbose
elif [ $2 == "print" ]; then
	echo Using only printable characters
	./randprintable | time ./test_speed "`extract $1`" verbose
elif [ $2 == "real" ]; then
	echo Using some real data

	# uncomment to be able to exit all at once
	trap "rm tmp.$$; echo; exit 1" 2

	if [ $3 ]; then 
		for f in $@; do
			if [ -r $f ] && [ $f != $1 ] && [ $f != $2 ]; then
				printf $f\\t
				echo `extract $1`
				cat $f | time ./test_speed "`extract $1`" 2> /dev/stdout | tee -a tmp.$$
			fi
		done
	else
		for f in data/*; do
			printf $f\\t
			cat $f | time ./test_speed "`extract $1`" 2> /dev/stdout | tee -a tmp.$$
		done
	fi

	printf Total:\ 
	cat tmp.$$ | cut -d\  -f 2 | add

	rm tmp.$$
else
	echo Please specify \"all\", \"print\" or \"real\"> /dev/stderr
	exit 1
fi
