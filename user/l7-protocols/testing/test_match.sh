#!/bin/bash

extract()
{
	if [ -r $1 ]; then
	# this can miss psuedo-valid files that have crap after the pattern
		cat $1 | grep -v ^$ | grep -v ^# | tail -1
	else
		echo $1
	fi
}

if [ ! $1 ]; then
	echo Please specify a pattern or pattern file.
	exit 1
fi

if [ $2 ]; then
	times=$2
else
	times=500
fi

if [ -x ./randchars ] && [ -x ./match ] && [ -x ./randprintable ]; then
	true
else
	echo Can\'t find randchars, match or randprintable.  
	echo They should be in this directory.  Did you say \"make\"?
	exit 1
fi

printf "Out of $times random streams, this many match: "

pattern="`extract $1`"

for f in `seq $times`; do
	if [ $2 ]; then printf . > /dev/stderr; fi
	if ! ./randchars | ./match $pattern; then exit 1; fi
done | grep -v No -c

printf "Out of $times printable random streams, this many match: " 

for f in `seq $times`; do
	if [ $2 ]; then printf . > /dev/stderr; fi
	if ! ./randprintable | ./match $pattern; then exit 1; fi
done | grep -v No -c
