#!/bin/sh 

BEFORE=$1
NOW=$2

fail=1
pass=0
result=$pass

tmp2=/tmp/tmp.diff

if [ ! -e $BEFORE ] ; then
  echo "$BEFORE is not existing"
  exit $fail
fi

if [ ! -e $NOW ] ; then
  echo "$NOW is not existing"
  exit $fail
fi


num_before=`grep -nr "Passed Tests" $BEFORE | head -1 | awk '{print $5}'`
grep -nr "Passed Tests List"  -A `expr $num_before + 1` $BEFORE | tail -$num_before | awk '{print $3}' | sort > /tmp/tmp.before
num_now=`grep -nr "Failed Tests" $NOW | head -1 | awk '{print $5}'`
grep -nr "Failed Tests List"  -A `expr $num_now + 1` $NOW | tail -$num_now | awk '{print $3}'  > /tmp/tmp.now1
num_now=`grep -nr "Broken Tests" $NOW | head -1 | awk '{print $5}'`
grep -nr "Broken Tests List"  -A `expr $num_now + 1` $NOW | tail -$num_now | awk '{print $3}'  >> /tmp/tmp.now1
num_now=`grep -nr "Warning Tests" $NOW | head -1 | awk '{print $5}'`
grep -nr "Warning Tests List"  -A `expr $num_now + 1` $NOW | tail -$num_now | awk '{print $3}' >> /tmp/tmp.now1 
cat /tmp/tmp.now1 | sort > /tmp/tmp.now

    comm -12 /tmp/tmp.before /tmp/tmp.now > $tmp2
    grep -s . $tmp2 >/dev/null
if [ $? = 0 ]; then
        echo "Old tests that passed, now have failed, broken or have warnings"
        echo
        cat $tmp2
        echo
	result=$fail
fi
    
num_before=`grep -nr "Failed Tests" $BEFORE | head -1 | awk '{print $5}'`
grep -nr "Failed Tests List"  -A `expr $num_before + 1` $BEFORE | tail -$num_before | awk '{print $3}'  > /tmp/tmp.before1
num_before=`grep -nr "Broken Tests" $BEFORE | head -1 | awk '{print $5}'`
grep -nr "Broken Tests List"  -A `expr $num_before + 1` $BEFORE | tail -$num_before | awk '{print $3}'  >> /tmp/tmp.before1
num_before=`grep -nr "Warning Tests" $BEFORE | head -1 | awk '{print $5}'`
grep -nr "Warning Tests List"  -A `expr $num_before + 1` $BEFORE | tail -$num_before | awk '{print $3}' >> /tmp/tmp.before1 
cat /tmp/tmp.before1 | sort > /tmp/tmp.before
num_now=`grep -nr "Passed Tests" $NOW | head -1 | awk '{print $5}'`
grep -nr "Passed Tests List"  -A `expr $num_now + 1` $NOW | tail -$num_now | awk '{print $3}' | sort > /tmp/tmp.now

    comm -12 /tmp/tmp.before /tmp/tmp.now > $tmp2
    grep -s . $tmp2 >/dev/null
if [ $? = 0 ]; then
        echo "Old tests that failed, broken or have warnings, now have passed:"
        echo
        cat $tmp2
        echo
fi


num_before=`grep -nr "Crashing Tests" $BEFORE | head -1 | awk '{print $5}'`
grep -nr "Crashing Tests List"  -A `expr $num_before + 1` $BEFORE | tail -$num_before| awk '{print $3}' | sort >  /tmp/tmp.before
num_now=`grep -nr "Crashing Tests" $NOW | head -1 | awk '{print $5}'`
grep -nr "Crashing Tests List"  -A `expr $num_now + 1` $NOW | tail -$num_now | awk '{print $3}' | sort > /tmp/tmp.now

    comm -13 /tmp/tmp.before /tmp/tmp.now > $tmp2
    grep -s . $tmp2 >/dev/null
if [ $? = 0 ]; then
        echo "New cases that crash:"
        echo
        cat $tmp2
        echo
	result=$fail
fi

  comm -23 /tmp/tmp.before /tmp/tmp.now > $tmp2
    grep -s . $tmp2 >/dev/null
if [ $? = 0 ]; then
        echo "Old cases that crash now disappear :"
        echo
        cat $tmp2
        echo
fi


num_before=`grep -nr "Skipped Tests" $BEFORE | head -1 | awk '{print $5}'`
grep -nr "Skipped Tests List"  -A `expr $num_before + 1` $BEFORE | tail -$num_before | awk '{print $3}' | sort >  /tmp/tmp.before
num_now=`grep -nr "Skipped Tests" $NOW | head -1 | awk '{print $5}'`
grep -nr "Skipped Tests List"  -A `expr $num_now + 1` $NOW | tail -$num_now | awk '{print $3}' | sort > /tmp/tmp.now

    comm -13 /tmp/tmp.before /tmp/tmp.now > $tmp2
    grep -s . $tmp2 >/dev/null
if [ $? = 0 ]; then
        echo "New cases that are not running:"
        echo
        cat $tmp2
        echo
	result=$fail
fi

  comm -23 /tmp/tmp.before /tmp/tmp.now > $tmp2
    grep -s . $tmp2 >/dev/null
if [ $? = 0 ]; then
        echo "Old cases that skipped now are running:"
        echo
        cat $tmp2
        echo
fi

exit $result
