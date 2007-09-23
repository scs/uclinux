#!/bin/sh

total=`awk '// { sum += $1 }; END { print sum }' $1`
tab=`echo "x=l($total)/l(10); scale =0 ; x/1" | bc -l`
for sum in `awk '{ print $4}' $1 | awk -F : '{ print $1}' | sort | uniq`
do
  sum_fig=`grep "$sum:" $1 | awk '// { sum += $1 }; END { print sum }'`
  if [ -z $sum_fig ] ; then
     sum_fig=`grep "$sum" $1 | awk '// { sum += $1 }; END { print sum }'`
  fi
  if [ -z $sum_fig ] ; then
    sum_sed=`echo $sum | sed 's/\]/\\\]/' | sed 's/\[/\\\[/'`
    sum_fig=`grep "$sum_sed:" $1 | awk '// { sum += $1 }; END { print sum }'`
  fi
  sum_percent=`echo "scale=2; $sum_fig * 100 / $total" | bc`
  j=`echo "scale=2; length($sum_fig * 100 / $total)" | bc`
  i=`echo "x=l($sum_fig)/l(10); scale =0 ; $tab - x/1 " | bc -l`
  while [ $i -gt 0 ]
  do
    i=`expr $i - 1`
    echo -n " "
  done
  echo -n "$sum_fig ("
  if [ "${sum_percent}" = "0" ] ; then
    echo -n "  .00%) "
  else
    while [ $j -lt 4 ]
    do
      j=`expr $j + 1`
      echo -n " "
    done
    echo -n "$sum_percent%) "
  fi
  echo $sum
done
