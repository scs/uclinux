#!/bin/sh

cd test/logs
 
if [ ! -f summary.new ] ; then
  touch summary.new
  chmod 777 summary.new
fi

summary_file=$1

cat $summary_file > summary.new

if [ ! -f detailed.new ] ; then
  touch detailed.new
  chmod 777 detailed.new
fi

detailed_file=$2

cat $detailed_file > detailed.new


