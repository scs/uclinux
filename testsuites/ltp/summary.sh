#!/bin/sh

cd /home/main-cvs/ltp/test/logs
 
if [ ! -f summary.new ] ; then
  touch summary.new
  chmod 777 summary.new
fi

summary_file=$1

cat $summary_file > summary.new


