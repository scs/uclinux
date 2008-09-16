#!/bin/sh

ip_addr=10.99.22.73
xenomai_test=xeno-test_new
load=workload

echo "-------------------------------------------------------"
rsh -lroot $ip_addr $xenomai_test latency -t0 -sh -T 120
echo "-------------------------------------------------------"
rsh -lroot $ip_addr $xenomai_test latency -t0 -sh -T 120 &
sleep 3 
rsh -lroot $ip_addr $load 

echo "-------------------------------------------------------"
rsh -lroot $ip_addr $xenomai_test latency -t1 -sh -T 120
echo "-------------------------------------------------------"
rsh -lroot $ip_addr $xenomai_test latency -t1 -sh -T 120 &
sleep 3
rsh -lroot $ip_addr $load

echo "-------------------------------------------------------"
rsh -lroot $ip_addr $xenomai_test latency -t2 -sh -T 120
echo "-------------------------------------------------------"
rsh -lroot $ip_addr $xenomai_test latency -t2 -sh -T 120 &
sleep 3
rsh -lroot $ip_addr $load

echo "-------------------------------------------------------"
rsh -lroot $ip_addr $xenomai_test switchtest -T 120
echo "-------------------------------------------------------"
rsh -lroot $ip_addr $xenomai_test switchtest -T 120 &
sleep 3
rsh -lroot $ip_addr $load

echo "-------------------------------------------------------"
rsh -lroot $ip_addr $xenomai_test switchbench -h
echo "-------------------------------------------------------"
rsh -lroot $ip_addr $xenomai_test switchbench -h &
sleep 2
rsh -lroot $ip_addr $load

echo "-------------------------------------------------------"
rsh -lroot $ip_addr $xenomai_test  cyclictest -p 10 -n -l 1000
echo "-------------------------------------------------------"
rsh -lroot $ip_addr $xenomai_test  cyclictest -p 10 -n -l 1000 &
sleep 1
rsh -lroot $ip_addr $load
