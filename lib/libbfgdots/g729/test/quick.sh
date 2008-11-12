#!/bin/sh -x
# quick.sh
# David Rowe 9 October 2006
#
# Quick test of all four operating modes, prints MIPs out as well.

TEST_DIR=/var
#LD_DEBUG=all ./$1 $TEST_DIR/test_data/g729a/std_in_en/SINE.BIN $TEST_DIR/test_data/g729a/std_out_en/SINEA.BIT --enc --g729a --mips
$1 $TEST_DIR/test_data/g729a/std_in_en/SINE.BIN $TEST_DIR/test_data/g729a/std_out_en/SINEA.BIT --enc --g729a --mips --multi
$1 $TEST_DIR/test_data/g729a/std_in_de/SINEA.BIT $TEST_DIR/test_data/g729a/std_out_de/SINEA.OUT --dec --g729a --mips --multi
$1 $TEST_DIR/test_data/g729ab/tstseq1.bin $TEST_DIR/test_data/g729ab/tstseq1a.bit --enc --g729ab --mips --multi
$1 $TEST_DIR/test_data/g729ab/tstseq1a.bit $TEST_DIR/test_data/g729ab/tstseq1a.out --dec --g729ab --mips --multi
