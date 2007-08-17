#!/bin/sh
# alltests.sh
# David Rowe 9 October 2006
#
# Run all test vector through encoder and decoder. Tests
# pass if silent.

# The tests commented out failed but after disucssions with Adam Li-Yi
# at Analog we worked out that they were not valid tests for this
# codec, the vectors had been accidentally included.

TEST_DIR=/var
G729A_ENC_IN=$TEST_DIR/test_data/g729a/std_in_en
G729A_ENC_OUT=$TEST_DIR/test_data/g729a/std_out_en
G729A_DEC_IN=$TEST_DIR/test_data/g729a/std_in_de
G729A_DEC_OUT=$TEST_DIR/test_data/g729a/std_out_de
G729AB=$TEST_DIR/test_data/g729ab

# G729A encode tests

./$1 $G729A_ENC_IN/ALGTHM.IN $G729A_ENC_OUT/ALGTHM.BIT --enc --g729a --mips
./$1 $G729A_ENC_IN/FIXED.IN $G729A_ENC_OUT/FIXED.BIT --enc --g729a --mips
./$1 $G729A_ENC_IN/LSP.IN $G729A_ENC_OUT/LSP.BIT --enc --g729a --mips
./$1 $G729A_ENC_IN/PITCH.IN $G729A_ENC_OUT/PITCH.BIT --enc --g729a --mips
./$1 $G729A_ENC_IN/SINE.BIN $G729A_ENC_OUT/SINEA.BIT --enc --g729a --mips
./$1 $G729A_ENC_IN/SPEECH.IN $G729A_ENC_OUT/SPEECH.BIT --enc --g729a --mips
./$1 $G729A_ENC_IN/TAME.IN $G729A_ENC_OUT/TAME.BIT --enc --g729a --mips

#./$1 $G729A_ENC_IN/TSTSEQ1.BIN $G729A_ENC_OUT/TSTSEQ1A.BIT --enc --g729a
#./$1 $G729A_ENC_IN/TSTSEQ2.BIN $G729A_ENC_OUT/TSTSEQ2A.BIT --enc --g729a
#./$1 $G729A_ENC_IN/TSTSEQ3.BIN $G729A_ENC_OUT/TSTSEQ3A.BIT --enc --g729a
#./$1 $G729A_ENC_IN/TSTSEQ4.BIN $G729A_ENC_OUT/TSTSEQ4A.BIT --enc --g729a

# G729A decode tests

./$1 $G729A_DEC_IN/ALGTHM.BIT $G729A_DEC_OUT/ALGTHM.PST --dec --g729a --mips
./$1 $G729A_DEC_IN/FIXED.BIT $G729A_DEC_OUT/FIXED.PST --dec --g729a --mips
./$1 $G729A_DEC_IN/LSP.BIT $G729A_DEC_OUT/LSP.PST --dec --g729a --mips
./$1 $G729A_DEC_IN/PITCH.BIT $G729A_DEC_OUT/PITCH.PST --dec --g729a --mips
./$1 $G729A_DEC_IN/SINEA.BIT $G729A_DEC_OUT/SINEA.OUT --dec --g729a --mips
./$1 $G729A_DEC_IN/SPEECH.BIT $G729A_DEC_OUT/SPEECH.PST --dec --g729a --mips
./$1 $G729A_DEC_IN/TAME.BIT $G729A_DEC_OUT/TAME.PST --dec --g729a --mips 
./$1 $G729A_DEC_IN/ERASURE.BIT $G729A_DEC_OUT/ERASURE.PST --dec --g729a --mips
./$1 $G729A_DEC_IN/OVERFLOW.BIT $G729A_DEC_OUT/OVERFLOW.PST --dec --g729a --mips

./$1 $G729A_DEC_IN/TSTSEQ1A.BIT $G729A_DEC_OUT/TSTSEQ1A.OUT --dec --g729a --mips
./$1 $G729A_DEC_IN/TSTSEQ2A.BIT $G729A_DEC_OUT/TSTSEQ2A.OUT --dec --g729a --mips
./$1 $G729A_DEC_IN/TSTSEQ3A.BIT $G729A_DEC_OUT/TSTSEQ3A.OUT --dec --g729a --mips
./$1 $G729A_DEC_IN/TSTSEQ4A.BIT $G729A_DEC_OUT/TSTSEQ4A.OUT --dec --g729a --mips
./$1 $G729A_DEC_IN/TSTSEQ5.BIT $G729A_DEC_OUT/TSTSEQ5A.OUT --dec --g729a --mips
#./$1 $G729A_DEC_IN/TSTSEQ6.BIT $G729A_DEC_OUT/TSTSEQ6A.OUT --dec --g729a 

# G729AB encode tests

./$1 $G729AB/tstseq1.bin $G729AB/tstseq1a.bit --enc --g729ab --mips
./$1 $G729AB/tstseq2.bin $G729AB/tstseq2a.bit --enc --g729ab --mips
./$1 $G729AB/tstseq3.bin $G729AB/tstseq3a.bit --enc --g729ab --mips
./$1 $G729AB/tstseq4.bin $G729AB/tstseq4a.bit --enc --g729ab --mips

# G729AB decode tests

./$1 $G729AB/tstseq1a.bit $G729AB/tstseq1a.out --dec --g729ab --mips
./$1 $G729AB/tstseq2a.bit $G729AB/tstseq2a.out --dec --g729ab --mips
./$1 $G729AB/tstseq3a.bit $G729AB/tstseq3a.out --dec --g729ab --mips
./$1 $G729AB/tstseq4a.bit $G729AB/tstseq4a.out --dec --g729ab --mips
./$1 $G729AB/tstseq5.bit $G729AB/tstseq5a.out --dec --g729ab --mips
#./$1 $G729AB/tstseq6.bit $G729AB/tstseq6a.out --dec --g729ab


