#!/bin/sh

./fs_inod_bf /tmp 10 10 1

echo "*** file operation test. ***"

echo
echo "*** feof test ***"
./feof_test

echo 
echo "*** fgets test 02 ***"

./fgets_test02

echo 
echo "*** fprintf test ***"

./fprintf_test

echo 
echo "*** fputs_puts test ***"
./fputs_puts_test

echo 

echo "*** fscanf test ***"
./fscanf_test

echo 
echo "*** fsetpos test ***"
./fsetpos_test

echo 
echo "*** ftell_rewind test ***"
./ftell_rewind_test

echo 
echo "*** fflush test ***"
./fflush_test

echo 
echo "*** fgetpos test ***"
./fgetpos_test

echo 
echo "*** fopen_fclose test ***"
./fopen_fclose_test

echo 
echo "*** fputc_fgetc test ***"
./fputc_fgetc_test

echo 
echo "*** fread_fwrite test ***"
./fread_fwrite_test

echo 
echo "*** fseek test ***"
./fseek_test

echo 
echo "*** fsx-linux test ***"
./fsx-linux


