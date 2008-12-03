#!/bin/sh

if [ $# -ne 4 ]; then
    echo "Usage: $0 [input_file] [output_type] [plt_config_location] [output_format]"
    echo "output_type: snd, dft, 3dft, 3dft_ex"
    echo "output_format: ps, png"
    echo "example: $0 test.wav dft ./plt ps"
    exit 1
fi

if [ $2 == snd ]; then
    output_opt="-w"
elif [ $2 == dft ]; then
    output_opt=""
elif [ $2 == 3dft ] || [ $2 == 3dft_ex ]; then
    output_opt="-3"
else
    echo "No such output_type. Exit!"
    exit 1
fi
prefix=`basename $1 .wav`

snd2fftw $output_opt -i $1 -o $2.dat
if [ $? -ne 0 ]; then
    echo "FAIL: snd2fftw $output_opt -i $1 -o $2.dat"
    exit 1
else
    echo "PASS: snd2fftw $output_opt -i $1 -o $2.dat"
fi

gnuplot $3/plot_$2.plt
if [ $? -ne 0 ]; then
    echo "FAIL: gnuplot $3/plot_$2.plt"
    exit 1
else
    echo "PASS: gnuplot $3/plot_$2.plt"
fi

if [ $4 == png ]; then
    mogrify -trim -interlace line $2.png
    if [ $? -ne 0 ]; then
        echo "FAIL: mogrify -trim -interlace line $2.png"
        exit 1
    else
        echo "PASS: mogrify -trim -interlace line $2.png"
    fi
fi

mv $2.dat $prefix.$2.dat
if [ $? -ne 0 ]; then
    echo "FAIL: modify file name $2.dat"
    exit 1
else
    echo "PASS: modify file name $2.dat"
fi

if [ $4 == png ]; then
    mv $2.png $prefix.$2.png
    if [ $? -ne 0 ]; then
        echo "FAIL: modify file name $2.png"
        exit 1
    else
        echo "PASS: modify file name $2.png"
    fi
fi

if [ $4 == ps ]; then
    mv $2.ps  $prefix.$2.ps
    if [ $? -ne 0 ]; then
        echo "FAIL: modify file name $2.ps"
        exit 1
    else
        echo "PASS: modify file name $2.ps"
    fi
fi

echo "Audio DFT finish"
exit 0
