set grid
set xlabel "Frequency (Hz)"
set ylabel "Energy"
set xtics rotate

set terminal postscript color colortext solid enhanced
set output "dft.ps"
plot "dft.dat" notitle with lines

#unset grid
#set terminal png transparent interlace large size 400,300 enhanced
#set output "dft.png"
#plot "dft.dat" notitle with lines
