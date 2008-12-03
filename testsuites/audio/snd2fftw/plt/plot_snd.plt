set grid
set xlabel "Time (s)"
set ylabel "Amplitude [-1:1]"
set xtics rotate

set terminal postscript color colortext solid enhanced
set output "snd.ps"
plot "snd.dat" notitle with lines

unset grid
set terminal png transparent interlace large size 400,300 enhanced
set output "snd.png"
plot "snd.dat" notitle with lines
