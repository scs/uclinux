set pm3d at s hidden3d 100
set style line 100 lt 20 lw 0
set palette model XYZ functions gray**0.35, gray**0.5, gray**0.8
unset hidden3d
unset surf
set view 50,145
set border 1023-128
#set contour base
#set cntrparam bspline
unset clabel
unset colorbox
set grid xtics ytics ztics
set xlabel 'Time (s)'
set ylabel 'Frequency (Hz)'
set zlabel 'Energy'
set terminal postscript enhanced color colortext solid
set output "3dft_ex.ps"
splot '3dft_ex.dat' notitle
set terminal png transparent interlace large size 800,600 enhanced
set output "3dft_ex.png"
splot '3dft_ex.dat' every 2 notitle
