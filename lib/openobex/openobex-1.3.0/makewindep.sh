#This litte script will use GCC to generate dependecies for win32. 
#It needs cygwin etc...

cd $2
gcc $1 -I"$INCLUDE" -MM *.c| sed s/\.o:/\.obj:/ >windeps.dep
