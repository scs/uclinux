#!/bin/sh
# the script for test msh function call
echo "define function do_sysctl"

test_function1(){
	echo "$0 executed in test_function1!"
}

test_function2()
{
	echo "$0 executed in test_function2!" 
}

# check if function is executed correctly
echo "before function exec"

test_function1

test_function2

echo "finish exec"

