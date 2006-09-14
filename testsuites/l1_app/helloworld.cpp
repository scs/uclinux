#include <stdio.h>
#include "helloworldcpp.h"

helloworld::helloworld(char *str)
{
	this->str=str;
}

int helloworld::show_result()
{
	int i,r;
	i = 0;
	r = i+2;
	printf("%s", this->str);
	return r;
}

helloworld::~helloworld()
{
}

