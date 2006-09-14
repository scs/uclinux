#include <stdio.h>
#include "helloworldcpp.h"

int main(int argc, char *argv[])
{
	int r;
	class helloworld hw("hello\n");
	r=hw.show_result();
//	printf("get %d from helloworld(0x%x)\n", r, ((unsigned long *)hw.show_result)[0]);
	printf("get %d from helloworld(0x%x)\n", r, hw.str);
		
	return  0;
}
