#include <stdio.h>

#define TEST_SCRATCHPAD_LOW      0xffb00000
#define TEST_SCRATCHPAD_HIGH     0xffb01000


int main()
{
        char *str;
        str="Hello world!";
	printf("%s, %p\n", str,&str);

        if (((unsigned long)&str > TEST_SCRATCHPAD_HIGH) || ((unsigned long)&str < TEST_SCRATCHPAD_LOW)) {
                printf("        TEST FAIL\n");
        } else {
                printf("        TEST PASS\n");
        }

}

