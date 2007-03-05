/*
 * teststrings.c
 *
 */

#include <ipod/ipod_string.h>
#include <ipod/ipod_memory.h>
#include <stdio.h>

void compare(const char *testDesc,const char *s1,const char *s2,size_t numBytes)
{
	size_t offset = 0;
	while (numBytes--) {
		if (*s1 != *s2) {
			fprintf(stderr,"%s : Mismatch at offset %d ('%x' vs '%x')\n",testDesc,offset,*s1,*s2);
			return;
		}
		s1++; s2++; offset++;
	}
	fprintf(stderr,"%s : Passed\n",testDesc);
}

char *s_iso8859 = "\xd6";
char *s_utf8 = "\xc3\x96";
char *s_utf16 = "\xd6\x0";

int main(int argc, char **argv) {
	char *a,*b;
	size_t numChars;
	
	a = ipod_string_utf8_from_iso8859(s_iso8859);
	compare("ISO8859 -> UTF8",a,s_utf8,strlen(s_utf8));
	ipod_memory_free(a);
	
	a = ipod_string_iso8859_from_utf8(s_utf8);
	compare("UTF8 -> ISO8859",a,s_iso8859,strlen(s_iso8859));
	ipod_memory_free(a);
	
	a = ipod_string_utf16_from_utf8(s_utf8,&numChars);
	compare("UTF8 -> UTF16",a,s_utf16,numChars*2);
	ipod_memory_free(a);
	
	a = ipod_string_utf8_from_utf16(s_utf16,2);
	compare("UTF16 -> UTF8",a,s_utf8,strlen(s_utf8));
	ipod_memory_free(a);

	a = ipod_string_utf16_from_iso8859(s_iso8859,&numChars);
	compare("ISO8859-> UTF16",a,s_utf16,numChars*2);
	ipod_memory_free(a);
	
	a = ipod_string_iso8859_from_utf16(s_utf16,2);
	compare("UTF16 -> ISO8859",a,s_iso8859,2);
	ipod_memory_free(a);

	return 0;
}
