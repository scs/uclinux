/* string-lib.h - headers for string-lib.c
   $Id: string-lib.h 1009 2005-07-25 01:53:52Z magicyang $
*/

char *newstr(char *str);
char *substr(char *str, int offset, int len);
char *replace_ltgt(char *str);
char *lower_case(char *buffer);
