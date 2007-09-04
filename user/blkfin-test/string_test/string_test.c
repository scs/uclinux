/*
 * File:         arch/blackfin/kernel/string_test.c
 * Based on:
 * Author:
 *
 * Created:
 * Description:  Test cases for string operations in kernel space
 *
 * Modified:
 *               Copyright 2004-2006 Analog Devices Inc.
 *
 * Bugs:         Enter bugs at http://blackfin.uclinux.org/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see the file COPYING, or write
 * to the Free Software Foundation, Inc.,
 * 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <linux/init.h>
#include <linux/module.h>


#define STREQ(a, b)     (strcmp((a), (b)) == 0)

const char *it = "<UNSET>";     /* Routine name for message routines. */
size_t errors = 0;

/* Complain if condition is not true.  */
static void
check (int thing, int number)
{
  if (!thing)
    {
      printk("%s flunked test %d\n", it, number);
      ++errors;
    }
   else {
      printk("%s  test %d ok\n", it, number);
     }
}

/* Complain if first two args don't strcmp as equal.  */
static void
equal (const char *a, const char *b, int number)
{
  check(a != NULL && b != NULL && STREQ (a, b), number);
}

char one[50];
char two[50];
char *cp;

static void
test_strcmp (void)
{
  it = "strcmp";
  check (strcmp ("", "") == 0, 1);              /* Trivial case. */
  check (strcmp ("a", "a") == 0, 2);            /* Identity. */
  check (strcmp ("abc", "abc") == 0, 3);        /* Multicharacter. */
  check (strcmp ("abc", "abcd") < 0, 4);        /* Length mismatches. */
  check (strcmp ("abcd", "abc") > 0, 5);
  check (strcmp ("abcd", "abce") < 0, 6);       /* Honest miscompares. */
  check (strcmp ("abce", "abcd") > 0, 7);
  check (strcmp ("a\203", "a") > 0, 8);         /* Tricky if char signed. */
  check (strcmp ("a\203", "a\003") > 0, 9);
 {
    char buf1[0x40], buf2[0x40];
    int i, j;
    for (i=0; i < 0x10; i++)
      for (j = 0; j < 0x10; j++)
        {
          int k;
          for (k = 0; k < 0x3f; k++)
            {
              buf1[k] = '0' ^ (k & 4);
              buf2[k] = '4' ^ (k & 4);
            }
          buf1[i] = buf1[0x3f] = 0;
          buf2[j] = buf2[0x3f] = 0;
          for (k = 0; k < 0xf; k++)
            {
              int cnum = 0x10+0x10*k+0x100*j+0x1000*i;
              printk("1ww buf1 %c , buf2 %c \n",*buf1, *buf2 );
              printk("2ww buf1 %s , buf2 %s \n", buf1, buf2 );
              check (strcmp (buf1+i,buf2+j) == 0, cnum);
              buf1[i+k] = 'A' + i + k;
              buf1[i+k+1] = 0;
              printk("1rr buf1+i %c , buf2+j %c \n",*(buf1+i), *(buf2+j) );
              printk("2rr buf1+i %s , buf2+j %s \n", buf1+i, buf2+j );

              check (strcmp (buf1+i,buf2+j) > 0, cnum+1);
              check (strcmp (buf2+j,buf1+i) < 0, cnum+2);
              buf2[j+k] = 'B' + i + k;
              buf2[j+k+1] = 0;
              check (strcmp (buf1+i,buf2+j) < 0, cnum+3);
              check (strcmp (buf2+j,buf1+i) > 0, cnum+4);
              buf2[j+k] = 'A' + i + k;
              buf1[i] = 'A' + i + 0x80;
              check (strcmp (buf1+i,buf2+j) > 0, cnum+5);
              check (strcmp (buf2+j,buf1+i) < 0, cnum+6);
              buf1[i] = 'A' + i;
            }
        }
  }
/*
  {
    char buf1[0x10], buf2[0x10];
    int i, j;

    for (i=0; i < 0x10; i++)
      for (j = 0; j < 0x10; j++)
        {
          int k;
          for (k = 0; k < 0xf; k++)
            {
              buf1[k] = '0' ^ (k & 4);
              
              buf2[k] = '4' ^ (k & 4);
              printk("buf1[%d] %x , buf2[%d] %x \n",k, buf1[k], k, buf2[k]);
            }
          buf1[0] = '0';
          buf2[0] = '0';
              printk("0ww 444444444 %c ,  %c 55555555 \n", buf1[0], buf2[0] );
          for (k = 0; k < 0xf; k++)
            {
              int cnum = 0x10+0x10*k+0x100*j+0x1000*i;

              printk("1ww buf1 %c , buf2 %c \n",*buf1, *buf2 );
              printk("2ww buf1 %s , buf2 %s \n", buf1, buf2 );
              printk("3ww buf1 %x , buf2 %x \n", buf1, buf2 );
              check (strcmp (buf1,buf2) == 0, cnum);
              buf1[i+k] = 'A' + i + k;
              buf1[i+k+1] = '0';
              printk("4ww buf1 %s  \n", buf1 );
              check (strcmp (buf1+i,buf2+j) > 0, cnum+1);
              printk("buf1+%d %c , buf2+%d %c \n",i, buf1+i,j, buf2+j );
              check (strcmp (buf2+j,buf1+i) < 0, cnum+2);
              buf2[j+k] = 'B' + i + k;
              buf2[j+k+1] = 0;
              check (strcmp (buf1+i,buf2+j) < 0, cnum+3);
              check (strcmp (buf2+j,buf1+i) > 0, cnum+4);
              buf2[j+k] = 'A' + i + k;
              buf1[i] = 'A' + i + 0x80;
              check (strcmp (buf1+i,buf2+j) > 0, cnum+5);
              check (strcmp (buf2+j,buf1+i) < 0, cnum+6);
              buf1[i] = 'A' + i;
            }
        }
  }*/

}


#define SIMPLE_COPY(fn, n, str, ntest) \
  do {                                                                        \
    int __n;                                                                  \
    char *cp;                                                                 \
    for (__n = 0; __n < (int) sizeof (one); ++__n)                            \
      one[__n] = 'Z';                                                         \
    fn (one, str);                                                            \
    for (cp = one, __n = 0; __n < n; ++__n, ++cp)                             \
      check (*cp == '0' + (n % 10), ntest);                                  \
      check (*cp == '\0', ntest);                                               \
  } while (0)

static void
test_strcpy (void)
{
  int i;
  char *aa;
  it = "strcpy";
     aa = strcpy (one, "abcd");
    printk(" %x  test  ok\n",one );
    printk(" %x  test  ok\n",aa );
  check (aa == one, 1); /* Returned value. */
  equal (one, "abcd", 2);               /* Basic test. */

  (void) strcpy (one, "x");
  equal (one, "x", 3);                  /* Writeover. */
  equal (one+2, "cd", 4);               /* Wrote too much? */


  (void) strcpy (two, "hi there");
  (void) strcpy (one, two);
  equal (one, "hi there", 5);           /* Basic test encore. */
  equal (two, "hi there", 6);           /* Stomped on source? */

  (void) strcpy (one, "");
  equal (one, "", 7);                   /* Boundary condition. */

  for (i = 0; i < 16; i++)
    {
      (void) strcpy (one + i, "hi there");      /* Unaligned destination. */
      equal (one + i, "hi there", 8 + (i * 2));
      (void) strcpy (two, one + i);             /* Unaligned source. */
      equal (two, "hi there", 9 + (i * 2));
    }
  SIMPLE_COPY(strcpy, 0, "", 41);
  SIMPLE_COPY(strcpy, 1, "1", 42);
  SIMPLE_COPY(strcpy, 2, "22", 43);
  SIMPLE_COPY(strcpy, 3, "333", 44);
  SIMPLE_COPY(strcpy, 4, "4444", 45);
  SIMPLE_COPY(strcpy, 5, "55555", 46);
  SIMPLE_COPY(strcpy, 6, "666666", 47);
  SIMPLE_COPY(strcpy, 7, "7777777", 48);
  SIMPLE_COPY(strcpy, 8, "88888888", 49);
  SIMPLE_COPY(strcpy, 9, "999999999", 50);
  SIMPLE_COPY(strcpy, 10, "0000000000", 51);
  SIMPLE_COPY(strcpy, 11, "11111111111", 52);
  SIMPLE_COPY(strcpy, 12, "222222222222", 53);
  SIMPLE_COPY(strcpy, 13, "3333333333333", 54);
  SIMPLE_COPY(strcpy, 14, "44444444444444", 55);
  SIMPLE_COPY(strcpy, 15, "555555555555555", 56);
  SIMPLE_COPY(strcpy, 16, "6666666666666666", 57);

  /* Simple test using implicitly coerced `void *' arguments.  */
  const void *src = "frobozz";
  void *dst = one;
  check (strcpy (dst, src) == dst, 1);
  equal (dst, "frobozz", 2);
}

static void
test_memcpy (void)
{
  int i;
  it = "memcpy";
  check(memcpy(one, "abc", 4) == one, 1);       /* Returned value. */
  equal(one, "abc", 2);                 /* Did the copy go right? */

  (void) strcpy(one, "abcdefgh");
  (void) memcpy(one+1, "xyz", 2);
  equal(one, "axydefgh", 3);            /* Basic test. */

  (void) strcpy(one, "abc");
  (void) memcpy(one, "xyz", 0);
  equal(one, "abc", 4);                 /* Zero-length copy. */

  (void) strcpy(one, "hi there");
  (void) strcpy(two, "foo");
  (void) memcpy(two, one, 9);
  equal(two, "hi there", 5);            /* Just paranoia. */
  equal(one, "hi there", 6);            /* Stomped on source? */

  for (i = 0; i < 16; i++)
    {
      const char *x = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
      strcpy (one, x);
      check (memcpy (one + i, "hi there", 9) == one + i,
             7 + (i * 6));              /* Unaligned destination. */
      check (memcmp (one, x, i) == 0, 8 + (i * 6));  /* Wrote under? */
      equal (one + i, "hi there", 9 + (i * 6));
      check (one[i + 9] == 'x', 10 + (i * 6));       /* Wrote over? */
      check (memcpy (two, one + i, 9) == two,
             11 + (i * 6));             /* Unaligned source. */
      equal (two, "hi there", 12 + (i * 6));
    }
}


static int test_init(void)
{
 int status;

  /* Test strcmp first because we use it to test other things.  */
  test_strcpy ();

//  test_strcmp ();
    test_memcpy();

  return status;

}

static void test_exit(void)
{
//	printk(KERN_INFO "Dual core test module removed: testarg = [%d]\n", *testarg);
}

module_init(test_init);
module_exit(test_exit);

MODULE_LICENSE("GPL");
