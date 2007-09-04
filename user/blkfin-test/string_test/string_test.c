/*
 * File:         string_test.c
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
test_strncmp (void)
{
  /* First test as strcmp with big counts, then test count code.  */
  it = "strncmp";
  check (strncmp ("", "", 99) == 0, 1); /* Trivial case. */
  check (strncmp ("a", "a", 99) == 0, 2);       /* Identity. */
  check (strncmp ("abc", "abc", 99) == 0, 3);   /* Multicharacter. */
  check (strncmp ("abc", "abcd", 99) < 0, 4);   /* Length unequal. */
  check (strncmp ("abcd", "abc", 99) > 0, 5);
  check (strncmp ("abcd", "abce", 99) < 0, 6);  /* Honestly unequal. */
  check (strncmp ("abce", "abcd", 99) > 0, 7);
  check (strncmp ("a\203", "a", 2) > 0, 8);     /* Tricky if '\203' < 0 */
  check (strncmp ("a\203", "a\003", 2) > 0, 9);
  check (strncmp ("abce", "abcd", 3) == 0, 10); /* Count limited. */
  check (strncmp ("abce", "abc", 3) == 0, 11);  /* Count == length. */
  check (strncmp ("abcd", "abce", 4) < 0, 12);  /* Nudging limit. */
  check (strncmp ("abc", "def", 0) == 0, 13);   /* Zero count. */
  check (strncmp ("abc", "", (size_t)-1) > 0, 14);      /* set sign bit in count */
  check (strncmp ("abc", "abc", (size_t)-2) == 0, 15);
}

static void
test_strncpy (void)
{
  /* Testing is a bit different because of odd semantics.  */
  it = "strncpy";
  check (strncpy (one, "abc", 4) == one, 1);    /* Returned value. */
  equal (one, "abc", 2);                        /* Did the copy go right? */

  (void) strcpy (one, "abcdefgh");
  (void) strncpy (one, "xyz", 2);
  equal (one, "xycdefgh", 3);                   /* Copy cut by count. */

  (void) strcpy (one, "abcdefgh");
  (void) strncpy (one, "xyz", 3);               /* Copy cut just before NUL. */
  equal (one, "xyzdefgh", 4);

  (void) strcpy (one, "abcdefgh");
  (void) strncpy (one, "xyz", 4);               /* Copy just includes NUL. */
  equal (one, "xyz", 5);
  equal (one+4, "efgh", 6);                     /* Wrote too much? */

  (void) strcpy (one, "abcdefgh");
  (void) strncpy (one, "xyz", 5);               /* Copy includes padding. */
  equal (one, "xyz", 7);
  equal (one+4, "", 8);
  equal (one+5, "fgh", 9);

  (void) strcpy (one, "abc");
  (void) strncpy (one, "xyz", 0);               /* Zero-length copy. */
  equal (one, "abc", 10);

  (void) strncpy (one, "", 2);          /* Zero-length source. */
  equal (one, "", 11);
  equal (one+1, "", 12);
  equal (one+2, "c", 13);

  (void) strcpy (one, "hi there");
  (void) strncpy (two, one, 9);
  equal (two, "hi there", 14);          /* Just paranoia. */
  equal (one, "hi there", 15);          /* Stomped on source? */
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

static void
test_memchr (void)
{
  it = "memchr";
  check(memchr("abcd", 'z', 4) == NULL, 1);     /* Not found. */
  (void) strcpy(one, "abcd");
  check(memchr(one, 'c', 4) == one+2, 2);       /* Basic test. */
  check(memchr(one, ~0xff|'c', 4) == one+2, 2); /* ignore highorder bits. */
  check(memchr(one, 'd', 4) == one+3, 3);       /* End of string. */
  check(memchr(one, 'a', 4) == one, 4); /* Beginning. */
  check(memchr(one, '\0', 5) == one+4, 5);      /* Finding NUL. */
  (void) strcpy(one, "ababa");
  check(memchr(one, 'b', 5) == one+1, 6);       /* Finding first. */
  check(memchr(one, 'b', 0) == NULL, 7);        /* Zero count. */
  check(memchr(one, 'a', 1) == one, 8); /* Singleton case. */
  (void) strcpy(one, "a\203b");
  check(memchr(one, 0203, 3) == one+1, 9);      /* Unsignedness. */

  /* now test all possible alignment and length combinations to catch
     bugs due to unrolled loops (assuming unrolling is limited to no
     more than 128 byte chunks: */
  {
    char buf[128 + sizeof(long)];
    long align, len, i, pos;

    for (align = 0; align < (long) sizeof(long); ++align) {
      for (len = 0; len < (long) (sizeof(buf) - align); ++len) {
        for (i = 0; i < len; ++i) {
          buf[align + i] = 'x';         /* don't depend on memset... */
        }
        for (pos = 0; pos < len; ++pos) {
#if 0
          printf("align %d, len %d, pos %d\n", align, len, pos);
#endif
          check(memchr(buf + align, 'x', len) == buf + align + pos, 10);
          check(memchr(buf + align, 'x', pos) == NULL, 11);
          buf[align + pos] = '-';
        }
      }
    }
  }
}

static void
test_memcmp (void)
{
  it = "memcmp";
  check(memcmp("a", "a", 1) == 0, 1);           /* Identity. */
  check(memcmp("abc", "abc", 3) == 0, 2);       /* Multicharacter. */
  check(memcmp("abcd", "abce", 4) < 0, 3);      /* Honestly unequal. */
  check(memcmp("abce", "abcd", 4) > 0, 4);
  check(memcmp("alph", "beta", 4) < 0, 5);
  check(memcmp("a\203", "a\003", 2) > 0, 6);
  check(memcmp("abce", "abcd", 3) == 0, 7);     /* Count limited. */
  check(memcmp("abc", "def", 0) == 0, 8);       /* Zero count. */
}

static void
test_memmove (void)
{
  it = "memmove";
  check(memmove(one, "abc", 4) == one, 1);      /* Returned value. */
  equal(one, "abc", 2);                 /* Did the copy go right? */

  (void) strcpy(one, "abcdefgh");
  (void) memmove(one+1, "xyz", 2);
  equal(one, "axydefgh", 3);            /* Basic test. */

  (void) strcpy(one, "abc");
  (void) memmove(one, "xyz", 0);
  equal(one, "abc", 4);                 /* Zero-length copy. */

  (void) strcpy(one, "hi there");
  (void) strcpy(two, "foo");
  (void) memmove(two, one, 9);
  equal(two, "hi there", 5);            /* Just paranoia. */
  equal(one, "hi there", 6);            /* Stomped on source? */

  (void) strcpy(one, "abcdefgh");
  (void) memmove(one+1, one, 9);
  equal(one, "aabcdefgh", 7);           /* Overlap, right-to-left. */

  (void) strcpy(one, "abcdefgh");
  (void) memmove(one+1, one+2, 7);
  equal(one, "acdefgh", 8);             /* Overlap, left-to-right. */

  (void) strcpy(one, "abcdefgh");
  (void) memmove(one, one, 9);
  equal(one, "abcdefgh", 9);            /* 100% overlap. */
}

static void
test_memset (void)
{
  int i;

  it = "memset";
  (void) strcpy(one, "abcdefgh");
  check(memset(one+1, 'x', 3) == one+1, 1);     /* Return value. */
  equal(one, "axxxefgh", 2);            /* Basic test. */

  (void) memset(one+2, 'y', 0);
  equal(one, "axxxefgh", 3);            /* Zero-length set. */

  (void) memset(one+5, 0, 1);
  equal(one, "axxxe", 4);                       /* Zero fill. */
  equal(one+6, "gh", 5);                        /* And the leftover. */

  (void) memset(one+2, 010045, 1);
  equal(one, "ax\045xe", 6);            /* Unsigned char convert. */

  /* Non-8bit fill character.  */
  memset (one, 0x101, sizeof (one));
  for (i = 0; i < (int) sizeof (one); ++i)
    check (one[i] == '\01', 7);

  /* Test for more complex versions of memset, for all alignments and
     lengths up to 256. This test takes a little while, perhaps it should
     be made weaker?  */
  {
    char data[512];
    int j;
    int k;
    int c;

    for (i = 0; i < 512; i++)
      data[i] = 'x';
    for (c = 0; c <= 'y'; c += 'y')  /* check for memset(,0,) and
                                        memset(,'y',) */
      for (j = 0; j < 256; j++)
        for (i = 0; i < 256; i++)
          {
            memset (data + i, c, j);
            for (k = 0; k < i; k++)
              if (data[k] != 'x')
                goto fail;
            for (k = i; k < i+j; k++)
              {
                if (data[k] != c)
                  goto fail;
                data[k] = 'x';
              }
            for (k = i+j; k < 512; k++)
              if (data[k] != 'x')
                goto fail;
            continue;

          fail:
            check (0, 8 + i + j * 256 + (c != 0) * 256 * 256);
          }
  }
}


static int test_init(void)
{
 int status;

  /* Test strcmp first because we use it to test other things.  */
  test_strcpy ();

//  test_strcmp ();

  /* strncmp.  */
  test_strncmp ();

  /* strncpy.  */
  test_strncpy ();

  /* memcmp.  */
  test_memcmp ();

  /* memchr.  */
  test_memchr ();

  /* memcpy - need not work for overlap.  */
  test_memcpy ();

  /* memmove - must work on overlap.  */
  test_memmove ();

  /* memset.  */
  test_memset ();

  if (errors == 0)
    {
      status = 0;
      printk("TEST PASS.");
    }
  else
    {
      status = 1;
      printk("%Zd errors.TEST FAIL\n", errors);
    }

  return status;

}

static void test_exit(void)
{
}

module_init(test_init);
module_exit(test_exit);

MODULE_LICENSE("GPL");
