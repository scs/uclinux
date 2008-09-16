#include "nxlib.h"
#include <stdlib.h>
#include <string.h>

struct _list {
	char **list;
	int alloc;
	int used;
	struct _list *next;
};

static struct _list *g_fontlist = 0;

static struct _list *
_createFontList(void)
{
	struct _list *ptr;

	if (!g_fontlist)
		ptr = g_fontlist =
			(struct _list *)Xcalloc(sizeof(struct _list), 1);
	else {
		struct _list *t;
		for (t = g_fontlist; t->next; t = t->next)
			continue;
		ptr = t->next =
			(struct _list *)Xcalloc(sizeof(struct _list), 1);
	}
	return ptr;
}

static int
_addFontToList(struct _list *list, char *font)
{
	if (list->alloc == 0) {
		list->list = Xmalloc(5 * sizeof(char *));
		list->alloc = 5;
	} else if (list->used == list->alloc) {
		list->list = Xrealloc(list->list,
				(list->alloc + 5) * sizeof(char *));
		list->alloc += 5;
	}

	list->list[list->used++] = strdup(font);
	return list->used;
}

static char **
_getFontList(struct _list *list, int *size)
{
	if (!list->list) {
		*size = 0;
		return 0;
	}

	if (list->alloc != list->used)
		list->list =
			Xrealloc(list->list, (list->used) * sizeof(char *));

	*size = list->used;
	return list->list;
}

static void
_freeFontList(char **fontlist)
{
	struct _list *ptr = g_fontlist;
	struct _list *prev = 0;

	if (!fontlist)
		return;

	while (ptr) {
		if (ptr->list == fontlist) {
			int i;
			for (i = 0; i < ptr->used; i++)
				Xfree(ptr->list[i]);

			Xfree(ptr->list);

			if (ptr == g_fontlist)
				g_fontlist = ptr->next;
			else
				prev->next = ptr->next;

			return;
		}
		prev = ptr;
		ptr = ptr->next;
	}
}

#if 1
static int
dashcount(char *name)
{
	int	ndashes = 0;

	while (*name)
		if (*name++ == '-')
			++ndashes;
	return ndashes;
}

static int
patternmatch(char *pat, int patdashes, char *string, int stringdashes)
{
	int c, t;

	if (stringdashes < patdashes)
		return 0;

	for (;;) {
	    switch (c = *pat++) {
	    case '*':
		if (!(c = *pat++))
			return 1;
		if (c == '-') {
			patdashes--;
			for (;;) {
				while ((t = *string++) != '-')
					if (!t)
						return 0;
				stringdashes--;
				if (patternmatch(pat, patdashes, string, stringdashes))
					return 1;
				if (stringdashes == patdashes)
					return 0;
			}
		} else {
			for (;;) {
				while ((t = *string++) != c) {
					if (!t)
						return 0;
					if (t == '-') {
						if (stringdashes-- < patdashes)
							return 0;
					}
				}
				if (patternmatch(pat, patdashes, string, stringdashes))
					return 1;
			}
		}
	    case '?':
		if (*string++ == '-')
			stringdashes--;
		break;
	    case '\0':
		return (*string == '\0');
	    case '-':
		if (*string++ == '-') {
			patdashes--;
			stringdashes--;
			break;
		}
		return 0;
	    default:
		if (c == *string++)
			break;
		return 0;
	    }
	}
}

static int
match(char *pat, char *string)
{
	return patternmatch(pat, dashcount(pat), string, dashcount(string));
}

#else
static int
match(char *pattern, char *font)
{
	char *src = pattern;
	char *dst = font;
	int m = 0;

	if (!strcmp(pattern, "-*"))
		pattern = "*"; //"-*-*-*-*-*-*-*-*-*-*-*-*-*-*";

	if (!strcmp(pattern, "*"))
		return 1;

	while (1) {
		char *s, *e;

		src++;
		dst++;

		/* Skip any wildcardish stuff */
		if (*src == '*') {
			src++;
			if (!*src)
				break;

			for (; *dst && *dst != '-'; dst++)
				continue;
			if (!*dst)
				break;

			continue;
		}

		/* Find the end of the compare */
		s = src;
		e = src;
		for (; *e && *e != '-'; e++)
			continue;

		if (strncmp(s, dst, (int) (e - s)) == 0) {
			m = 1;
		} else {
			m = 0;
			break;
		}

		src += (int) (e - s);
		dst += (int) (e - s);
	}
	return m;
}
#endif

static char **
_findFontPattern(char *pattern, int maxnames, int *count)
{
	struct _list *flist = _createFontList();
	int fcount = 0, i = 0, f;
	char buffer[128];

	if (!_nxfontlist)
		_nxSetDefaultFontDir();

	for (f = 0; f < _nxfontcount; f++) {
		FILE *fontdir = _nxLoadFontDir(_nxfontlist[f]);
		if (!fontdir)
			continue;

		fgets(buffer, 128, fontdir);
		fcount = atoi(buffer);

		if (!fcount) {
			fclose(fontdir);
			continue;
		}

		for (i = 0; i < fcount; i++) {
			char *font;

			memset(buffer, 0, 128);
			fgets(buffer, 128, fontdir);

			/* Remove the end 'o line */
			buffer[strlen(buffer) - 1] = '\0';

			/* Find the field seperator */
			font = strchr(buffer, ' ');
			*font++ = '\0';

			if (match(pattern, font))
				if (_addFontToList(flist, font) == maxnames)
					break;
		}
		fclose(fontdir);
	}
	return _getFontList(flist, count);
}

/*
 * Compare two strings just like strcmp, but preserve decimal integer
 * sorting order, i.e. "2" < "10" or "iso8859-2" < "iso8859-10" <
 * "iso10646-1". Strings are sorted as if sequences of digits were
 * prefixed by a length indicator (i.e., does not ignore leading zeroes).
 *
 * Markus Kuhn <Markus.Kuhn@cl.cam.ac.uk>
 */
#define isdigit(c) ('0' <= (c) && (c) <= '9')
static int
strcmpn(unsigned char *s1, unsigned char *s2)
{
	int digits, predigits = 0;
	unsigned char *ss1, *ss2;

	while (1) {
		if (*s1 == 0 && *s2 == 0)
			return 0;
		digits = isdigit(*s1) && isdigit(*s2);
		if (digits && !predigits) {
			ss1 = s1;
			ss2 = s2;
			while (isdigit(*ss1) && isdigit(*ss2))
				ss1++, ss2++;
			if (!isdigit(*ss1) && isdigit(*ss2))
				return -1;
			if (isdigit(*ss1) && !isdigit(*ss2))
				return 1;
		}
		if (*s1 < *s2)
			return -1;
		if (*s1 > *s2)
			return 1;
		predigits = digits;
		s1++, s2++;
	}
}

static int
comparefunc(const void* a, const void* b)
{
	char *aa = *(char **)a;
	char *bb = *(char **)b;

	return strcmpn(aa, bb);
}

char **
XListFonts(Display * display, _Xconst char *pattern, int maxnames,
	int *actual_count_return)
{
	int count;
	char **ret;

	ret = _findFontPattern((char *)pattern, maxnames, &count);
	*actual_count_return = count;

	/* sort the return, helps for lack of locale info at end of XLFD*/
	qsort((char *)ret, count, sizeof(char *), comparefunc);

	return ret;
}

int
XFreeFontNames(char **list)
{
	_freeFontList(list);
	return 1;
}
