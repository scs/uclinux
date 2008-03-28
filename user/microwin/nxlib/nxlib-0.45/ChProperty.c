#include <string.h>
#include "nxlib.h"

struct window_props {
	Atom property;
	Atom type;
	int format;
	unsigned char *data;
	int count;
	struct window_props *next;
};

struct windows {
	Window w;
	struct window_props *properties;
	struct windows *next;
};
static struct windows *window_list[32];

static int
_nxAddProperty(Window w, Atom property, Atom type, int format, int mode,
	       const unsigned char *data, int nelements)
{
	int hash = w % 32;
	struct windows *win = 0;
	struct window_props *prop = 0;

	if (!window_list[hash]) {
		win = window_list[hash] =
			(struct windows *) Xcalloc(sizeof(struct windows), 1);
	} else {
		struct windows *t = window_list[hash];
		while (t->next) {
			if (t->w == w) {
				win = t;
				break;
			}

			t = t->next;
		}

		if (!win)
			win = t->next =
				(struct windows *) Xcalloc(sizeof(struct windows), 1);
	}

	if (!win->properties)
		prop = win->properties =
			(struct window_props *) Xcalloc(sizeof(struct window_props), 1);
	else {
		struct window_props *t = win->properties;
		while (t->next) {
			if (t->property == property) {
				prop = t;
				break;
			}

			t = t->next;
		}

		if (!prop)
			prop = t->next =
				(struct window_props *) Xcalloc(sizeof(struct window_props), 1);
	}

	switch (mode) {
	case PropModeAppend:
	case PropModePrepend:
		if (prop->data) {
			char *n;

			if (type != prop->type || format != prop->format)
				return (0);

			n = (char *) Xmalloc((prop->count + nelements) *
					    (prop->format / 8));

			if (mode == PropModeAppend) {
				memcpy(n, prop->data,
				       prop->count * (prop->format / 8));
				memcpy(n + (prop->count * (prop->format / 8)),
				       data,
				       (nelements * (prop->format / 8)));
			} else {
				memcpy(n, data,
				       nelements * (prop->format / 8));
				memcpy(n + (nelements * (prop->format / 8)),
				       prop->data,
				       (prop->count * (prop->format / 8)));
			}

			Xfree(prop->data);
			prop->data = n;

			prop->count = prop->count + nelements;
			break;
		}
		/* Fall through */

	case PropModeReplace:
		if (prop->data)
			Xfree(prop->data);
		prop->data = (char *) Xmalloc(nelements * (format / 8));
		memcpy(prop->data, data, (nelements * (format / 8)));

		prop->property = property;
		prop->type = type;
		prop->format = format;
		prop->count = nelements;

		break;
	}

	return 1;
}

static int
_nxDelProperty(Window w, Atom property)
{

	int hash = (w % 32);

	struct windows *win;
	struct window_props *prop;

	for (win = window_list[hash]; win; win = win->next)
		if (win->w == w) {
			struct window_props *prev = 0;

			for (prop = win->properties; prop; prop = prop->next)
				if (prop->property == property) {
					if (prev)
						prev->next = prop->next;
					else
						win->properties = prop->next;

					if (prop->data)
						Xfree(prop->data);
					Xfree(prop);
					return (1);
				}
		}

	return 1;
}

int
_nxDelAllProperty(Window w)
{

	int hash = (w % 32);

	struct windows *win;
	struct window_props *prop;

	for (win = window_list[hash]; win; win = win->next)
		if (win->w == w) {
			prop = win->properties;
			while (prop) {
				struct window_props *next = prop->next;
				if (prop->data)
					Xfree(prop->data);
				Xfree(prop);
				prop = next;
			}

			Xfree(win);
			return 1;
		}

	return 1;
}

int
XChangeProperty(Display * display, Window w, Atom property,
		Atom type, int format, int mode,
		_Xconst unsigned char *data, int nelements)
{
printf("XChangeProperty %s\n", XGetAtomName(display, property));
	return _nxAddProperty(w, property, type, format, mode,
			       data, nelements);
}

int
XDeleteProperty(Display * display, Window w, Atom property)
{
	return _nxDelProperty(w, property);
}
