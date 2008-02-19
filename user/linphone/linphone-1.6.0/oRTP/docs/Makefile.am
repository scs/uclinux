## Process this file with automake to produce Makefile.in

# We require automake 1.9 at least.
AUTOMAKE_OPTIONS = 1.9

# This is a blank Makefile.am for using gtk-doc.
# Copy this to your project's API docs directory and modify the variables to
# suit your project. See the GTK+ Makefiles in gtk+/docs/reference for examples
# of using the various options.

# The name of the module, e.g. 'glib'.
DOC_MODULE=ortp

# The top-level SGML file. You can change this if you want to.
DOC_MAIN_SGML_FILE=$(DOC_MODULE)-docs.sgml

# The directory containing the source code. Relative to $(srcdir).
# gtk-doc will search all .c & .h files beneath here for inline comments
# documenting the functions and macros.
# e.g. DOC_SOURCE_DIR=../../../gtk
DOC_SOURCE_DIR = $(top_srcdir)/include/ortp $(top_srcdir)/src

# Extra options to pass to gtkdoc-scangobj. Not normally needed.
SCANGOBJ_OPTIONS=

# Extra options to supply to gtkdoc-scan.
# e.g. SCAN_OPTIONS=--deprecated-guards="GTK_DISABLE_DEPRECATED" 
SCAN_OPTIONS=

# Extra options to supply to gtkdoc-mkdb.
# e.g. MKDB_OPTIONS=--sgml-mode --output-format=xml
MKDB_OPTIONS=--sgml-mode --output-format=sgml

# Extra options to supply to gtkdoc-mktmpl
# e.g. MKTMPL_OPTIONS=--only-section-tmpl
MKTMPL_OPTIONS=

# Extra options to supply to gtkdoc-fixref. Not normally needed.
# e.g. FIXXREF_OPTIONS=--extra-dir=../gdk-pixbuf/html --extra-dir=../gdk/html
FIXXREF_OPTIONS=

# Used for dependencies. The docs will be rebuilt if any of these change.
# e.g. HFILE_GLOB=$(top_srcdir)/*.h
# e.g. CFILE_GLOB=$(top_srcdir)/*.c
HFILE_GLOB = $(top_srcdir)/include/ortp/*.h $(top_srcdir)/src/*.h
CFILE_GLOB = $(top_srcdir)/src/*.c

# Header files to ignore when scanning.
# e.g. IGNORE_HFILES=gtkdebug.h gtkintl.h
IGNORE_HFILES=tny-account-priv.h tny-attach-list-model-priv.h tny-msg-folder-priv.h tny-msg-priv.h

# Images to copy into HTML directory.
# e.g. HTML_IMAGES=$(top_srcdir)/gtk/stock-icons/stock_about_24.png
HTML_IMAGES = 

# Extra SGML files that are included by $(DOC_MAIN_SGML_FILE).
# e.g. content_files=running.sgml building.sgml changes-2.0.sgml
content_files=sgml/tree_index.sgml

# SGML files where gtk-doc abbrevations (#GtkWidget) are expanded
# These files must be listed here *and* in content_files
# e.g. expand_content_files=running.sgml
expand_content_files=

# CFLAGS and LDFLAGS for compiling gtkdoc-scangobj with your library.
# Only needed if you are using gtkdoc-scangobj to dynamically query widget
# signals and properties.
# e.g. INCLUDES=-I$(top_srcdir) -I$(top_builddir) $(GTK_DEBUG_FLAGS)
# e.g. GTKDOC_LIBS=$(top_builddir)/gtk/$(gtktargetlib)
#
INCLUDES = -I$(top_srcdir)/include
GTKDOC_LIBS = $(top_builddir)/src/libortp.la

#INCLUDES = $(LIBTINYMAIL_CFLAGS) $(LIBTINYMAILUI_CFLAGS) 		\
#	$(LIBTINYMAIL_CAMEL_CFLAGS) $(LIBTINYMAIL_GNOMEVFS_CFLAGS) 	\
#	$(LIBTINYMAILUI_GTK_CFLAGS) $(LIBTINYMAILUI_MOZEMBED_CFLAGS) 	\
#	$(LIBTINYMAIL_GNOME_DESKTOP_CFLAGS) $(LIBTINYMAIL_TEST_CFLAGS)  \
#	$(TINYMAIL_CFLAGS) -I$(top_srcdir)/libtinymail 			\
#	-I$(top_srcdir)/libtinymailui -I$(top_srcdir)/libtinymailui-gtk	\
#	-I$(top_srcdir)/libtinymailui-mozembed				\
#	-I$(top_srcdir)/libtinymail-camel				\
#	-I$(top_srcdir)/libtinymail-gnomevfs				\
#	-I$(top_srcdir)/tinymail
#
#GTKDOC_LIBS= $(LIBTINYMAIL_LIBS) $(LIBTINYMAILUI_LIBS) 						\
#	$(LIBTINYMAIL_CAMEL_LIBS) $(LIBTINYMAIL_GNOMEVFS_LIBS)      				\
#	$(LIBTINYMAILUI_GTK_LIBS) $(LIBTINYMAILUI_MOZEMBED_LIBS)    				\
#	$(LIBTINYMAIL_GNOME_DESKTOP_LIBS) $(LIBTINYMAIL_TEST_LIBS)  				\
#	$(TINYMAIL_LIBS)									\
#	$(top_builddir)/libtinymail/libtinymail-$(API_VERSION).la 				\
#	 $(top_builddir)/libtinymail-camel/libtinymail-camel-$(API_VERSION).la			\
#	$(top_builddir)/libtinymailui/libtinymailui-$(API_VERSION).la				\
#	$(top_builddir)/libtinymailui-gtk/libtinymailui-gtk-$(API_VERSION).la			\
#	$(top_builddir)/libtinymailui-mozembed/libtinymailui-mozembed-$(API_VERSION).la		\
#	$(top_builddir)/libtinymail-gnome-desktop/libtinymail-gnome-desktop-$(API_VERSION).la	\
#	$(top_builddir)/libtinymail-gnomevfs/libtinymail-gnomevfs-$(API_VERSION).la

# This includes the standard gtk-doc make rules, copied by gtkdocize.
include $(top_srcdir)/gtk-doc.make

# Other files to distribute
# e.g. EXTRA_DIST += version.xml.in
EXTRA_DIST += ortp-sections.txt
