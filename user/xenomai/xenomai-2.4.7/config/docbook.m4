#                                               -*- Autoconf -*-
# Building Docbook-XML documents with the autotools.
#
# Check whether needed tools for generating Docbook XML doc are installed and
# running. 
#  - "docbook-root" is the name of the source tree subdirectory which is the
# docbook documentation root. It is expected to contain at least : 
#      catalog.in, used to match DTD generic addresses to their local copy ;
#      pictures, with all the pictures referenced by the XML documents ;
#      css, with the CSS referenced by the html documents.
#
#  - "generated-doc-root" is the name of the source tree subdirectory which 
# contains the generated documentation. It is expected to contain at least :
#      html/pictures with the pictures needed by the html documents ;
#      html/css with the css needed by the html documents ;
#      html/* one directory by html document ;
#      pdf/*.pdf one pdf file by pdf document ;
#
#  - "docbook-dtd-version" is the version of the Docbook-XML DTD used.
#
# DBX_DOC_INIT(docbook-root, generated-doc-root, docbook-dtd-version)
# ------------------------------------------------------------------------------
AC_DEFUN([DBX_DOC_INIT], 
[
DBX_DOC_ROOT="$1"
AC_SUBST(DBX_DOC_ROOT)

AC_MSG_CHECKING(whether compiling Docbook XML documentation)
AC_ARG_ENABLE(dbx, 
        AS_HELP_STRING([--enable-dbx],[Build Docbook XML documentation.]),
	[case "$enableval" in
	y | ye | yes) DBX_DOC=yes;;
	*) DBX_DOC="" ;;
	esac])

if test \! -f "$srcdir/$1/catalog.in"; then
    if test x$DBX_DOC = xyes;
    then
        AC_MSG_ERROR([$1/catalog.in could not be found in the source tree,
DocBook documentation can not be generated.])
    fi
    AC_MSG_RESULT([not present.])
else
    AC_MSG_RESULT(${DBX_DOC:-no})
fi
AM_CONDITIONAL(DBX_DOC,[test "$DBX_DOC" = yes])

# 
DBX_GEN_DOC_ROOT="$2"
AC_SUBST(DBX_GEN_DOC_ROOT)

# First: search for needed tools.
AC_CHECK_PROG(DBX_LINT, xmllint, xmllint)
if test x"$DBX_LINT" = x -a -n "$DBX_DOC"; then
   AC_MSG_ERROR([xmllint was not found. Check your PATH variable and try again.])
fi
AC_SUBST(DBX_LINT)


AC_CHECK_PROG(DBX_XSLTPROC, xsltproc, xsltproc)
if test x"$DBX_XSLTPROC" = x -a -n "$DBX_DOC"; then
   AC_MSG_ERROR([xsltproc was not found. Check your PATH variable and try 
again.])
fi
AC_SUBST(DBX_XSLTPROC)


AC_CHECK_PROG(DBX_FOP, fop, fop)
if test x"$DBX_FOP" = x -a -n "$DBX_DOC"; then
   AC_MSG_ERROR([fop was not found. Check your PATH variable and try again.])
fi
AC_SUBST(DBX_FOP)

# Second: search for DTD and XSL stylesheets.
DBX_DTD_VERSION="$3"

AC_MSG_CHECKING(whether Docbook XML documentation generation can use network.)
AC_ARG_ENABLE(dbx-network,
        AS_HELP_STRING([--enable-dbx-network],[Try to access Docbook DTD and
XSL stylesheets through network (default is to die if local installation can not
be found by configure).]),
        [ case "$enable_dbx_network" in 
           y | yes | yes )
                DBX_NET=yes;;
           n | no )
                DBX_NET="";;
          esac
        ])

# Do not define the --nonet xsltproc flag if the option --enable-dbx-network was
# passed
AC_MSG_RESULT(${DBX_NET:-no})
if test -n "$DBX_NET"; then
    unset DBX_MAYBE_NONET
else
    DBX_MAYBE_NONET=--nonet
fi
AC_SUBST(DBX_MAYBE_NONET)


AC_MSG_CHECKING(for docbook-xml root dir)
AC_ARG_WITH(dbx-root,
        AS_HELP_STRING([--with-dbx-root],[specify the Docbook XML root (that 
is, the directory where docbookx.dtd should be found). Default is to use
well-known locations (or network if --enable-dbx-network was passed).]),
        [DBX_ROOT="$withval"])
if test x"$DBX_ROOT" = x; then
   # Still not found, we will hence look for it using the "well-known"
   # places (well... for the moment, only the Debian package directory) 
   for dir in \
       /usr/share/sgml/docbook/dtd/xml/$DBX_DTD_VERSION
   do
        if test -e $dir/docbookx.dtd; then
           DBX_ROOT="$dir"; 
           break;
        fi
   done
fi
AC_MSG_RESULT(${DBX_ROOT:-network})
if test x"$DBX_ROOT" = x; then
   if test x"$enable_dbx_network" != x  -a -n "$DBX_DOC"; then 
        AC_MSG_ERROR([The Docbook XML DTD was not found, and accessing it
through network is forbidden.])
   fi
   DBX_ROOT="http://www.oasis-open.org/docbook/xml/$DBX_DTD_VERSION/"
else
   DBX_ROOT="file://$DBX_ROOT"
fi
AC_SUBST(DBX_ROOT)


AC_MSG_CHECKING(for docbook-xsl root dir)
AC_ARG_WITH(docbook-xsl-root,
	AS_HELP_STRING([--with-dbx-xsl-root],[specify the Docbook XML XSL
stylesheet root. Default is to use well-known locations (or network if
--enable-dbx-network was passed)]),
        [ DBX_XSL_ROOT="$withval" ])
if test x"$DBX_XSL_ROOT" = x; then
   # Still not found, we will hence look for it using the "well-known"
   # places (well... for the moment, only the Debian standard directory) 
   for dir in \
       /usr/share/sgml/docbook/stylesheet/xsl/nwalsh
   do
        if test -e "$dir/html/docbook.xsl"; then
           DBX_XSL_ROOT="$dir"; 
           break;
        fi
   done
fi
AC_MSG_RESULT(${DBX_XSL_ROOT:-network})
if test x"$DBX_XSL_ROOT" = x; then
   if test x"$enable_dbx_network" != x -a -n "$DBX_DOC"; then
        AC_MSG_ERROR([The Docbook XML DTD was not found, and accessing it 
through network is forbidden.])
   fi
   DBX_XSL_ROOT="http://http://docbook.sourceforge.net/release/xsl/current"
else
   DBX_XSL_ROOT="file://$DBX_XSL_ROOT"
fi
AC_SUBST(DBX_XSL_ROOT)


DBX_ABS_SRCDIR=`case $srcdir in
  [\\/]* | ?:[\\/]* ) echo : ;;
  *) echo false ;;
esac`
AM_CONDITIONAL(DBX_ABS_SRCDIR, $DBX_ABS_SRCDIR)


])
