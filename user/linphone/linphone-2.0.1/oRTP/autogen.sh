AM_VERSION=1.9
set -x
rm -rf config.cache autom4te.cache
aclocal-$AM_VERSION
autoheader
automake-$AM_VERSION --add-missing --copy
libtoolize --copy --force
autoconf
