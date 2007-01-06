include $(top_srcdir)/Make_global.am

sbin_PROGRAMS = conntrack
conntrack_SOURCES = conntrack.c

conntrack_LDFLAGS = $(all_libraries) -rdynamic -lnetfilter_conntrack -lnfnetlink
 
