/*
 * applets.h - a listing of all tinylogin applets.
 *
 * If you write a new applet, you need to add an entry to this list to make
 * busybox aware of it.
 *
 * It is CRUCIAL that this listing be kept in ascii order, otherwise the binary
 * search lookup contributed by Gaute B Strokkenes stops working. If you value
 * your kneecaps, you'll be sure to *make sure* that any changes made to this
 * file result in the listing remaining in ascii order. You have been warned.
 */

#undef APPLET
#undef APPLET_ODDNAME
#undef APPLET_NOUSAGE


#if defined(PROTOTYPES)
  #define APPLET(a,b,c,d) extern int b(int argc, char **argv);
  #define APPLET_NOUSAGE(a,b,c,d) extern int b(int argc, char **argv);
  #define APPLET_ODDNAME(a,b,c,d,e) extern int b(int argc, char **argv);
  extern const char usage_messages[];
#elif defined(MAKE_USAGE)
  #ifdef CONFIG_FEATURE_VERBOSE_USAGE
    #define APPLET(a,b,c,d) a##_trivial_usage "\n\n" a##_full_usage "\0"
    #define APPLET_NOUSAGE(a,b,c,d) "\0"
    #define APPLET_ODDNAME(a,b,c,d,e) e##_trivial_usage "\n\n" e##_full_usage "\0"
  #else
    #define APPLET(a,b,c,d) a##_trivial_usage "\0"
    #define APPLET_NOUSAGE(a,b,c,d) "\0"
    #define APPLET_ODDNAME(a,b,c,d,e) e##_trivial_usage "\0"
  #endif
#elif defined(MAKE_LINKS)
#  define APPLET(a,b,c,d) LINK c a
#  define APPLET_NOUSAGE(a,b,c,d) LINK c a
#  define APPLET_ODDNAME(a,b,c,d,e) LINK c a
#else
  const struct BB_applet applets[] = {
  #define APPLET(a,b,c,d) {#a,b,c,d},
  #define APPLET_NOUSAGE(a,b,c,d) {a,b,c,d},
  #define APPLET_ODDNAME(a,b,c,d,e) {a,b,c,d},
#endif



#ifdef CONFIG_ADDGROUP
	APPLET(addgroup, addgroup_main, _BB_DIR_BIN, _BB_SUID_NEVER)
#endif
#ifdef CONFIG_ADDUSER
	APPLET(adduser, adduser_main, _BB_DIR_BIN, _BB_SUID_NEVER)
#endif
#ifdef CONFIG_DELGROUP
	APPLET(delgroup, delgroup_main, _BB_DIR_BIN, _BB_SUID_NEVER)
#endif
#ifdef CONFIG_DELUSER
	APPLET(deluser, deluser_main, _BB_DIR_BIN, _BB_SUID_NEVER)
#endif
#ifdef CONFIG_GETTY
	APPLET(getty, getty_main, _BB_DIR_SBIN, _BB_SUID_NEVER)
#endif
#ifdef CONFIG_LOGIN
	APPLET(login, login_main, _BB_DIR_BIN, _BB_SUID_NEVER)
#endif
#ifdef CONFIG_PASSWD
	APPLET(passwd, passwd_main, _BB_DIR_USR_BIN, _BB_SUID_ALWAYS)
#endif
#ifdef CONFIG_SU
	APPLET(su, su_main, _BB_DIR_BIN, _BB_SUID_ALWAYS)
#endif
#ifdef CONFIG_SULOGIN
	APPLET(sulogin, sulogin_main, _BB_DIR_SBIN, _BB_SUID_NEVER)
#endif
	APPLET_NOUSAGE("tinylogin", tinylogin_main, _BB_DIR_BIN, _BB_SUID_MAYBE)
#ifdef CONFIG_VLOCK
	APPLET(vlock, vlock_main, _BB_DIR_USR_BIN, _BB_SUID_ALWAYS)
#endif
#if !defined(PROTOTYPES) && !defined(MAKE_USAGE)
	{ 0,NULL,0 }
};

#endif
