/*
 * This file is parsed by sed. You MUST use single line comments.
 * IE	//#define CONFIG_BLAH
 */

#define CONFIG_ADDUSER
#define CONFIG_ADDGROUP
#define CONFIG_DELUSER
#define CONFIG_DELGROUP
#define CONFIG_GETTY
#define CONFIG_LOGIN
#define CONFIG_PASSWD
#define CONFIG_SU
#define CONFIG_SULOGIN
#define CONFIG_VLOCK
//
//
//
// This is where feature definitions go.  Generally speaking,
// turning this stuff off makes things a bit smaller (and less 
// pretty/useful).
//
//
// Enable using shadow passwords
#define CONFIG_FEATURE_SHADOWPASSWDS
//
// Enable checking of /etc/securetty by login
#define CONFIG_FEATURE_SECURETTY
//
// Enable using sha passwords
#define CONFIG_FEATURE_SHA1_PASSWORDS
//
// Enable use of a wheel group
#define CONFIG_WHEEL_GROUP
//
// This compiles out everything but the most 
// trivial --help usage information (i.e. reduces binary size)
#define CONFIG_FEATURE_TRIVIAL_HELP
//
// Enable 'tinylogin --install [-s]' to allow tinylogin
// to create links (or symlinks) at runtime for all the 
// commands that are compiled into the binary.  This needs 
// the /proc filesystem to work properly...
#define CONFIG_FEATURE_INSTALLER
//
//
//---------------------------------------------------
// Nothing beyond this point should ever be touched by 
// mere mortals so leave this stuff alone.
//
#ifdef CONFIG_FEATURE_SHA1_PASSWORDS
#define CONFIG_SHA1
#endif
//
#ifdef CONFIG_FEATURE_SHADOWPASSWDS
#define CONFIG_SHADOW
#endif
//
#ifdef CONFIG_SU
#define CONFIG_LOGIN
#endif
