#define addgroup_trivial_usage \
	"[OPTIONS] <group_name>"
#define addgroup_full_usage \
	"Adds a group to the system" \
	"Options:\n" \
	    "\t-g\t\tspecify gid\n"

#define adduser_trivial_usage \
	"[OPTIONS] <user_name>"
#define adduser_full_usage \
	"Adds a user to the system" \
	"Options:\n" \
	    "\t-h\t\thome directory\n" \
	    "\t-s\t\tshell\n" \
	    "\t-g\t\tGECOS string\n"

#define delgroup_trivial_usage \
	"GROUP"
#define delgroup_full_usage \
	 "Deletes group GROUP from the system"

#define deluser_trivial_usage \
	"USER"
#define deluser_full_usage \
	 "Deletes user USER from the system"

#define login_trivial_usage \
	"[OPTION]... [username] [ENV=VAR ...]"
#define login_full_usage \
	"Begin a new session on the system\n\n" \
	"Options:\n" \
	"\t-f\tDo not authenticate (user already authenticated)\n" \
	"\t-h\tName of the remote host for this login.\n" \
	"\t-p\tPreserve environment."

#ifdef CONFIG_FEATURE_SHA1_PASSWORDS
  #define PASSWORD_ALG_TYPES(a) a
#else
  #define PASSWORD_ALG_TYPES(a)
#endif
#define passwd_trivial_usage \
	"[OPTION] [name]"
#define passwd_full_usage \
	"CChange a user password. If no name is specified,\n" \
	"changes the password for the current user.\n" \
	"Options:\n" \
	"\t-a\tDefine which algorithm shall be used for the password.\n" \
	"\t\t\t(Choices: des, md5" \
	PASSWORD_ALG_TYPES(", sha1") \
	")\n\t-d\tDelete the password for the specified user account.\n" \
	"\t-l\tLocks (disables) the specified user account.\n" \
	"\t-u\tUnlocks (re-enables) the specified user account."


#define su_trivial_usage \
	"[OPTION]... [-] [username]"
#define su_full_usage \
	"Change user id or become root.\n" \
	"Options:\n" \
	"\t-p\tPreserve environment"


#define sulogin_trivial_usage \
	"[OPTION]... [tty-device]"
#define sulogin_full_usage \
	"Single user login\n" \
	"Options:\n" \
	"\t-f\tDo not authenticate (user already authenticated)\n" \
	"\t-h\tName of the remote host for this login.\n" \
	"\t-p\tPreserve environment."


#define getty_trivial_usage \
	"getty [OPTIONS]... baud_rate,... line [termtype]"
#define getty_full_usage \
	"\nOpens a tty, prompts for a login name, then invokes /bin/login\n\n" \
	"Options:\n" \
	"\t-h\t\tEnable hardware (RTS/CTS) flow control.\n" \
	"\t-i\t\tDo not display /etc/issue before running login.\n" \
	"\t-L\t\tLocal line, so do not do carrier detect.\n" \
	"\t-m\t\tGet baud rate from modem's CONNECT status message.\n" \
	"\t-w\t\tWait for a CR or LF before sending /etc/issue.\n" \
	"\t-l login_app\tInvoke login_app instead of /bin/login.\n" \
	"\t-t timeout\tTerminate after timeout if no username is read.\n" \
	"\t-I initstring\tSets the init string to send before anything else.\n" \
	"\t-H login_host\tLog login_host into the utmp file as the hostname."


#define vlock_trivial_usage \
	"[OPTIONS]"
#define vlock_full_usage \
	"Lock a virtual terminal.  A password is required to unlock\n" \
	"Options:\n" \
	"\t-a\tLock all VTs"

