/* os_dep.c
 * (c) 2002 Mikulas Patocka
 * This file is a part of the Links program, released under GPL.
 */

#include "links.h"

#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

#if defined(HAVE_LIBGPM) && defined(HAVE_GPM_H)
#define USE_GPM
#endif

#ifdef USE_GPM
#include <gpm.h>
#endif

/* prototypes */
int get_e(char *);
void sigwinch(void *);
void exec_new_links(struct terminal *, unsigned char *, unsigned char *, unsigned char *);
void open_in_new_twterm(struct terminal *, unsigned char *, unsigned char *);
void open_in_new_xterm(struct terminal *, unsigned char *, unsigned char *);
void open_in_new_screen(struct terminal *, unsigned char *, unsigned char *);
void open_in_new_g(struct terminal *, unsigned char *, unsigned char *);


int is_safe_in_shell(unsigned char c)
{
	return c == '@' || c == '+' || c == '-' || c == '.' || c == ',' || c == '=' || (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || c == '_' || (c >= 'a' && c <= 'z');
}

int is_safe_in_url(unsigned char c)
{
	return is_safe_in_shell(c) || c == ':' || c == '/' || c >= 0x80;
}

void check_shell_security(unsigned char **cmd)
{
	unsigned char *c = *cmd;
	while (*c) {
		if (!is_safe_in_shell(*c)) *c = '_';
		c++;
	}
}

int check_shell_url(unsigned char *url)
{
	while (*url) {
		if (!is_safe_in_url(*url)) return -1;
		url++;
	}
	return 0;
}

unsigned char *escape_path(unsigned char *path)
{
	unsigned char *result;
	size_t i;
	if (strchr(path, '"')) return stracpy(path);
	for (i = 0; path[i]; i++) if (!is_safe_in_url(path[i])) goto do_esc;
	return stracpy(path);
	do_esc:
	result = stracpy("\"");
	add_to_strn(&result, path);
	add_to_strn(&result, "\"");
	return result;
}

int get_e(char *env)
{
	char *v;
	if ((v = getenv(env))) return atoi(v);
	return 0;
}

void ignore_signals(void)
{
	signal(SIGPIPE, SIG_IGN);
#ifdef SIGXFSZ
	signal(SIGXFSZ, SIG_IGN);
#endif
}

char *clipboard = NULL;

#if defined(WIN32)
#include <windows.h>
#endif

#if defined(OS2)

#define INCL_MOU
#define INCL_VIO
#define INCL_DOSPROCESS
#define INCL_DOSERRORS
#define INCL_WIN
#define INCL_WINCLIPBOARD
#define INCL_WINSWITCHLIST
#include <os2.h>
#include <io.h>
#include <process.h>
#include <sys/video.h>
#ifdef HAVE_SYS_FMUTEX_H
#include <sys/builtin.h>
#include <sys/fmutex.h>
#endif

#ifdef X2
/* from xf86sup - XFree86 OS/2 support driver */
#include <pty.h>
#endif

#endif

#if defined(O_SIZE) && defined(__EMX__)

int open_prealloc(char *name, int flags, int mode, off_t siz)
{
	return open(name, flags | O_SIZE, mode, (unsigned long)siz);
}

void prealloc_truncate(int h, off_t siz)
{
	ftruncate(h, siz);
}

#endif

/* Terminal size */

#ifdef WIN32

/* Cygwin has a bug and loses WIGWINCH sometimes, so poll it */

static void winch_thread(void *p, int l)
{
	static int old_xsize, old_ysize;
	static int cur_xsize, cur_ysize;
	if (get_terminal_size(0, &old_xsize, &old_ysize)) return;
	while (1) {
		if (get_terminal_size(1, &cur_xsize, &cur_ysize)) return;
		if ((old_xsize != cur_xsize) || (old_ysize != cur_ysize)) {
			old_xsize = cur_xsize;
			old_ysize = cur_ysize;
			raise(SIGWINCH);
		}
		sleep(1);
	}
}

static void win32_resize_poll(void)
{
	static int winch_thread_running = 0;
	if (!winch_thread_running) {
		if (start_thread(winch_thread, NULL, 0) >= 0)
			winch_thread_running = 1;
	}
}

#endif

#if defined(UNIX) || defined(BEOS) || defined(RISCOS) || defined(ATHEOS) || defined(WIN32) || defined(SPAD)

void sigwinch(void *s)
{
	((void (*)(void))s)();
}

void handle_terminal_resize(int fd, void (*fn)(void))
{
	install_signal_handler(SIGWINCH, sigwinch, fn, 0);
#ifdef WIN32
	win32_resize_poll();
#endif
}

void unhandle_terminal_resize(int fd)
{
	install_signal_handler(SIGWINCH, NULL, NULL, 0);
}

int get_terminal_size(int fd, int *x, int *y)
{
	struct winsize ws;
	if (!x || !y) return -1;
	if (ioctl(1, TIOCGWINSZ, &ws) != -1) {
		if (!(*x = ws.ws_col) && !(*x = get_e("COLUMNS"))) *x = 80;
		if (!(*y = ws.ws_row) && !(*y = get_e("LINES"))) *y = 24;
		return 0;
	} else {
		if (!(*x = get_e("COLUMNS"))) *x = 80;
		if (!(*y = get_e("LINES"))) *y = 24;
	}
	return 0;
}

#elif defined(OS2)

#define A_DECL(type, var) type var##1, var##2, *var = _THUNK_PTR_STRUCT_OK(&var##1) ? &var##1 : &var##2

int is_xterm(void)
{
	static int xt = -1;
	if (xt == -1) xt = !!getenv("WINDOWID");
	return xt;
}

int winch_pipe[2];
int winch_thread_running = 0;

#define WINCH_SLEEPTIME 500 /* time in ms for winch thread to sleep */

void winch_thread(void)
{
	/* A thread which regularly checks whether the size of 
	   window has changed. Then raise SIGWINCH or notifiy
	   the thread responsible to handle this. */
	static int old_xsize, old_ysize;
	static int cur_xsize, cur_ysize;

	ignore_signals();
	if (get_terminal_size(1, &old_xsize, &old_ysize)) return;
	while (1) {
		if (get_terminal_size(1, &cur_xsize, &cur_ysize)) return;
		if ((old_xsize != cur_xsize) || (old_ysize != cur_ysize)) {
			old_xsize = cur_xsize;
			old_ysize = cur_ysize;
			write(winch_pipe[1], "x", 1);
			/* Resizing may take some time. So don't send a flood
                     of requests?! */
			_sleep2(2*WINCH_SLEEPTIME);   
		}
		else
			_sleep2(WINCH_SLEEPTIME);
	}
}

void winch(void *s)
{
	char c;
	while (can_read(winch_pipe[0]) && read(winch_pipe[0], &c, 1) == 1);
	((void (*)(void))s)();
}

void handle_terminal_resize(int fd, void (*fn)(void))
{
	if (!is_xterm()) return;
	if (!winch_thread_running) {
		if (c_pipe(winch_pipe) < 0) return;
		winch_thread_running = 1;
		_beginthread((void (*)(void *))winch_thread, NULL, 0x32000, NULL);
	}
	set_handlers(winch_pipe[0], winch, NULL, NULL, fn);
}

void unhandle_terminal_resize(int fd)
{
	set_handlers(winch_pipe[0], NULL, NULL, NULL, NULL);
}

int get_terminal_size(int fd, int *x, int *y)
{
	if (!x || !y) return -1;
	if (is_xterm()) {
#ifdef X2
		/* int fd; */
		int arc;
		struct winsize win;

		/* fd = STDIN_FILENO; */
		arc = ptioctl(1, TIOCGWINSZ, &win);
		if (arc) {
			*x = 80;
			*y = 24;
			return 0;
		}
		*y = win.ws_row;
		*x = win.ws_col;
		goto set_default;
#else
		*x = 80; *y = 24;
		return 0;
#endif
	} else {
		int a[2] = { 0, 0 };
		_scrsize(a);
		*x = a[0];
		*y = a[1];
		set_default:
		if (*x == 0) {
			*x = get_e("COLUMNS");
			if (*x == 0) *x = 80;
		}
		if (*y == 0) {
			*y = get_e("LINES");
			if (*y == 0) *y = 24;
		}
	}
	return 0;
}

#elif defined(WIN32)

#endif

/* Pipe */

#if defined(UNIX) || defined(BEOS) || defined(RISCOS) || defined(ATHEOS) || defined(SPAD)

void set_bin(int fd)
{
}

int c_pipe(int *fd)
{
	return pipe(fd);
}

#elif defined(OS2) || defined(WIN32)

void set_bin(int fd)
{
	setmode(fd, O_BINARY);
}

int c_pipe(int *fd)
{
	int r = pipe(fd);
	if (!r) set_bin(fd[0]), set_bin(fd[1]);
	return r;
}

#endif

/* Filename */

int check_file_name(unsigned char *file)
{
	return 1;		/* !!! FIXME */
}

/* Exec */

int can_twterm(void) /* Check if it make sense to call a twterm. */
{
	static int xt = -1;
	if (xt == -1) xt = !!getenv("TWDISPLAY");
	return xt;
}


#if defined(UNIX) || defined(SPAD)

int is_xterm(void)
{
	static int xt = -1;
	if (xt == -1) xt = getenv("DISPLAY") && *getenv("DISPLAY");
	return xt;
}

#elif defined(BEOS) || defined(ATHEOS)

int is_xterm(void)
{
	return 0;
}

#elif defined(WIN32)

int is_xterm(void)
{
	static int xt = -1;
	if (xt == -1) xt = !!getenv("WINDOWID");
	return xt;
}

#elif defined(RISCOS)

int is_xterm(void)
{
       return 1;
}

#endif

tcount resize_count = 0;

void close_fork_tty(void)
{
	struct terminal *t;
	struct download *d;
	struct connection *c;
	struct k_conn *k;
	foreach (t, terminals) if (t->fdin > 0) close(t->fdin);
	foreach (d, downloads) if (d->handle > 0) close(d->handle);
	foreach (c, queue) close_socket(&c->sock1), close_socket(&c->sock2);
	foreach (k, keepalive_connections) close(k->conn);
}

#if defined(WIN32)

void get_path_to_exe(void)
{
	/* Standard method (argv[0]) doesn't work, if links is executed from
	   symlink --- it returns symlink name and cmd.exe is unable to start
	   it */
	unsigned r;
	static unsigned char path[4096];
	r = GetModuleFileName(NULL, path, sizeof path);
	if (r <= 0 || r >= sizeof path) {
		path_to_exe = g_argv[0];
		return;
	}
	path_to_exe = path;
}

#else

void get_path_to_exe(void)
{
	path_to_exe = g_argv[0];
}

#endif

#if defined(UNIX) || defined(BEOS) || defined(RISCOS) || defined(ATHEOS) || defined(SPAD)

#if defined(BEOS) && defined(HAVE_SETPGID)

int exe(char *path, int fg)
{
	pid_t p;
	int s;
	fg=fg;  /* ignore flag */
	if (!(p = fork())) {
		setpgid(0, 0);
		system(path);
		_exit(0);
	}
	if (p > 0) waitpid(p, &s, 0);
	else return system(path);
	return 0;
}

#else

/* UNIX */
int exe(char *path, int fg)
{
#ifdef G
	if (F && drv->exec) return drv->exec(path, fg);
#endif
#ifdef SIGTSTP
	signal(SIGTSTP, SIG_DFL);
#endif
#ifdef SIGCONT
	signal(SIGCONT, SIG_DFL);
#endif
#ifdef SIGWINCH
	signal(SIGWINCH, SIG_DFL);
#endif
	return system(path);
}

#endif

/* clipboard -> links */
unsigned char *get_clipboard_text(struct terminal *term)
{
#ifdef GRDRV_X
	if(term && term->dev && term->dev->drv && !strcmp(term->dev->drv->name,"x")) {
		return x_get_clipboard_text();
	}
#endif
	return stracpy(clipboard);
}

/* links -> clipboard */
void set_clipboard_text(struct terminal *term, unsigned char *data)
{
#ifdef GRDRV_X
	if(term && term->dev && term->dev->drv && !strcmp(term->dev->drv->name,"x")) {
		x_set_clipboard_text(term->dev, data);
		return;
	}
#endif
	if (clipboard) mem_free(clipboard);
	clipboard = stracpy(data);
}

int clipboard_support(struct terminal *term)
{
#ifdef GRDRV_X
	if(term && term->dev && term->dev->drv && !strcmp(term->dev->drv->name,"x")) {
		return 1;
	}
#endif
	return 0;
}

void set_window_title(unsigned char *title)
{
	/* !!! FIXME */
}

unsigned char *get_window_title(void)
{
	/* !!! FIXME */
	return NULL;
}

int resize_window(int x, int y)
{
	return -1;
}

#elif defined(WIN32)

static int is_winnt(void)
{
	OSVERSIONINFO v;
	v.dwOSVersionInfoSize = sizeof v;
	if (!GetVersionEx(&v)) return 0;
	return v.dwPlatformId >= VER_PLATFORM_WIN32_NT;
}

#define WIN32_START_STRING	"start /wait "

int exe(char *path, int fg)
{
	/* This is very tricky. We must have exactly 3 arguments, the first
	   one shell and the second one "/c", otherwise Cygwin would quote
	   the arguments and trash them */
	int ct;
	char buffer[1024];
	char buffer2[1024];
	pid_t pid;
	unsigned char *x1;
	char *arg;
	x1 = GETSHELL;
	if (!x1) x1 = DEFAULT_SHELL;
	arg = alloca(strlen(WIN32_START_STRING) + 3 + strlen(path) + 1);
	strcpy(arg, WIN32_START_STRING);
	if (*path == '"' && strlen(x1) >= 7 && !strcasecmp(x1 + strlen(x1) - 7, "cmd.exe")) strcat(arg, "\"\" ");
	strcat(arg, path);
	ct = GetConsoleTitle(buffer, sizeof buffer);
	if (!(pid = fork())) {
		int i;
	/* Win98 crashes if we spawn command.com and have some sockets open */
		for (i = 0; i < FD_SETSIZE; i++) close(i);
		open("nul", O_RDONLY);
		open("nul", O_WRONLY);
		open("nul", O_WRONLY);
		execlp(x1, x1, "/c", arg, NULL);
		_exit(1);
	}
	if (!is_winnt()) {
		sleep(1);
		if (ct && GetConsoleTitle(buffer2, sizeof buffer2) && !casecmp(buffer2, "start", 5)) {
			SetConsoleTitle(buffer);
		}
	}
	if (pid != -1) waitpid(pid, NULL, 0);
	return 0;
}

unsigned char *get_clipboard_text(struct terminal *term)
{
	char buffer[256];
	unsigned char *str, *s, *d;
	int l;
	int r;
	int h = open("/dev/clipboard", O_RDONLY);
	if (h == -1) return stracpy(clipboard);
	set_bin(h);	/* O_TEXT doesn't work on clipboard handle */
	str = init_str();
	l = 0;
	while ((r = hard_read(h, buffer, sizeof buffer)) > 0)
		add_bytes_to_str(&str, &l, buffer, r);
	close(h);
	for (s = str, d = str; *s; s++)
		if (!(s[0] == '\r' && s[1] == '\n')) *d++ = *s;
	*d = 0;
	return str;
}

/* Putting Czech characters to clipboard doesn't work, but it should be fixed
   rather in Cygwin than here */
void set_clipboard_text(struct terminal *term, unsigned char *data)
{
	unsigned char *conv_data;
	int l;
	int h;
	if (clipboard) mem_free(clipboard);
	clipboard = stracpy(data);
	h = open("/dev/clipboard", O_WRONLY);
	if (h == -1) return;
	set_bin(h);	/* O_TEXT doesn't work on clipboard handle */
	conv_data = init_str();
	l = 0;
	for (; *data; data++)
		if (*data == '\n') add_to_str(&conv_data, &l, "\r\n");
		else add_chr_to_str(&conv_data, &l, *data);
	hard_write(h, conv_data, l);
	mem_free(conv_data);
	close(h);
}

int clipboard_support(struct terminal *term)
{
	return 1;
}


static int get_windows_cp(void)
{
	char str[6];
	int cp, idx;
	static int win_cp_idx = -1;
	if (win_cp_idx != -1) return win_cp_idx;
	cp = GetConsoleOutputCP();
	if (cp <= 0 || cp >= 100000) return 0;
	sprintf(str, "%d", cp);
	if ((idx = get_cp_index(str)) < 0) return 0;
	win_cp_idx = idx;
	return idx;
}

static int get_utf8_cp(void)
{
	static int idx = -1;
	return idx >= 0 ? idx : (idx = get_cp_index("utf-8"));
}

void set_window_title(unsigned char *title)
{
	unsigned char *t;
	struct conv_table *ct;
	if (is_xterm()) return;
	ct = get_translation_table(get_utf8_cp(), get_windows_cp());
	t = convert_string(ct, title, strlen(title), NULL);
	SetConsoleTitle(t);
	mem_free(t);
}

unsigned char *get_window_title(void)
{
	struct conv_table *ct;
	int r;
	char buffer[1024];
	if (is_xterm()) return NULL;
	if (!(r = GetConsoleTitle(buffer, sizeof buffer))) return NULL;
	ct = get_translation_table(get_windows_cp(), get_utf8_cp());
	return convert_string(ct, buffer, r, NULL);
}

static void call_resize(unsigned char *x1, int x, int y)
{
	pid_t pid;
	unsigned char arg[40];
	sprintf(arg, "mode %d,%d", x, y);
	if (!(pid = fork())) {
		int i;
	/* Win98 crashes if we spawn command.com and have some sockets open */
		for (i = 0; i < FD_SETSIZE; i++) if (i != 1 && i != 2) close(i);
		open("nul", O_WRONLY);
		execlp(x1, x1, "/c", arg, NULL);
		_exit(1);
	}
	if (pid != -1) waitpid(pid, NULL, 0);
}

int resize_window(int x, int y)
{
	int old_x, old_y;
	int ct = 0, fullscreen = 0;
	char buffer[1024];
	unsigned char *x1;
	if (is_xterm()) return -1;
	if (get_terminal_size(1, &old_x, &old_y)) return -1;
	x1 = GETSHELL;
	if (!x1) x1 = DEFAULT_SHELL;
	if (!is_winnt()) {
		ct = GetConsoleTitle(buffer, sizeof buffer);
	}

	call_resize(x1, x, y);
	if (!is_winnt()) {
		int new_x, new_y;
	/* If we resize console on Win98 in fullscreen mode, it won't be
	   notified by Cygwin (it is valid for all Cygwin apps). So we must
	   switch to windowed mode, resize it again (twice, because resizing
	   to the same size won't have an effect) and switch back to full-screen
	   mode. */
	/* I'm not sure what's the behavior on WinNT 4. Anybody wants to test?
	   */
		if (!fullscreen && !get_terminal_size(1, &new_x, &new_y) && (new_x != x || new_y != y)) {
			fullscreen = 1;
			keybd_event(VK_MENU, 0x38, 0, 0);
			keybd_event(VK_RETURN, 0x1c, 0, 0);
			keybd_event(VK_RETURN, 0x1c, KEYEVENTF_KEYUP, 0);
			keybd_event(VK_MENU, 0x38, KEYEVENTF_KEYUP, 0);
			if (y != 25) call_resize(x1, 80, 25);
			else call_resize(x1, 80, 50);
			call_resize(x1, x, y);
			if (get_terminal_size(1, &new_x, &new_y) || new_x != x || new_y != y) call_resize(x1, old_x, old_y);
			keybd_event(VK_MENU, 0x38, 0, 0);
			keybd_event(VK_RETURN, 0x1c, 0, 0);
			keybd_event(VK_RETURN, 0x1c, KEYEVENTF_KEYUP, 0);
			keybd_event(VK_MENU, 0x38, KEYEVENTF_KEYUP, 0);
		}
		if (ct) SetConsoleTitle(buffer);
	}
	return 0;
}

#elif defined(OS2)

#ifdef G
_fmutex fd_mutex;
int fd_mutex_init = 0;
#endif

int exe(char *path, int fg)
{
	int flags = P_SESSION;
	pid_t pid;
	int ret;
#ifdef G
	int old0 = 0, old1 = 1, old2 = 2;
#endif
	char *shell;
	fg=fg; /* ignore flag */
	if (!(shell = GETSHELL)) shell = DEFAULT_SHELL;
	if (is_xterm()) flags |= P_BACKGROUND;
#ifdef G
	if (F) {
		if (!fd_mutex_init) {
			if (_fmutex_create(&fd_mutex, 0)) return -1;
			fd_mutex_init = 1;
		}
		_fmutex_request(&fd_mutex, _FMR_IGNINT);
		old0 = dup(0);
		old1 = dup(1);
		old2 = dup(2);
		close(0);
		close(1);
		close(2);
		open("con", O_RDONLY);
		open("con", O_WRONLY);
		open("con", O_WRONLY);
	}
#endif
	pid = spawnlp(flags, shell, shell, "/c", path, NULL);
#ifdef G
	if (F) {
		dup2(old0, 0);
		dup2(old1, 1);
		dup2(old2, 2);
		close(old0);
		close(old1);
		close(old2);
		_fmutex_release(&fd_mutex);
	}
#endif
	if (pid != -1) waitpid(pid, &ret, 0);
	else ret = -1;
	return ret;
}

unsigned char *get_clipboard_text(struct terminal *term)
{
	PTIB tib;
	PPIB pib;
	HAB hab;
	HMQ hmq;
	ULONG oldType;
	char *ret = NULL;

	DosGetInfoBlocks(&tib, &pib);

	oldType = pib->pib_ultype;

	pib->pib_ultype = 3;

	if ((hab = WinInitialize(0)) != NULLHANDLE) {
		if ((hmq = WinCreateMsgQueue(hab, 0)) != NULLHANDLE) {

			if (WinOpenClipbrd(hab)) {
				ULONG fmtInfo = 0;

				if (WinQueryClipbrdFmtInfo(hab, CF_TEXT, &fmtInfo)!=FALSE)
				{
					ULONG selClipText = WinQueryClipbrdData(hab, CF_TEXT);

					if (selClipText)
					{
						char *u;
						PCHAR pchClipText = (PCHAR)selClipText;
						ret = mem_alloc(strlen(pchClipText)+1);
						strcpy(ret, pchClipText);
						while ((u = strchr(ret, 13))) memmove(u, u + 1, strlen(u + 1) + 1);
					}
				}

				WinCloseClipbrd(hab);
			}

#ifdef G
			if (F && ret) {
				static int cp = -1;
				struct conv_table *ct;
				unsigned char *d;
				if (cp == -1) {
					int c = WinQueryCp(hmq);
					unsigned char a[64];
					snprintf(a, 64, "%d", c);
					if ((cp = get_cp_index(a)) < 0 || is_cp_special(cp)) cp = 0;
				}
				ct = get_translation_table(cp, get_cp_index("utf-8"));
				d = convert_string(ct, ret, strlen(ret), NULL);
				mem_free(ret);
				ret = d;
			}
#endif
			WinDestroyMsgQueue(hmq);
		}
		WinTerminate(hab);
	}

	pib->pib_ultype = oldType;

	return ret;
}

void set_clipboard_text(struct terminal * term, unsigned char *data)
{
	PTIB tib;
	PPIB pib;
	HAB hab;
	HMQ hmq;
	ULONG oldType;

	unsigned char *d = NULL;
	
	DosGetInfoBlocks(&tib, &pib);

	oldType = pib->pib_ultype;

	pib->pib_ultype = 3;

	if ((hab = WinInitialize(0)) != NULLHANDLE) {
		if ((hmq = WinCreateMsgQueue(hab, 0)) != NULLHANDLE) {
#ifdef G
			if (F) {
				static int cp = -1;
				struct conv_table *ct;
				if (cp == -1) {
					int c = WinQueryCp(hmq);
					unsigned char a[64];
					snprintf(a, 64, "%d", c);
					if ((cp = get_cp_index(a)) < 0 || is_cp_special(cp)) cp = 0;
				}
				ct = get_translation_table(get_cp_index("utf-8"), cp);
				d = convert_string(ct, data, strlen(data), NULL);
				data = d;
			}
#endif
			if(WinOpenClipbrd(hab)) {
				PVOID pvShrObject = NULL;
				if (DosAllocSharedMem(&pvShrObject, NULL, strlen(data)+1, PAG_COMMIT | PAG_WRITE | OBJ_GIVEABLE) == NO_ERROR) {
					strcpy(pvShrObject, data);
					WinSetClipbrdData(hab, (ULONG)pvShrObject, CF_TEXT, CFI_POINTER);
				}
				WinCloseClipbrd(hab);
			}
			WinDestroyMsgQueue(hmq);
		}
		WinTerminate(hab);
	}

	pib->pib_ultype = oldType;

	if (d) mem_free(d);
}

int clipboard_support(struct terminal *term)
{
	return 1;
}

unsigned char *get_window_title(void)
{
#ifndef OS2_DEBUG
	/*char *org_switch_title;*/
	char *org_win_title = NULL;
	static PTIB tib = NULL;
	static PPIB pib = NULL;
	ULONG oldType;
	HSWITCH hSw = NULLHANDLE;
	SWCNTRL swData;
	HAB hab;
	HMQ hmq;

	/* save current process title */

	if (!pib) DosGetInfoBlocks(&tib, &pib);
	oldType = pib->pib_ultype;
	memset(&swData, 0, sizeof swData);
	if (hSw == NULLHANDLE) hSw = WinQuerySwitchHandle(0, pib->pib_ulpid);
	if (hSw!=NULLHANDLE && !WinQuerySwitchEntry(hSw, &swData)) {
		/*org_switch_title = mem_alloc(strlen(swData.szSwtitle)+1);
		strcpy(org_switch_title, swData.szSwtitle);*/
		/* Go to PM */
		pib->pib_ultype = 3;
		if ((hab = WinInitialize(0)) != NULLHANDLE) {
			if ((hmq = WinCreateMsgQueue(hab, 0)) != NULLHANDLE) {
				org_win_title = mem_alloc(MAXNAMEL+1);
				WinQueryWindowText(swData.hwnd, MAXNAMEL+1, org_win_title);
				org_win_title[MAXNAMEL] = 0;
				/* back From PM */
				WinDestroyMsgQueue(hmq);
			}
			WinTerminate(hab);
		}
		pib->pib_ultype = oldType;
	}
	return org_win_title;
#else
	return NULL;
#endif
}

void set_window_title(unsigned char *title)
{
#ifndef OS2_DEBUG
	static PTIB tib;
	static PPIB pib;
	ULONG oldType;
	static HSWITCH hSw;
	SWCNTRL swData;
	HAB hab;
	HMQ hmq;
	if (!title) return;
	if (!pib) DosGetInfoBlocks(&tib, &pib);
	oldType = pib->pib_ultype;
	memset(&swData, 0, sizeof swData);
	if (hSw == NULLHANDLE) hSw = WinQuerySwitchHandle(0, pib->pib_ulpid);
	if (hSw!=NULLHANDLE && !WinQuerySwitchEntry(hSw, &swData)) {
		strncpy(swData.szSwtitle, title, MAXNAMEL-1);
		swData.szSwtitle[MAXNAMEL-1] = 0;
		WinChangeSwitchEntry(hSw, &swData);
		/* Go to PM */
		pib->pib_ultype = 3;
		if ((hab = WinInitialize(0)) != NULLHANDLE) {
			if ((hmq = WinCreateMsgQueue(hab, 0)) != NULLHANDLE) {
				if(swData.hwnd)
					WinSetWindowText(swData.hwnd, title);
					/* back From PM */
				WinDestroyMsgQueue(hmq);
			}
			WinTerminate(hab);
		}
	}
	pib->pib_ultype = oldType;
#endif
}

int resize_window(int x, int y)
{
	int xfont, yfont;
	A_DECL(VIOMODEINFO, vmi);
	resize_count++;
	if (is_xterm()) return -1;
	vmi->cb = sizeof(*vmi);
	if (VioGetMode(vmi, 0)) return -1;
	vmi->col = x;
	vmi->row = y;
	/*debug("%d %d %d", vmi->buf_length, vmi->full_length, vmi->partial_length);*/
	for (xfont = 9; xfont >= 8; xfont--)
		for (yfont = 16; yfont >= 8; yfont--) {
			vmi->hres = x * xfont;
			vmi->vres = y * yfont;
			if (vmi->vres <= 400) vmi->vres = 400;
			else if (vmi->vres <= 480) vmi->vres = 480;
			vmi->buf_length = vmi->full_length = vmi->partial_length = x * ((vmi->vres + yfont - 1) / yfont) * 2;
			vmi->full_length = (vmi->full_length + 4095) & ~4095;
			vmi->partial_length = (vmi->partial_length + 4095) & ~4095;
			if (!VioSetMode(vmi, 0)) return 0;
		}
	return -1;
}

#endif

/* Threads */

struct tdata {
	void (*fn)(void *, int);
	int h;
	unsigned char data[1];
};

#if defined(HAVE_BEGINTHREAD) || defined(BEOS) || defined(HAVE_PTHREADS) || defined(HAVE_ATHEOS_THREADS_H)

void bgt(struct tdata *t)
{
	ignore_signals();
	t->fn(t->data, t->h);
	write(t->h, "x", 1);
	close(t->h);
	free(t);
}

#ifdef HAVE_PTHREADS
void *bgpt(struct tdata *t)
{
	bgt(t);
	return NULL;
}
#endif

#ifdef HAVE_ATHEOS_THREADS_H
#include <atheos/threads.h>
uint32 abgt(void *t)
{
	bgt(t);
	return 0;
}
#endif

#endif

#if defined(UNIX) || defined(OS2) || defined(RISCOS) || defined(ATHEOS) || defined(SPAD) || defined(WIN32)

void terminate_osdep(void) {}

#endif

#ifndef BEOS

void block_stdin(void) {}
void unblock_stdin(void) {}

#endif

#if defined(BEOS)

#include <be/kernel/OS.h>

int thr_sem_init = 0;
sem_id thr_sem;

struct list_head active_threads = { &active_threads, &active_threads };

struct active_thread {
	struct active_thread *next;
	struct active_thread *prev;
	thread_id tid;
	void (*fn)(void *);
	void *data;
};

int32 started_thr(void *data)
{
	struct active_thread *thrd = data;
	thrd->fn(thrd->data);
	if (acquire_sem(thr_sem) < B_NO_ERROR) return 0;
	del_from_list(thrd);
	free(thrd);
	release_sem(thr_sem);
	return 0;
}

int start_thr(void (*fn)(void *), void *data, unsigned char *name)
{
	struct active_thread *thrd;
	int tid;
	if (!thr_sem_init) {
		if ((thr_sem = create_sem(0, "thread_sem")) < B_NO_ERROR) return -1;
		thr_sem_init = 1;
	} else if (acquire_sem(thr_sem) < B_NO_ERROR) return -1;
	if (!(thrd = malloc(sizeof(struct active_thread)))) goto rel;
	thrd->fn = fn;
	thrd->data = data;
	if ((tid = thrd->tid = spawn_thread(started_thr, name, B_NORMAL_PRIORITY, thrd)) < B_NO_ERROR) {
		free(thrd);
		rel:
		release_sem(thr_sem);
		return -1;
	}
	resume_thread(thrd->tid);
	add_to_list(active_threads, thrd);
	release_sem(thr_sem);
	return tid;
}

void terminate_osdep(void)
{
	struct list_head *p;
	struct active_thread *thrd;
	if (acquire_sem(thr_sem) < B_NO_ERROR) return;
	foreach(thrd, active_threads) kill_thread(thrd->tid);
	while ((p = active_threads.next) != &active_threads) {
		del_from_list(p);
		free(p);
	}
	release_sem(thr_sem);
}

int start_thread(void (*fn)(void *, int), void *ptr, int l)
{
	int p[2];
	struct tdata *t;
	if (c_pipe(p) < 0) return -1;
	if (!(t = malloc(sizeof(struct tdata) + l))) return -1;
	t->fn = fn;
	t->h = p[1];
	memcpy(t->data, ptr, l);
	if (start_thr((void (*)(void *))bgt, t, "links_thread") < 0) {
		close(p[0]);
		close(p[1]);
		mem_free(t);
		return -1;
	}
	return p[0];
}


#elif defined(HAVE_BEGINTHREAD)

int start_thread(void (*fn)(void *, int), void *ptr, int l)
{
	int p[2];
	struct tdata *t;
	if (c_pipe(p) < 0) return -1;
	fcntl(p[0], F_SETFL, O_NONBLOCK);
	fcntl(p[1], F_SETFL, O_NONBLOCK);
	if (!(t = malloc(sizeof(struct tdata) + l))) return -1;
	t->fn = fn;
	t->h = p[1];
	memcpy(t->data, ptr, l);
	if (_beginthread((void (*)(void *))bgt, NULL, 65536, t) == -1) {
		close(p[0]);
		close(p[1]);
		mem_free(t);
		return -1;
	}
	return p[0];
}

#ifdef HAVE_READ_KBD

int tp = -1;
int ti = -1;

void input_thread(void *p)
{
	char c[2];
	int h = (int)p;
	ignore_signals();
	while (1) {
		/*c[0] = _read_kbd(0, 1, 1);
		if (c[0]) if (write(h, c, 1) <= 0) break;
		else {
			int w;
			printf("1");fflush(stdout);
			c[1] = _read_kbd(0, 1, 1);
			printf("2");fflush(stdout);
			w = write(h, c, 2);
			printf("3");fflush(stdout);
			if (w <= 0) break;
			if (w == 1) if (write(h, c+1, 1) <= 0) break;
			printf("4");fflush(stdout);
		}*/
           /* for the records: 
                 _read_kbd(0, 1, 1) will
                 read a char, don't echo it, wait for one available and
                 accept CTRL-C.
                 Knowing that, I suggest we replace this call completly!
            */
                *c = _read_kbd(0, 1, 1);
                write(h, c, 1);
	}
	close(h);
}
#endif /* #ifdef HAVE_READ_KBD */

#if defined(HAVE_MOUOPEN) && !defined(USE_GPM)

#define USING_OS2_MOUSE

#ifdef HAVE_SYS_FMUTEX_H
_fmutex mouse_mutex;
int mouse_mutex_init = 0;
#endif
int mouse_h = -1;

struct os2_mouse_spec {
	int p[2];
	void (*fn)(void *, unsigned char *, int);
	void *data;
	unsigned char buffer[sizeof(struct event)];
	int bufptr;
	int terminate;
};

void mouse_thread(void *p)
{
	int status;
	struct os2_mouse_spec *oms = p;
	A_DECL(HMOU, mh);
	A_DECL(MOUEVENTINFO, ms);
	A_DECL(USHORT, rd);
	A_DECL(USHORT, mask);
	struct event ev;
	ignore_signals();
	ev.ev = EV_MOUSE;
	if (MouOpen(NULL, mh)) goto ret;
	mouse_h = *mh;
	*mask = MOUSE_MOTION_WITH_BN1_DOWN | MOUSE_BN1_DOWN |
		MOUSE_MOTION_WITH_BN2_DOWN | MOUSE_BN2_DOWN |
		MOUSE_MOTION_WITH_BN3_DOWN | MOUSE_BN3_DOWN |
		MOUSE_MOTION;
	MouSetEventMask(mask, *mh);
	*rd = MOU_WAIT;
	status = -1;
	while (1) {
		/*int w, ww;*/
		if (MouReadEventQue(ms, rd, *mh)) break;
#ifdef HAVE_SYS_FMUTEX_H
		_fmutex_request(&mouse_mutex, _FMR_IGNINT);
#endif
		if (!oms->terminate) MouDrawPtr(*mh);
#ifdef HAVE_SYS_FMUTEX_H
		_fmutex_release(&mouse_mutex);
#endif
		ev.x = ms->col;
		ev.y = ms->row;
		/*debug("status: %d %d %d", ms->col, ms->row, ms->fs);*/
		if (ms->fs & (MOUSE_BN1_DOWN | MOUSE_BN2_DOWN | MOUSE_BN3_DOWN)) ev.b = status = B_DOWN | (ms->fs & MOUSE_BN1_DOWN ? B_LEFT : ms->fs & MOUSE_BN2_DOWN ? B_MIDDLE : B_RIGHT);
		else if (ms->fs & (MOUSE_MOTION_WITH_BN1_DOWN | MOUSE_MOTION_WITH_BN2_DOWN | MOUSE_MOTION_WITH_BN3_DOWN)) {
			int b = ms->fs & MOUSE_MOTION_WITH_BN1_DOWN ? B_LEFT : ms->fs & MOUSE_MOTION_WITH_BN2_DOWN ? B_MIDDLE : B_RIGHT;
			if (status == -1) b |= B_DOWN;
			else b |= B_DRAG;
			ev.b = status = b;
		}
		else {
			if (status == -1) continue;
			ev.b = (status & BM_BUTT) | B_UP;
			status = -1;
		}
		if (hard_write(oms->p[1], (unsigned char *)&ev, sizeof(struct event)) != sizeof(struct event)) break;
	}
#ifdef HAVE_SYS_FMUTEX_H
	_fmutex_request(&mouse_mutex, _FMR_IGNINT);
#endif
	mouse_h = -1;
	MouClose(*mh);
#ifdef HAVE_SYS_FMUTEX_H
	_fmutex_release(&mouse_mutex);
#endif
	ret:
	close(oms->p[1]);
	/*free(oms);*/
}

void mouse_handle(struct os2_mouse_spec *oms)
{
	int r;
	if ((r = read(oms->p[0], oms->buffer + oms->bufptr, sizeof(struct event) - oms->bufptr)) <= 0) {
		unhandle_mouse(oms);
		return;
	}
	if ((oms->bufptr += r) == sizeof(struct event)) {
		oms->bufptr = 0;
		oms->fn(oms->data, oms->buffer, sizeof(struct event));
	}
}

void *handle_mouse(int cons, void (*fn)(void *, unsigned char *, int), void *data)
{
	struct os2_mouse_spec *oms;
	if (is_xterm()) return NULL;
#ifdef HAVE_SYS_FMUTEX_H
	if (!mouse_mutex_init) {
		if (_fmutex_create(&mouse_mutex, 0)) return NULL;
		mouse_mutex_init = 1;
	}
#endif
		/* This is never freed but it's allocated only once */
	if (!(oms = malloc(sizeof(struct os2_mouse_spec)))) return NULL;
	oms->fn = fn;
	oms->data = data;
	oms->bufptr = 0;
	oms->terminate = 0;
	if (c_pipe(oms->p)) {
		free(oms);
		return NULL;
	}
	_beginthread(mouse_thread, NULL, 0x10000, (void *)oms);
	set_handlers(oms->p[0], (void (*)(void *))mouse_handle, NULL, NULL, oms);
	return oms;
}

void unhandle_mouse(void *om)
{
	struct os2_mouse_spec *oms = om;
	want_draw();
	oms->terminate = 1;
	set_handlers(oms->p[0], NULL, NULL, NULL, NULL);
	close(oms->p[0]);
	done_draw();
}

void want_draw(void)
{
	A_DECL(NOPTRRECT, pa);
#ifdef HAVE_SYS_FMUTEX_H
	if (mouse_mutex_init) _fmutex_request(&mouse_mutex, _FMR_IGNINT);
#endif
	if (mouse_h != -1) {
		static int x = -1, y = -1;
		static tcount c = -1;
		if (x == -1 || y == -1 || (c != resize_count)) get_terminal_size(1, &x, &y), c = resize_count;
		pa->row = 0;
		pa->col = 0;
		pa->cRow = y - 1;
		pa->cCol = x - 1;
		MouRemovePtr(pa, mouse_h);
	}
}

void done_draw(void)
{
#ifdef HAVE_SYS_FMUTEX_H
	if (mouse_mutex_init) _fmutex_release(&mouse_mutex);
#endif
}

#endif /* if HAVE_MOUOPEN */

#elif defined(HAVE_CLONE)

/* This is maybe buggy... */

#include <sched.h>

struct thread_stack {
	struct thread_stack *next;
	struct thread_stack *prev;
	int pid;
	void *stack;
	void (*fn)(void *, int);
	int h;
	int l;
	unsigned char data[1];
};

void bglt(struct thread_stack *ts)
{
	ts->fn(ts->data, ts->h);
	write(ts->h, "x", 1);
	close(ts->h);
}

struct list_head thread_stacks = { &thread_stacks, &thread_stacks };

int start_thread(void (*fn)(void *, int), void *ptr, int l)
{
	struct thread_stack *ts;
	int p[2];
	int f;
	if (c_pipe(p) < 0) return -1;
	fcntl(p[0], F_SETFL, O_NONBLOCK);
	fcntl(p[1], F_SETFL, O_NONBLOCK);
	/*if (!(t = malloc(sizeof(struct tdata) + l))) return -1;
	t->fn = fn;
	t->h = p[1];
	memcpy(t->data, ptr, l);*/
	foreach(ts, thread_stacks) {
		if (ts->pid == -1 || kill(ts->pid, 0)) {
			if (ts->l >= l) goto ts_ok;
			else {
				struct thread_stack *tts = ts;
				ts = ts->prev;
				del_from_list(tts); free(tts->stack); free(tts);
			}
		}
	}
	if (!(ts = malloc(sizeof(struct thread_stack) + l))) goto fail;
	if (!(ts->stack = malloc(0x10000))) {
		free(ts);
		goto fail;
	}
	ts->l = l;
	add_to_list(thread_stacks, ts);
	ts_ok:
	ts->fn = fn;
	ts->h = p[1];
	memcpy(ts->data, ptr, l);
	if ((ts->pid = __clone((int (*)(void *))bglt, (char *)ts->stack + 0x8000, CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | SIGCHLD, ts)) == -1) {
		fail:
		close(p[0]);
		close(p[1]);
		return -1;
	}
	return p[0];
}

#elif defined(HAVE_PTHREADS)

#include <pthread.h>

int start_thread(void (*fn)(void *, int), void *ptr, int l)
{
	pthread_t thread;
	struct tdata *t;
	int p[2];
	if (c_pipe(p) < 0) return -1;
	fcntl(p[0], F_SETFL, O_NONBLOCK);
	fcntl(p[1], F_SETFL, O_NONBLOCK);
	if (!(t = malloc(sizeof(struct tdata) + l))) return -1;
	t->fn = fn;
	t->h = p[1];
	memcpy(t->data, ptr, l);
	if (pthread_create(&thread, NULL, (void *(*)(void *))bgpt, t)) {
		close(p[0]);
		close(p[1]);
		mem_free(t);
		return -1;
	}
	return p[0];
}

#elif defined(HAVE_ATHEOS_THREADS_H) && defined(HAVE_SPAWN_THREAD) && defined(HAVE_RESUME_THREAD)

#include <atheos/threads.h>

int start_thread(void (*fn)(void *, int), void *ptr, int l)
{
	int p[2];
	thread_id f;
	struct tdata *t;
	if (c_pipe(p) < 0) return -1;
	fcntl(p[0], F_SETFL, O_NONBLOCK);
	fcntl(p[1], F_SETFL, O_NONBLOCK);
	if (!(t = malloc(sizeof(struct tdata) + l))) return -1;
	t->fn = fn;
	t->h = p[1];
	memcpy(t->data, ptr, l);
	if ((f = spawn_thread("links_lookup", abgt, 0, 0, t)) == -1) {
		close(p[0]);
		close(p[1]);
		mem_free(t);
		return -1;
	}
	resume_thread(f);
	return p[0];
}

#else /* HAVE_BEGINTHREAD */

int start_thread(void (*fn)(void *, int), void *ptr, int l)
{
	int p[2];
	pid_t f;
	if (c_pipe(p) < 0) return -1;
	fcntl(p[0], F_SETFL, O_NONBLOCK);
	fcntl(p[1], F_SETFL, O_NONBLOCK);
	if (!(f = fork())) {
		close_fork_tty();
		close(p[0]);
		fn(ptr, p[1]);
		write(p[1], "x", 1);
		close(p[1]);
		_exit(0);
	}
	if (f == -1) {
		close(p[0]);
		close(p[1]);
		return -1;
	}
	close(p[1]);
	return p[0];
}

#endif

#ifndef USING_OS2_MOUSE
void want_draw(void) {}
void done_draw(void) {}
#endif

int get_output_handle(void) { return 1; }

#if defined(OS2)

int get_ctl_handle(void) { return get_input_handle(); }

#else

int get_ctl_handle(void) { return 0; }

#endif

#if defined(BEOS)

#elif defined(HAVE_BEGINTHREAD) && defined(HAVE_READ_KBD)
int get_input_handle(void)
{
	int fd[2];
	if (ti != -1) return ti;
	if (is_xterm()) return 0;
	if (c_pipe(fd) < 0) return 0;
	ti = fd[0];
	tp = fd[1];
	_beginthread(input_thread, NULL, 0x10000, (void *)tp);
/*
#if defined(HAVE_MOUOPEN) && !defined(USE_GPM)
	_beginthread(mouse_thread, NULL, 0x10000, (void *)tp);
#endif
*/
	return fd[0];
}

#else

int get_input_handle(void)
{
	return 0;
}

#endif /* defined(HAVE_BEGINTHREAD) && defined(HAVE_READ_KBD) */


void os_cfmakeraw(struct termios *t)
{
#ifdef HAVE_CFMAKERAW
	cfmakeraw(t);
#ifdef VMIN
	t->c_cc[VMIN] = 1;
#endif
#else
	t->c_iflag &= ~(IGNBRK|BRKINT|PARMRK|ISTRIP|INLCR|IGNCR|ICRNL|IXON);
	t->c_oflag &= ~OPOST;
	t->c_lflag &= ~(ECHO|ECHONL|ICANON|ISIG|IEXTEN);
	t->c_cflag &= ~(CSIZE|PARENB);
	t->c_cflag |= CS8;
	t->c_cc[VMIN] = 1;
	t->c_cc[VTIME] = 0;
#endif
}

#ifdef USE_GPM

struct gpm_mouse_spec {
	int h;
	void (*fn)(void *, unsigned char *, int);
	void *data;
};

static void gpm_mouse_in(struct gpm_mouse_spec *gms)
{
	Gpm_Event gev;
	struct event ev;
	if (Gpm_GetEvent(&gev) <= 0) {
		set_handlers(gms->h, NULL, NULL, NULL, NULL);
		return;
	}
	ev.ev = EV_MOUSE;
	ev.x = gev.x - 1;
	ev.y = gev.y - 1;
	if (ev.x < 0) ev.x = 0;
	if (ev.y < 0) ev.y = 0;
	if (gev.buttons & GPM_B_LEFT) ev.b = B_LEFT;
	else if (gev.buttons & GPM_B_MIDDLE) ev.b = B_MIDDLE;
	else if (gev.buttons & GPM_B_RIGHT) ev.b = B_RIGHT;
	else return;
	if (gev.type & GPM_DOWN) ev.b |= B_DOWN;
	else if (gev.type & GPM_UP) ev.b |= B_UP;
	else if (gev.type & GPM_DRAG) ev.b |= B_DRAG;
	else return;
	gms->fn(gms->data, (char *)&ev, sizeof(struct event));
}

/* GPM installs its own signal handlers and we don't want them */

sigset_t gpm_sigset;
char gpm_sigset_valid;
#ifdef SIGWINCH
struct sigaction gpm_winch;
char gpm_winch_valid;
#endif
#ifdef SIGTSTP
struct sigaction gpm_tstp;
char gpm_tstp_valid;
#endif

static void save_gpm_signals(void)
{
	sigset_t sig;
	sigemptyset(&sig);
#ifdef SIGWINCH
	sigaddset(&sig, SIGWINCH);
#endif
#ifdef SIGTSTP
	sigaddset(&sig, SIGTSTP);
#endif
	gpm_sigset_valid = !sigprocmask(SIG_BLOCK, &sig, &gpm_sigset);
#ifdef SIGWINCH
	gpm_winch_valid = !sigaction(SIGWINCH, NULL, &gpm_winch);
#endif
#ifdef SIGTSTP
	gpm_tstp_valid = !sigaction(SIGTSTP, NULL, &gpm_tstp);
#endif
}

static void restore_gpm_signals(void)
{
#ifdef SIGWINCH
	if (gpm_winch_valid) sigaction(SIGWINCH, &gpm_winch, NULL);
#endif
#ifdef SIGTSTP
	if (gpm_tstp_valid) sigaction(SIGTSTP, &gpm_tstp, NULL);
#endif
	if (gpm_sigset_valid) sigprocmask(SIG_SETMASK, &gpm_sigset, NULL);
}

void *handle_mouse(int cons, void (*fn)(void *, unsigned char *, int), void *data)
{
	int h;
	Gpm_Connect conn;
	struct gpm_mouse_spec *gms;
	conn.eventMask = ~GPM_MOVE;
	conn.defaultMask = GPM_MOVE;
	conn.minMod = 0;
	conn.maxMod = 0;
	save_gpm_signals();
	h = Gpm_Open(&conn, cons);
	restore_gpm_signals();
	if (h < 0) return NULL;
	gms = mem_alloc(sizeof(struct gpm_mouse_spec));
	gms->h = h;
	gms->fn = fn;
	gms->data = data;
	set_handlers(h, (void (*)(void *))gpm_mouse_in, NULL, NULL, gms);
	return gms;
}

void unhandle_mouse(void *h)
{
	struct gpm_mouse_spec *gms = h;
	set_handlers(gms->h, NULL, NULL, NULL, NULL);
	save_gpm_signals();
	Gpm_Close();
	restore_gpm_signals();
	mem_free(gms);
}

#elif !defined(USING_OS2_MOUSE)

void *handle_mouse(int cons, void (*fn)(void *, unsigned char *, int), void *data) { return NULL; }
void unhandle_mouse(void *data) { }

#endif /* #ifdef USE_GPM */

#if defined(OS2)

int get_system_env(void)
{
	if (is_xterm()) return 0;
	return ENV_OS2VIO;		/* !!! FIXME: telnet */
}

#elif defined(BEOS)

int get_system_env(void)
{
	unsigned char *term = getenv("TERM");
	if (!term || (upcase(term[0]) == 'B' && upcase(term[1]) == 'E')) return ENV_BE;
	return 0;
}

#elif defined(WIN32)

int get_system_env(void)
{
	if (is_xterm()) return 0;
	return ENV_WIN32;
}

#else

int get_system_env(void)
{
	return 0;
}

#endif

void exec_new_links(struct terminal *term, unsigned char *xterm, unsigned char *exe, unsigned char *param)
{
	unsigned char *str;
	str = mem_alloc(strlen(xterm) + 1 + strlen(exe) + 1 + strlen(param) + 1);
	if (*xterm) sprintf(str, "%s %s %s", xterm, exe, param);
	else sprintf(str, "%s %s", exe, param);
	exec_on_terminal(term, str, "", 2);
	mem_free(str);
}

void open_in_new_twterm(struct terminal *term, unsigned char *exe, unsigned char *param)
{
	unsigned char *twterm;
	if (!(twterm = getenv("LINKS_TWTERM"))) twterm = "twterm -e";
	exec_new_links(term, twterm, exe, param);
}

void open_in_new_xterm(struct terminal *term, unsigned char *exe, unsigned char *param)
{
	unsigned char *xterm;
	if (!(xterm = getenv("LINKS_XTERM"))) xterm = "xterm -e";
	exec_new_links(term, xterm, exe, param);
}

void open_in_new_screen(struct terminal *term, unsigned char *exe, unsigned char *param)
{
	exec_new_links(term, "screen", exe, param);
}

#ifdef OS2
void open_in_new_vio(struct terminal *term, unsigned char *exe, unsigned char *param)
{
	exec_new_links(term, "cmd /c start /c /f /win", exe, param);
}

void open_in_new_fullscreen(struct terminal *term, unsigned char *exe, unsigned char *param)
{
	exec_new_links(term, "cmd /c start /c /f /fs", exe, param);
}
#endif

#ifdef WIN32
void open_in_new_win32(struct terminal *term, unsigned char *exe, unsigned char *param)
{
	exec_new_links(term, "", exe, param);
}
#endif

#ifdef BEOS
void open_in_new_be(struct terminal *term, unsigned char *exe, unsigned char *param)
{
	exec_new_links(term, "Terminal", exe, param);
}
#endif

#ifdef G
void open_in_new_g(struct terminal *term, unsigned char *exe, unsigned char *param)
{
	void *info;
	unsigned char *target=NULL;
	int len;
	int base = 0;
	unsigned char *url = "";
	if (!cmpbeg(param, "-target "))
	{
		unsigned char *p;
		target=param+strlen("-target ");
		for (p=target;*p!=' '&&*p;p++);
		*p=0;
		param=p+1;
	}	
	if (!cmpbeg(param, "-base-session ")) {
		base = atoi(param + strlen("-base-session "));
	} else {
		url = param;
	}
	if ((info = create_session_info(base, url, target, &len))) attach_g_terminal(info, len);
}
#endif

struct {
	int env;
	void (*fn)(struct terminal *term, unsigned char *, unsigned char *);
	unsigned char *text;
	unsigned char *hk;
} oinw[] = {
	{ENV_XWIN, open_in_new_xterm, TEXT_(T_XTERM), TEXT_(T_HK_XTERM)},
	{ENV_TWIN, open_in_new_twterm, TEXT_(T_TWTERM), TEXT_(T_HK_TWTERM)},
	{ENV_SCREEN, open_in_new_screen, TEXT_(T_SCREEN), TEXT_(T_HK_SCREEN)},
#ifdef OS2
	{ENV_OS2VIO, open_in_new_vio, TEXT_(T_WINDOW), TEXT_(T_HK_WINDOW)},
	{ENV_OS2VIO, open_in_new_fullscreen, TEXT_(T_FULL_SCREEN), TEXT_(T_HK_FULL_SCREEN)},
#endif
#ifdef WIN32
	{ENV_WIN32, open_in_new_win32, TEXT_(T_WINDOW), TEXT_(T_HK_WINDOW)},
#endif
#ifdef BEOS
	{ENV_BE, open_in_new_be, TEXT_(T_BEOS_TERMINAL), TEXT_(T_HK_BEOS_TERMINAL)},
#endif
#ifdef G
	{ENV_G, open_in_new_g, TEXT_(T_WINDOW), TEXT_(T_HK_WINDOW)},
#endif
	{0, NULL, NULL, NULL}
};

struct open_in_new *get_open_in_new(int environment)
{
	int i;
	struct open_in_new *oin = DUMMY;
	int noin = 0;
	if (anonymous) return NULL;
	if (environment & ENV_G) environment = ENV_G;
	for (i = 0; oinw[i].env; i++) if ((environment & oinw[i].env) == oinw[i].env) {
		if ((unsigned)noin > MAXINT / sizeof(struct open_in_new) - 2) overalloc();
		oin = mem_realloc(oin, (noin + 2) * sizeof(struct open_in_new));
		oin[noin].text = oinw[i].text;
		oin[noin].hk = oinw[i].hk;
		oin[noin].fn = oinw[i].fn;
		noin++;
		oin[noin].text = NULL;
		oin[noin].hk = NULL;
		oin[noin].fn = NULL;
	}
	if (oin == DUMMY) return NULL;
	return oin;
}

int can_resize_window(int environment)
{
	if (environment & (ENV_OS2VIO | ENV_WIN32)) return 1;
	return 0;
}

int can_open_os_shell(int environment)
{
#ifdef OS2
	if (environment & ENV_XWIN) return 0;
#endif
	return 1;
}

#ifndef OS2
void set_highpri(void)
{
}
#else
void set_highpri(void)
{
	DosSetPriority(PRTYS_PROCESS, PRTYC_FOREGROUNDSERVER, 0, 0);
}
#endif

#ifndef HAVE_SNPRINTF

#define B_SZ	65536

char snprtintf_buffer[B_SZ];

int my_snprintf(char *str, int n, char *f, ...)
{
	int i;
	va_list l;
	if (!n) return -1;
	va_start(l, f);
	vsprintf(snprtintf_buffer, f, l);
	va_end(l);
	i = strlen(snprtintf_buffer);
	if (i >= B_SZ) {
		error("String size too large!");
		va_end(l);
		fatal_tty_exit();
		exit(RET_FATAL);
	}
	if (i >= n) {
		memcpy(str, snprtintf_buffer, n);
		str[n - 1] = 0;
		va_end(l);
		return -1;
	}
	strcpy(str, snprtintf_buffer);
	va_end(l);
	return i;
}

#endif

#ifndef HAVE_MEMMOVE

#define MEMMOVE

typedef	long word;		/* "word" used for optimal copy speed */

#define	wsize	sizeof(word)
#define	wmask	(wsize - 1)

/*
 * Copy a block of memory, handling overlap.
 * This is the routine that actually implements
 * (the portable versions of) bcopy, memcpy, and memmove.
 */
void *
memmove(dst0, src0, length)
	void *dst0;
	const void *src0;
	size_t length;
{
	char *dst = dst0;
	const char *src = src0;
	size_t t;
	unsigned long u;

	if (length == 0 || dst == src)		/* nothing to do */
		goto done;

	/*
	 * Macros: loop-t-times; and loop-t-times, t>0
	 */
#define	TLOOP(s) if (t) TLOOP1(s)
#define	TLOOP1(s) do { s; } while (--t)

	if ((unsigned long)dst < (unsigned long)src) {
		/*
		 * Copy forward.
		 */
		u = (unsigned long)src;	/* only need low bits */
		if ((u | (unsigned long)dst) & wmask) {
			/*
			 * Try to align operands.  This cannot be done
			 * unless the low bits match.
			 */
			if ((u ^ (unsigned long)dst) & wmask || length < wsize)
				t = length;
			else
				t = wsize - (size_t)(u & wmask);
			length -= t;
			TLOOP1(*dst++ = *src++);
		}
		/*
		 * Copy whole words, then mop up any trailing bytes.
		 */
		t = length / wsize;
		TLOOP(*(word *)(void *)dst = *(const word *)(const void *)src; src += wsize; dst += wsize);
		t = length & wmask;
		TLOOP(*dst++ = *src++);
	} else {
		/*
		 * Copy backwards.  Otherwise essentially the same.
		 * Alignment works as before, except that it takes
		 * (t&wmask) bytes to align, not wsize-(t&wmask).
		 */
		src += length;
		dst += length;
		u = (unsigned long)src;
		if ((u | (unsigned long)dst) & wmask) {
			if ((u ^ (unsigned long)dst) & wmask || length <= wsize)
				t = length;
			else
				t = (size_t)(u & wmask);
			length -= t;
			TLOOP1(*--dst = *--src);
		}
		t = length / wsize;
		TLOOP(src -= wsize; dst -= wsize; *(word *)(void *)dst = *(const word *)(const void *)src);
		t = length & wmask;
		TLOOP(*--dst = *--src);
	}
done:
#if defined(MEMCOPY) || defined(MEMMOVE)
	return (dst0);
#else
	return;
#endif
}

#endif

#ifndef HAVE_RAISE

int
raise(s)
        int s;
        {
#ifdef HAVE_GETPID
                return(kill(getpid(), s));
#else
		return 0;
#endif
};

#endif

#ifndef HAVE_STRTOUL

/****yes bad fix***/
unsigned long strtoul(const char *nptr, char **endptr, int base) {
 return (unsigned long)strtol(nptr,endptr,base);
 };

#endif

#ifndef HAVE_STRERROR

char **sys_errlist;
char *strerror(int errnum) { return sys_errlist[errnum];};

#endif

#ifndef HAVE_GETTIMEOFDAY
int gettimeofday(struct timeval *tv, struct timezone *tz)
{
	if (tv) tv->tv_sec = time(NULL), tv->tv_usec = 0;
	if (tz) tz->tz_minuteswest = tz->tz_dsttime = 0;
	return 0;
}
#endif
#ifndef HAVE_STRCSPN
size_t strcspn(const char *s, const char *reject)
{
	size_t r;
	for (r = 0; *s; r++, s++) {
		const char *rj;
		for (rj = reject; *rj; rj++) if (*s == *rj) goto brk;
	}
	brk:
	return r;
}
#endif
#ifndef HAVE_STRSTR
char *strstr(const char *haystack, const char *needle)
{
	size_t hs = strlen(haystack);
	size_t ns = strlen(needle);
	while (hs >= ns) {
		if (!memcmp(haystack, needle, ns)) return haystack;
		haystack++, hs--;
	}
	return NULL;
}
#endif
#ifndef HAVE_TEMPNAM
char *tempnam(const char *dir, const char *pfx)
{
	static int counter = 0;
	unsigned char *d, *s, *a;
	int l;
	if (!(d = getenv("TMPDIR"))) {
		if (dir) d = (unsigned char *)dir;
		else if (!(d = getenv("TMP")) && !(d = getenv("TEMP"))) {
#ifdef P_tmpdir
			d = P_tmpdir;
#else
			d = "/tmp";
#endif
		}
	}
	l = 0;
	s = init_str();
	add_to_str(&s, &l, d);
	if (s[0] && s[strlen(s) - 1] != '/') add_chr_to_str(&s, &l, '/');
	add_to_str(&s, &l, (unsigned char *)pfx);
	add_num_to_str(&s, &l, counter++);
	a = strdup(s);
	mem_free(s);
	return a;
}
#endif
