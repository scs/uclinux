/*
 * Written by Thomas Heller, May 2000
 *
 * $Id$
 */

/*
 * Windows Installer program for distutils.
 *
 * (a kind of self-extracting zip-file)
 *
 * At runtime, the exefile has appended:
 * - compressed setup-data in ini-format, containing the following sections:
 *	[metadata]
 *	author=Greg Ward
 *	author_email=gward@python.net
 *	description=Python Distribution Utilities
 *	licence=Python
 *	name=Distutils
 *	url=http://www.python.org/sigs/distutils-sig/
 *	version=0.9pre
 *
 *	[Setup]
 *	info= text to be displayed in the edit-box
 *	title= to be displayed by this program
 *	target_version = if present, python version required
 *	pyc_compile = if 0, do not compile py to pyc
 *	pyo_compile = if 0, do not compile py to pyo
 *
 * - a struct meta_data_hdr, describing the above
 * - a zip-file, containing the modules to be installed.
 *   for the format see http://www.pkware.com/appnote.html
 *
 * What does this program do?
 * - the setup-data is uncompressed and written to a temporary file.
 * - setup-data is queried with GetPrivateProfile... calls
 * - [metadata] - info is displayed in the dialog box
 * - The registry is searched for installations of python
 * - The user can select the python version to use.
 * - The python-installation directory (sys.prefix) is displayed
 * - When the start-button is pressed, files from the zip-archive
 *   are extracted to the file system. All .py filenames are stored
 *   in a list.
 */

/*
 * To Do:
 *  - install a help-button, which will display the above
 *    text to the user
 *  - should there be a possibility to display a README file
 *    before starting the installation (if one is present in the archive)
 *  - think about uninstaller
 *  - more comments about what the code does(?)
 *
 *  - think about an uninstaller (?)
 *  - evolve this into a full blown installer (???)
 */

#include <windows.h>
#include <commctrl.h>
#include "resource.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#include "archive.h"

/* Bah: global variables */
HWND hwndMain;
HWND hDialog;

char *ini_file;			/* Full pathname of ini-file */
/* From ini-file */
char info[4096];		/* [Setup] info= */
char title[80];			/* [Setup] title= */
char target_version[10];	/* [Setup] target_version= */
char build_info[80];		/* [Setup] build_info= */

char meta_name[80];

char *arc_data;			/* memory mapped archive */
DWORD arc_size;			/* number of bytes in archive */
char install_dir[MAX_PATH];
char pythondll[MAX_PATH];
BOOL pyc_compile, pyo_compile;

BOOL success;			/* Installation successfull? */

#define WM_NUMFILES WM_USER+1
	/* wParam: 0, lParam: total number of files */
#define WM_NEXTFILE WM_USER+2
	/* wParam: number of this file */
	/* lParam: points to pathname */

enum { UNSPECIFIED, ASK, ALWAYS, NEVER } allow_overwrite = UNSPECIFIED;

static void unescape (char *str)
{
    char *dst = str;
    char *src = str;
    char *eon;
    char ch;

    while (src && *src) {
	if (*src == '\\') {
	    switch (*++src) {
	    case 'n':
		*dst++ = '\n';
		*dst++ = '\r';
		break;
	    case 'r':
		*dst++ = '\r';
		break;
	    case '0': case '1': case '2': case '3':
		ch = (char)strtol (src, &eon, 8);
		if (ch == '\n')
		    *dst++ = '\r';
		*dst++ = ch;
		src = eon;
	    }
	} else
	    *dst++ = *src++;
    }
    *dst = '\0';
}

static struct tagFile {
    char *path;
    struct tagFile *next;
} *file_list = NULL;

static void add_to_filelist (char *path)
{
    struct tagFile *p;
    p = (struct tagFile *)malloc (sizeof (struct tagFile));
    p->path = strdup (path);
    p->next = file_list;
    file_list = p;
}

static int do_compile_files (int (__cdecl * PyRun_SimpleString)(char *))
{
    struct tagFile *p;
    int total, n;
    char Buffer[MAX_PATH + 64];
    int errors = 0;

    total = 0;
    p = file_list;
    while (p) {
	++total;
	p = p->next;
    }
    SendDlgItemMessage (hDialog, IDC_PROGRESS, PBM_SETRANGE, 0,
			MAKELPARAM (0, total));
    SendDlgItemMessage (hDialog, IDC_PROGRESS, PBM_SETPOS, 0, 0);

    n = 0;
    p = file_list;
    while (p) {
	++n;
        wsprintf (Buffer,
		  "import py_compile; py_compile.compile (r'%s')",
		  p->path);
        if (PyRun_SimpleString (Buffer))
	    ++errors;
	SendDlgItemMessage (hDialog, IDC_PROGRESS, PBM_SETPOS, n, 0);
	SetDlgItemText (hDialog, IDC_INFO, p->path);
	p = p->next;
    }
    return errors;
}

static int compile_filelist (BOOL optimize_flag)
{
    void (__cdecl * Py_Initialize)(void);
    void (__cdecl * Py_Finalize)(void);
    int (__cdecl * PyRun_SimpleString)(char *);
    int *Py_OptimizeFlag;
    int errors = 0;
    HINSTANCE hPython;
    struct tagFile *p = file_list;

    if (!p)
	return 0;
    SetDlgItemText (hDialog, IDC_INFO, "Loading python...");
		
    hPython = LoadLibrary (pythondll);
    if (!hPython)
	return 1;
    Py_Initialize = (void (*)(void))GetProcAddress
	(hPython,"Py_Initialize");

    Py_Finalize = (void (*)(void))GetProcAddress (hPython,
						  "Py_Finalize");
    PyRun_SimpleString = (int (*)(char *))GetProcAddress (
	hPython, "PyRun_SimpleString");

    Py_OptimizeFlag = (int *)GetProcAddress (hPython,
					     "Py_OptimizeFlag");
    
    *Py_OptimizeFlag = optimize_flag;
    Py_Initialize ();

    errors += do_compile_files (PyRun_SimpleString);
    Py_Finalize ();
    FreeLibrary (hPython);

    return errors;
}

static BOOL SystemError (int error, char *msg)
{
    char Buffer[1024];
    int n;

    if (error) {
        LPVOID lpMsgBuf;
	FormatMessage( 
	    FORMAT_MESSAGE_ALLOCATE_BUFFER | 
	    FORMAT_MESSAGE_FROM_SYSTEM,
	    NULL,
	    error,
	    MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
	    (LPSTR)&lpMsgBuf,
	    0,
	    NULL 
	    );
        strncpy (Buffer, lpMsgBuf, sizeof (Buffer));
	LocalFree (lpMsgBuf);
    } else
	Buffer[0] = '\0';
    n = lstrlen (Buffer);
    _snprintf (Buffer+n, sizeof (Buffer)-n, msg);
    MessageBox (hwndMain, Buffer, "Runtime Error", MB_OK | MB_ICONSTOP);
    return FALSE;
}

static BOOL AskOverwrite (char *filename)
{
    int result;
  again:
    if (allow_overwrite == ALWAYS)
	return TRUE;
    if (allow_overwrite == NEVER)
	return FALSE;
    if (allow_overwrite == ASK)
        return (IDYES == MessageBox (hwndMain,
			    filename,
			    "Overwrite existing file?",
			    MB_YESNO | MB_ICONQUESTION));

    result = MessageBox (hwndMain,
"Overwrite existing files?\n"
"\n"
"Press YES to ALWAYS overwrite existing files,\n"
"press NO to NEVER overwrite existing files,\n"
"press CANCEL to ASK individually.",
		         "Overwrite options",
			 MB_YESNOCANCEL | MB_ICONQUESTION);
    if (result == IDYES)
	allow_overwrite = ALWAYS;
    else if (result == IDNO)
	allow_overwrite = NEVER;
    else
	allow_overwrite = ASK;
    goto again;
}

static BOOL notify (int code, char *fmt, ...)
{
    char Buffer[1024];
    va_list marker;
    BOOL result = TRUE;
    int a, b;
    char *cp;

    va_start (marker, fmt);
    _vsnprintf (Buffer, sizeof (Buffer), fmt, marker);

    switch (code) {
/* Questions */
    case CAN_OVERWRITE:
	result = AskOverwrite (Buffer);
	break;

/* Information notification */
    case DIR_CREATED:
	break;

    case FILE_CREATED:
    case FILE_OVERWRITTEN:
	if ((cp = strrchr(fmt, '.')) && (0 == strcmp (cp, ".py")))
	     add_to_filelist (fmt);
	break;

/* Error Messages */
    case ZLIB_ERROR:
	MessageBox (GetFocus(), Buffer, "Error", MB_OK | MB_ICONWARNING);
	break;

    case SYSTEM_ERROR:
	SystemError (GetLastError(), Buffer);
	break;

    case NUM_FILES:
	a = va_arg (marker, int);
	b = va_arg (marker, int);
	SendMessage (hDialog, WM_NUMFILES, 0, MAKELPARAM (0, a));
	SendMessage (hDialog, WM_NEXTFILE, b, (LPARAM)fmt);
    }
    va_end (marker);
    
    return result;
}

static char *MapExistingFile (char *pathname, DWORD *psize)
{
    HANDLE hFile, hFileMapping;
    DWORD nSizeLow, nSizeHigh;
    char *data;

    hFile = CreateFile (pathname,
	GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
	FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
	return NULL;
    nSizeLow = GetFileSize (hFile, &nSizeHigh);
    hFileMapping = CreateFileMapping (hFile,
	NULL, PAGE_READONLY, 0, 0, NULL);
    CloseHandle (hFile);

    if (hFileMapping == INVALID_HANDLE_VALUE)
	return NULL;
    
    data = MapViewOfFile (hFileMapping,
	FILE_MAP_READ, 0, 0, 0);

    CloseHandle (hFileMapping);
    *psize = nSizeLow;
    return data;
}

static char *ExtractIniFile (char *data, DWORD size)
{
    /* read the end of central directory record */
    struct eof_cdir *pe = (struct eof_cdir *)&data[size - sizeof
						  (struct eof_cdir)];
    
    int arc_start = size - sizeof (struct eof_cdir) - pe->nBytesCDir -
	pe->ofsCDir;

    int ofs = arc_start - sizeof (struct meta_data_hdr);

    /* read meta_data info */
    struct meta_data_hdr *pmd = (struct meta_data_hdr *)&data[ofs];
    char *src, *dst;
    char *ini_file;
    char tempdir[MAX_PATH];

    if (pe->tag != 0x06054b50) {
	SystemError (0, "Setup program invalid or damaged");
	return NULL;
    }

    if (pmd->tag != 0x12345679 || ofs < 0) {
	SystemError (0, "Setup program invalid or damaged");
	return NULL;
    }

    src = ((char *)pmd) - pmd->uncomp_size;
    ini_file = malloc (MAX_PATH); /* will be returned, so do not free it */
    if (!ini_file)
	return NULL;
    if (!GetTempPath (sizeof (tempdir), tempdir)
	|| !GetTempFileName (tempdir, "~du", 0, ini_file)) {
	SystemError (GetLastError(), "Could not create temporary file");
	return NULL;
    }
    
    dst = map_new_file (CREATE_ALWAYS, ini_file, NULL, pmd->uncomp_size,
			0, 0, notify);
    if (!dst)
	return NULL;
    memcpy (dst, src, pmd->uncomp_size);
    UnmapViewOfFile(dst);
    return ini_file;
}

static void PumpMessages (void)
{
    MSG msg;
    while (PeekMessage (&msg, NULL, 0, 0, PM_REMOVE)) {
        TranslateMessage (&msg);
        DispatchMessage (&msg);
    }
}

LRESULT CALLBACK
WindowProc (HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    HDC hdc;
    HFONT hFont;
    int h;
    PAINTSTRUCT ps;
    switch (msg) {
    case WM_PAINT:
	hdc = BeginPaint (hwnd, &ps);
	h = GetSystemMetrics (SM_CYSCREEN) / 10;
	hFont = CreateFont (h, 0, 0, 0, 700, TRUE,
			    0, 0, 0, 0, 0, 0, 0, "Times Roman");
	hFont = SelectObject (hdc, hFont);
	SetBkMode (hdc, TRANSPARENT);
	TextOut (hdc, 15, 15, title, strlen (title));
	SetTextColor (hdc, RGB (255, 255, 255));
	TextOut (hdc, 10, 10, title, strlen (title));
	DeleteObject (SelectObject (hdc, hFont));
	EndPaint (hwnd, &ps);
	return 0;
    }
    return DefWindowProc (hwnd, msg, wParam, lParam);
}

static HWND CreateBackground (char *title)
{
    WNDCLASS wc;
    HWND hwnd;
    char buffer[4096];

    wc.style = CS_VREDRAW | CS_HREDRAW;
    wc.lpfnWndProc = WindowProc;
    wc.cbWndExtra = 0;
    wc.cbClsExtra = 0;
    wc.hInstance = GetModuleHandle (NULL);
    wc.hIcon = NULL;
    wc.hCursor = LoadCursor (NULL, IDC_ARROW);
    wc.hbrBackground = CreateSolidBrush (RGB (0, 0, 128));
    wc.lpszMenuName = NULL;
    wc.lpszClassName = "SetupWindowClass";

    if (!RegisterClass (&wc))
	MessageBox (hwndMain,
		    "Could not register window class",
		    "Setup.exe", MB_OK);

    wsprintf (buffer, "Setup %s", title);
    hwnd = CreateWindow ("SetupWindowClass",
			 buffer,
			 0,
			 0, 0,
			 GetSystemMetrics (SM_CXFULLSCREEN),
			 GetSystemMetrics (SM_CYFULLSCREEN),
			 NULL,
			 NULL,
			 GetModuleHandle (NULL),
			 NULL);
    ShowWindow (hwnd, SW_SHOWMAXIMIZED);
    UpdateWindow (hwnd);
    return hwnd;
}

/*
 * Center a window on the screen
 */
static void CenterWindow (HWND hwnd)
{
	RECT rc;
	int w, h;

	GetWindowRect (hwnd, &rc);
	w = GetSystemMetrics (SM_CXSCREEN);
	h = GetSystemMetrics (SM_CYSCREEN);
	MoveWindow (hwnd, (w - (rc.right-rc.left))/2, (h - (rc.bottom-rc.top))/2,
		rc.right-rc.left, rc.bottom-rc.top, FALSE);
}

#include <prsht.h>

BOOL CALLBACK
IntroDlgProc (HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    LPNMHDR lpnm;
    char Buffer[4096];
    switch (msg) {
    case WM_INITDIALOG:
	CenterWindow (GetParent (hwnd));
	wsprintf (Buffer,
		  "This Wizard will install %s on your computer. "
		  "Click Next to continue or Cancel to exit the Setup Wizard.",
		  meta_name);
	SetDlgItemText (hwnd, IDC_TITLE, Buffer);
	SetDlgItemText (hwnd, IDC_INTRO_TEXT, info);
	SetDlgItemText (hwnd, IDC_BUILD_INFO, build_info);
	return FALSE;

    case WM_NOTIFY:
        lpnm = (LPNMHDR) lParam;

        switch (lpnm->code) {
	case PSN_SETACTIVE:
	    PropSheet_SetWizButtons(GetParent(hwnd), PSWIZB_NEXT);
	    break;

	case PSN_WIZNEXT:
	    break;

	case PSN_RESET:
	    break;
		
	default:
	    break;
	}
    }
    return FALSE;
}

/*
 * Fill the listbox specified by hwnd with all python versions found
 * in the registry. version, if not NULL or empty, is the version
 * required.
 */
static BOOL GetPythonVersions (HWND hwnd, HKEY hkRoot, LPSTR version)
{
    DWORD index = 0;
    char core_version[80];
    HKEY hKey;
    BOOL result = TRUE;
    DWORD bufsize;

    if (ERROR_SUCCESS != RegOpenKeyEx (hkRoot,
				     "Software\\Python\\PythonCore",
				     0,	KEY_READ, &hKey))
	return FALSE;
    bufsize = sizeof (core_version);
    while (ERROR_SUCCESS == RegEnumKeyEx (hKey, index,
					  core_version, &bufsize, NULL,
					  NULL, NULL, NULL)) {
	char subkey_name[80], vers_name[80], prefix_buf[MAX_PATH+1];
	int itemindex;
	DWORD value_size;
	HKEY hk;

	bufsize = sizeof (core_version);
	++index;
	if (version && *version && strcmp (version, core_version))
		continue;

	wsprintf (vers_name, "Python Version %s (found in registry)",
		  core_version);
	itemindex = SendMessage (hwnd, LB_ADDSTRING, 0,
				 (LPARAM)(LPSTR)vers_name);
	wsprintf (subkey_name,
		  "Software\\Python\\PythonCore\\%s\\InstallPath",
		  core_version);
	value_size = sizeof (subkey_name);
	RegOpenKeyEx (hkRoot, subkey_name, 0, KEY_READ, &hk);
	RegQueryValueEx (hk, NULL, NULL, NULL, prefix_buf,
			 &value_size);
	RegCloseKey (hk);
	SendMessage (hwnd, LB_SETITEMDATA, itemindex,
		     (LPARAM)(LPSTR)strdup (prefix_buf));
    }
    RegCloseKey (hKey);
    return result;
}

BOOL CALLBACK
SelectPythonDlgProc (HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    LPNMHDR lpnm;

    switch (msg) {
    case WM_INITDIALOG:
	GetPythonVersions (GetDlgItem (hwnd, IDC_VERSIONS_LIST),
			   HKEY_LOCAL_MACHINE, target_version);
	GetPythonVersions (GetDlgItem (hwnd, IDC_VERSIONS_LIST),
			   HKEY_CURRENT_USER, target_version);
	{	/* select the last entry which is the highest python
		   version found */
	    int count;
	    count = SendDlgItemMessage (hwnd, IDC_VERSIONS_LIST,
					LB_GETCOUNT, 0, 0);
	    if (count && count != LB_ERR)
		SendDlgItemMessage (hwnd, IDC_VERSIONS_LIST, LB_SETCURSEL,
				    count-1, 0);
	}
	goto UpdateInstallDir;
	break;

    case WM_COMMAND:
	switch (LOWORD (wParam)) {
	case IDC_VERSIONS_LIST:
	    switch (HIWORD (wParam)) {
		int id;
		char *cp;
	    case LBN_SELCHANGE:
	      UpdateInstallDir:
		PropSheet_SetWizButtons(GetParent(hwnd),
					PSWIZB_BACK | PSWIZB_NEXT);
		id = SendDlgItemMessage (hwnd, IDC_VERSIONS_LIST,
					 LB_GETCURSEL, 0, 0);
		if (id == LB_ERR) {
		    PropSheet_SetWizButtons(GetParent(hwnd),
					    PSWIZB_BACK);
		    SetDlgItemText (hwnd, IDC_PATH, "");
		    strcpy (install_dir, "");
		    strcpy (pythondll, "");
		} else {
		    char *pbuf;
		    int result;
		    PropSheet_SetWizButtons(GetParent(hwnd),
					    PSWIZB_BACK | PSWIZB_NEXT);
		    cp = (LPSTR)SendDlgItemMessage (hwnd,
						    IDC_VERSIONS_LIST,
						    LB_GETITEMDATA,
						    id,
						    0);
		    strcpy (install_dir, cp);
		    SetDlgItemText (hwnd, IDC_PATH, install_dir);
		    result = SendDlgItemMessage (hwnd, IDC_VERSIONS_LIST,
					LB_GETTEXTLEN, (WPARAM)id, 0);
		    pbuf = (char *)malloc (result + 1);
		    if (pbuf) {
			/* guess the name of the python-dll */
			int major, minor;
			SendDlgItemMessage (hwnd, IDC_VERSIONS_LIST,
					    LB_GETTEXT, (WPARAM)id,
					    (LPARAM)pbuf);
			result = sscanf (pbuf, "Python Version %d.%d",
					 &major, &minor);
			if (result == 2)
			    wsprintf (pythondll, "python%d%d.dll",
				      major, minor);
			free (pbuf);
		    } else
			strcpy (pythondll, "");
		}
	    }
	    break;
	}
	return 0;

    case WM_NOTIFY:
        lpnm = (LPNMHDR) lParam;

        switch (lpnm->code) {
	    int id;
	case PSN_SETACTIVE:
	    id = SendDlgItemMessage (hwnd, IDC_VERSIONS_LIST,
				     LB_GETCURSEL, 0, 0);
	    if (id == LB_ERR)
		PropSheet_SetWizButtons(GetParent(hwnd),
					PSWIZB_BACK);
	    else
		PropSheet_SetWizButtons(GetParent(hwnd),
					PSWIZB_BACK | PSWIZB_NEXT);
	    break;

	case PSN_WIZNEXT:
	    break;

	case PSN_WIZFINISH:
	    break;

	case PSN_RESET:
	    break;
		
	default:
	    break;
	}
    }
    return 0;
}

BOOL CALLBACK
InstallFilesDlgProc (HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    LPNMHDR lpnm;
    char Buffer[4096];

    switch (msg) {
    case WM_INITDIALOG:
	wsprintf (Buffer,
		  "Click Next to begin the installation of %s. "
		  "If you want to review or change any of your "
		  " installation settings, click Back. "
		  "Click Cancel to exit the wizard.",
		  meta_name);
	SetDlgItemText (hwnd, IDC_TITLE, Buffer);
	break;

    case WM_NUMFILES:
	SendDlgItemMessage (hwnd, IDC_PROGRESS, PBM_SETRANGE, 0, lParam);
	PumpMessages ();
	return TRUE;

    case WM_NEXTFILE:
	SendDlgItemMessage (hwnd, IDC_PROGRESS, PBM_SETPOS, wParam,
			    0);
	SetDlgItemText (hwnd, IDC_INFO, (LPSTR)lParam);
	PumpMessages ();
	return TRUE;

    case WM_NOTIFY:
        lpnm = (LPNMHDR) lParam;

        switch (lpnm->code) {
	case PSN_SETACTIVE:
	    PropSheet_SetWizButtons(GetParent(hwnd),
				    PSWIZB_BACK | PSWIZB_NEXT);

	    break;

	case PSN_WIZFINISH:
	    break;

	case PSN_WIZNEXT:
	    /* Handle a Next button click here */
	    hDialog = hwnd;

	    /* Make sure the installation directory name ends in a */
	    /* backslash */
	    if (install_dir[strlen(install_dir)-1] != '\\')
		strcat (install_dir, "\\");
	    /* Strip the trailing backslash again */
	    install_dir[strlen(install_dir)-1] = '\0';
	    

	    /* Extract all files from the archive */
	    SetDlgItemText (hwnd, IDC_TITLE, "Installing files...");
	    success = unzip_archive (install_dir, arc_data,
				    arc_size, notify);
	    /* Compile the py-files */
	    if (pyc_compile) {
		SetDlgItemText (hwnd, IDC_TITLE,
				"Compiling files to .pyc...");
		compile_filelist (FALSE);
	    }
	    if (pyo_compile) {
		SetDlgItemText (hwnd, IDC_TITLE,
				"Compiling files to .pyo...");
		compile_filelist (TRUE);
	    }
	    break;

	case PSN_RESET:
	    break;
		
	default:
	    break;
	}
    }
    return 0;
}


BOOL CALLBACK
FinishedDlgProc (HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    LPNMHDR lpnm;

    switch (msg) {
    case WM_INITDIALOG:
	if (!success)
	    SetDlgItemText (hwnd, IDC_INFO, "Installation failed.");
	break;

    case WM_NOTIFY:
        lpnm = (LPNMHDR) lParam;

        switch (lpnm->code) {
	case PSN_SETACTIVE: /* Enable the Finish button */
	    PropSheet_SetWizButtons(GetParent(hwnd), PSWIZB_FINISH);
	    break;

	case PSN_WIZNEXT:
	    break;

	case PSN_WIZFINISH:
	    break;

	case PSN_RESET:
	    break;
		
	default:
	    break;
	}
    }
    return 0;
}

void RunWizard (HWND hwnd)
{
    PROPSHEETPAGE   psp =       {0};
    HPROPSHEETPAGE  ahpsp[4] =  {0};
    PROPSHEETHEADER psh =       {0};

    /* Display module information */
    psp.dwSize =        sizeof(psp);
    psp.dwFlags =       PSP_DEFAULT|PSP_HIDEHEADER;
    psp.hInstance =     GetModuleHandle (NULL);
    psp.lParam =        0;
    psp.pfnDlgProc =    IntroDlgProc;
    psp.pszTemplate =   MAKEINTRESOURCE(IDD_INTRO);

    ahpsp[0] =          CreatePropertySheetPage(&psp);

    /* Select python version to use */
    psp.dwFlags =       PSP_DEFAULT|PSP_HIDEHEADER;
    psp.pszTemplate =       MAKEINTRESOURCE(IDD_SELECTPYTHON);
    psp.pfnDlgProc =        SelectPythonDlgProc;

    ahpsp[1] =              CreatePropertySheetPage(&psp);

    /* Install the files */
    psp.dwFlags =	    PSP_DEFAULT|PSP_HIDEHEADER;
    psp.pszTemplate =       MAKEINTRESOURCE(IDD_INSTALLFILES);
    psp.pfnDlgProc =        InstallFilesDlgProc;

    ahpsp[2] =              CreatePropertySheetPage(&psp);

    /* Show success or failure */
    psp.dwFlags =           PSP_DEFAULT|PSP_HIDEHEADER;
    psp.pszTemplate =       MAKEINTRESOURCE(IDD_FINISHED);
    psp.pfnDlgProc =        FinishedDlgProc;

    ahpsp[3] =              CreatePropertySheetPage(&psp);

    /* Create the property sheet */
    psh.dwSize =            sizeof(psh);
    psh.hInstance =         GetModuleHandle (NULL);
    psh.hwndParent =        hwnd;
    psh.phpage =            ahpsp;
    psh.dwFlags =           PSH_WIZARD/*97*//*|PSH_WATERMARK|PSH_HEADER*/;
    psh.pszbmWatermark =    NULL;
    psh.pszbmHeader =       NULL;
    psh.nStartPage =        0;
    psh.nPages =            4;

    PropertySheet(&psh);
}

int WINAPI WinMain (HINSTANCE hInst, HINSTANCE hPrevInst,
		    LPSTR lpszCmdLine, INT nCmdShow)
{
    char modulename[MAX_PATH];

    GetModuleFileName (NULL, modulename, sizeof (modulename));

    /* Map the executable file to memory */
    arc_data = MapExistingFile (modulename, &arc_size);
    if (!arc_data) {
	SystemError (GetLastError(), "Could not open archive");
	return 1;
    }

    /* Extract the configuration data into a temporary file */
    ini_file = ExtractIniFile (arc_data, arc_size);
    if (!ini_file) {
	return 1;
    }

    /* Read installation information */
    GetPrivateProfileString ("Setup", "title", "", title,
			     sizeof (title), ini_file);
    unescape (title);

    GetPrivateProfileString ("Setup", "info", "", info,
			     sizeof (info), ini_file);
    unescape (info);

    GetPrivateProfileString ("Setup", "build_info", "", build_info,
			     sizeof (build_info), ini_file);

    pyc_compile = GetPrivateProfileInt ("Setup", "target_compile", 1,
					ini_file);
    pyo_compile = GetPrivateProfileInt ("Setup", "target_optimize", 1,
					ini_file);

    GetPrivateProfileString ("Setup", "target_version", "",
			     target_version, sizeof (target_version),
			     ini_file);

    GetPrivateProfileString ("metadata", "name", "",
			     meta_name, sizeof (meta_name),
			     ini_file);

    hwndMain = CreateBackground (title);

    RunWizard (hwndMain);

    /* Clean up */
    UnmapViewOfFile (arc_data);
    if (ini_file)
	DeleteFile (ini_file);

    return 0;
}
