/*****************************************************************************
 * VLC Plugin description for OS X
 *****************************************************************************/

/* Definitions of system resource types */

data 'carb' (0)
{
};

/* The first string in the array is a plugin description,
 * the second is the plugin name */
resource 'STR#' (126)
{
    {
        "Version 0.8.6, copyright 1996-2006 The VideoLAN Team"
        "<BR><A HREF='http://www.videolan.org'>http://www.videolan.org</A>",
        "VLC Multimedia Plugin"
    };
};

/* A description for each MIME type in resource 128 */
resource 'STR#' (127)
{
    {
        /* OGG */
        "Ogg stream",
        "Ogg stream",
        /* VLC */
        "VLC plugin",
        /* Google VLC */
        "Google VLC plugin",
    };
};

/* A series of pairs of strings... first MIME type, then file extension(s) */
resource 'STR#' (128,"MIME Type")
{
    {
        /* OGG */
        "application/ogg", "ogg",
        "application/x-ogg", "ogg",
        /* VLC */
        "application/x-vlc-plugin", "vlc",
        /* Google VLC */
        "video/x-google-vlc-plugin", "",
    };
};

