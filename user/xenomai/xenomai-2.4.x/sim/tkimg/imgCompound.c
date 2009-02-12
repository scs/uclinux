/* 
 * compound_image.c
 *
 *	This procedure implements images of type "compoundimage".
 *
 *      It's somewhat inspired by Tix's compound image type, but it's
 *      different in several ways---both less general in what it can
 *      contain, and more general (in that a single image can be used
 *      in many widgets).
 *
 * $Id: imgCompound.c,v 1.1.1.1 2004/06/06 14:20:34 rpm Exp $
 *
 * */

#include <tk.h>
#include <string.h>

typedef enum {ITEM_TEXT, ITEM_IMAGE} ItemType;

#define MASTER_FIELDS ItemType type;\
                      struct VirtualItem_t *next;\
                      int width;\
                      int height

typedef struct VirtualItem_t
{
    MASTER_FIELDS;
} VirtualItem;

typedef struct
{
    MASTER_FIELDS;
    char *text;
    Tk_Anchor anchor;
    Tk_Justify justify;
    Tk_Font tkfont;
    Tk_TextLayout layout;
    XColor *colour;
    Pixmap stipple;
    int x, y;
    int wrapLength;
} MasterText;

typedef struct
{
    MASTER_FIELDS;
    char *image;
    Tk_Anchor anchor;
} MasterImage;

#define INSTANCE_FIELDS ItemType type;\
                        VirtualItem *next

typedef struct 
{
    INSTANCE_FIELDS;
    GC gc;
} InstanceText;

typedef struct
{
    INSTANCE_FIELDS;
    Tk_Image image;
} InstanceImage;


/*
 * The following data structure represents the master for a compound
 * image:
 */
struct CompoundInstance_t;
typedef struct
{
    Tcl_Interp *interp;
    Tk_ImageMaster master;
    Tk_Window randomWin;
    Display *display;
    Tcl_Obj *desc;
    VirtualItem *contents;
    struct CompoundInstance_t *instancePtr;
    int width;
    int height;
    int changing;
} CompoundMaster;

/* Type for an instance of a compound image */
typedef struct CompoundInstance_t
{
    CompoundMaster *master;
    VirtualItem *contents;
    Tk_Window tkwin;
    struct CompoundInstance_t *next;
    int refCount;
} CompoundInstance;

static Tk_ConfigSpec textOptionSpecs[] = {
    {TK_CONFIG_ANCHOR, "-anchor", (char*)NULL, (char*)NULL,
     "center", Tk_Offset(MasterText, anchor), TK_CONFIG_DONT_SET_DEFAULT},
    {TK_CONFIG_COLOR, "-fill", (char*)NULL, (char*)NULL,
     "black", Tk_Offset(MasterText, colour), TK_CONFIG_NULL_OK},
    {TK_CONFIG_FONT, "-font", (char*)NULL, (char*)NULL,
     "Helvetica -12", Tk_Offset(MasterText, tkfont), 0},
    {TK_CONFIG_JUSTIFY, "-justify", (char *) NULL, (char *) NULL,
	"left", Tk_Offset(MasterText, justify), TK_CONFIG_DONT_SET_DEFAULT},
    {TK_CONFIG_BITMAP, "-bgstipple", (char *) NULL, (char *) NULL,
	(char *) NULL, Tk_Offset(MasterText, stipple), TK_CONFIG_NULL_OK},
    {TK_CONFIG_STRING, "-text", (char *) NULL, (char *) NULL,
	"", Tk_Offset(MasterText, text), 0},
    {TK_CONFIG_PIXELS, "-width", (char *) NULL, (char *) NULL,
	"0", Tk_Offset(MasterText, wrapLength), 0},
    {TK_CONFIG_END, (char *) NULL, (char *) NULL, (char *) NULL,
	(char *) NULL, 0, 0}
};

static Tk_ConfigSpec imageOptionSpecs[] = {
    {TK_CONFIG_ANCHOR, "-anchor", (char*)NULL, (char*)NULL,
     "center", Tk_Offset(MasterImage, anchor), TK_CONFIG_DONT_SET_DEFAULT},
    {TK_CONFIG_STRING, "-image", (char*)NULL, (char*)NULL,
     (char*)NULL, Tk_Offset(MasterImage, image), TK_CONFIG_NULL_OK},
    {TK_CONFIG_END, (char *) NULL, (char *) NULL, (char *) NULL,
	(char *) NULL, 0, 0}
};

    
static Tk_ImageCreateProc ImgCmpCreate;
static Tk_ImageGetProc ImgCmpGet;
static Tk_ImageDisplayProc ImgCmpDisplay;
static Tk_ImageFreeProc ImgCmpFree;
static Tk_ImageDeleteProc ImgCmpDelete;
static void RedisplayImagesWhenIdle(CompoundMaster*);
static void RedisplayImages(ClientData);
static void ImageHasChanged(ClientData, int, int, int, int, int, int);

static void DeleteInstance(Tcl_Interp *, VirtualItem*);
static void DeleteMaster(Tcl_Interp *, CompoundMaster*);
static int ReconfigureMaster(CompoundMaster*, char *);
static int ReconfigureInstance(Tk_Window tkwin, CompoundMaster*, CompoundInstance*);
static void DeleteInstanceStuff(ClientData instanceData);
static Tcl_CmdProc CompoundImageCmd;

Tk_ImageType imgCompoundImageType = {
    "compoundimg",		/* name */
    ImgCmpCreate,		/* createProc */
    ImgCmpGet,			/* getProc */
    ImgCmpDisplay,		/* displayProc */
    ImgCmpFree,			/* freeProc */
    ImgCmpDelete,		/* deleteProc */
};

static int
ImgCmpCreate(Tcl_Interp *interp, 
	     char *name,
	     int argc, char **argv,
	     Tk_ImageType *typePtr,
	     Tk_ImageMaster master,
	     ClientData *masterDataPtr)
{
    CompoundMaster *m = (CompoundMaster*)Tcl_Alloc(sizeof(CompoundMaster));
    int ok;
    if (m==NULL) {
	return TCL_ERROR;
    }
    
    m->interp = interp;
    m->master = master;
    m->randomWin = Tk_MainWindow(interp);
    m->display = Tk_Display(m->randomWin);
    m->changing = 0;
    m->contents = 0;
    m->instancePtr = 0;
    m->desc = 0;
    m->width = m->height = 0;
    *masterDataPtr = (ClientData)m;

    /* Mvmple processing of arguments */
    if (argc==2 && !strcmp(argv[0], "-contents")) {
	ok = ReconfigureMaster(m, argv[1]);
    } else {
	if (argc!=0) {
	    Tcl_SetResult(interp, "expecting -contents {...}", TCL_STATIC);
	    return TCL_ERROR;
	}
	ok = TCL_OK;
    }
    
    Tcl_CreateCommand(interp, name, CompoundImageCmd, (ClientData)m,
		      (Tcl_CmdDeleteProc*)0);
    
    return ok;
}

int
CompoundImageCmd(ClientData clientData, Tcl_Interp *interp,
		 int argc, char *argv[])
{
    CompoundMaster *m = (CompoundMaster*)clientData;
    if (argc==1) {
	Tcl_SetResult(interp, m->desc ? Tcl_GetStringFromObj(m->desc,(int*)0):"",
		      TCL_STATIC);
	return TCL_OK;
    }
    if (argc==2) {
	int ok = ReconfigureMaster(m, argv[1]);
	CompoundInstance *im;
	for (im = m->instancePtr; im; im = im->next) {
	    ReconfigureInstance(im->tkwin, m, im);
	}
	
	RedisplayImagesWhenIdle(m);
	return ok;
    }
    Tcl_SetResult(interp, "wrong # args", TCL_STATIC);
    return TCL_ERROR;
}

static int
ReconfigureMaster(CompoundMaster *m, char *strDesc)
{
    Tcl_Obj *desc = Tcl_NewStringObj(strDesc, -1);
    int list_len;
    int i;
    VirtualItem **next = &m->contents;

    Tcl_IncrRefCount(desc);
    
    DeleteMaster(m->interp, m);
    if (m->desc) {
	Tcl_DecrRefCount(m->desc);
    }
#ifdef DEBUG
    printf("Reconfiguring master: %s\n", strDesc);
#endif
    m->desc = 0;
    m->contents = 0;
    
    m->width = m->height = 0;
    
    /* Convert to list, and find length */
    if (Tcl_ListObjLength(m->interp, desc, &list_len)!=TCL_OK) {
	goto error;
    }
    
    for (i=0; i<list_len; i++) {
	Tcl_Obj *itemDesc;
	int item_len;
	char *type;
	Tcl_Obj *objPtr;
	VirtualItem *vi;
	
	if (Tcl_ListObjIndex(m->interp, desc, i, &itemDesc)!=TCL_OK) {
	    goto error;
	}
	if (Tcl_ListObjLength(m->interp, itemDesc, &item_len)!=TCL_OK) {
	    goto error;
	}
	if (item_len==0) {
	    /* Ignore empty lists for the time being */
	    continue;
	}

	/* Get first object.  This can't fail */
	Tcl_ListObjIndex(m->interp, itemDesc, 0, &objPtr);
	type = Tcl_GetStringFromObj(objPtr, NULL);
	if (!strcmp(type, "text")) {
	    MasterText *t = (MasterText*)Tcl_Alloc(sizeof(MasterText));
	    char *strlist = Tcl_GetStringFromObj(itemDesc, NULL);
	    int list_argc;
	    char **list_argv;
	    
	    if (!t) {
		goto error;
	    }
	    t->type = ITEM_TEXT;
	    (void)Tcl_SplitList(m->interp, strlist, &list_argc, &list_argv);
	    
	    t->anchor = TK_ANCHOR_CENTER;
	    t->colour = NULL;
	    t->tkfont = NULL;
	    t->justify = TK_JUSTIFY_LEFT;
	    t->text = NULL;
	    t->stipple = None;
	    t->wrapLength = 0;
	    
	    if (Tk_ConfigureWidget(m->interp, m->randomWin, textOptionSpecs,
				   list_argc-1, &list_argv[1], (char*)t, 0)==TCL_ERROR) {
		goto error;
	    }
	    
	    Tcl_Free((char*)list_argv);

	    t->layout = Tk_ComputeTextLayout(t->tkfont, 
					     t->text,
					     -1, t->wrapLength, 
					     t->justify,
					     0, &t->width, &t->height);
	    
	    m->height = t->height > m->height ? t->height : m->height;
	    t->x = 0;
	    if (t->wrapLength > t->width) {
		switch (t->anchor) {
		case TK_ANCHOR_CENTER:
		case TK_ANCHOR_N:
		case TK_ANCHOR_S:
		    t->x = (t->wrapLength-t->width+0.5)/2;
		    break;
		case TK_ANCHOR_E:
		case TK_ANCHOR_NE:
		case TK_ANCHOR_SE:
		    t->x = t->wrapLength-t->width;
		}
	    }
	    if (t->wrapLength>0) {
		t->width = t->wrapLength;
	    }

	    m->width += t->width;
	    vi = (VirtualItem*)t;
	} else if (!strcmp(type, "image") && item_len!=1) {
	    MasterImage *im = (MasterImage*)Tcl_Alloc(sizeof(MasterImage));
	    Tk_Image image;
	    char *strlist = Tcl_GetStringFromObj(itemDesc, NULL);
	    int list_argc;
	    char **list_argv;
	    
	    if (!im) {
		goto error;
	    }
	    im->type = ITEM_IMAGE;
	    (void)Tcl_SplitList(m->interp, strlist, &list_argc, &list_argv);
	    
	    im->anchor = TK_ANCHOR_CENTER;
	    im->image = NULL;
	    
	    if (Tk_ConfigureWidget(m->interp, m->randomWin, imageOptionSpecs,
				   list_argc-1, &list_argv[1], (char*)im, 0)==TCL_ERROR) {
		goto error;
	    }
	    
	    Tcl_Free((char*)list_argv);
	    
	    image = Tk_GetImage(m->interp, m->randomWin, 
				im->image,
				ImageHasChanged,
				(ClientData)m);
	    if (!image) {
		goto error;
	    }
	    Tk_SizeOfImage(image, &im->width, &im->height);
	    m->width += im->width;
	    m->height = im->height>m->height?im->height:m->height;
	    Tk_FreeImage(image);
	    vi = (VirtualItem*)im;
	} else {
	    Tcl_SetResult(m->interp, "something unexpected encountered",
			  TCL_STATIC);
	    goto error;
	}
	*next = vi;
	next = &(vi->next);
	*next = 0;
    }
    m->desc = desc;
    return TCL_OK;
    
 error:
    DeleteMaster(m->interp, m);
    Tcl_DecrRefCount(desc);
    m->contents = 0;
    return TCL_ERROR;
}

static ClientData
ImgCmpGet(Tk_Window tkwin, ClientData masterData)
{
    CompoundMaster *m = (CompoundMaster*)masterData;
    CompoundInstance *im;
    
    im = m->instancePtr;
    while (im) {
	if (im->tkwin == tkwin) {
	    im->refCount++;
	    return (ClientData)im;
	}
	im = im->next;
    }
    
    im = (CompoundInstance*)Tcl_Alloc(sizeof(CompoundInstance));
    
    if (!im) {
	Tcl_SetResult(m->interp, "Alloc failed in ImgCmpGet", TCL_STATIC);
	Tcl_BackgroundError(m->interp);
	return 0;
    }
	    
    im->master = m;
    im->tkwin = tkwin;
    im->contents = 0;
    im->refCount = 0;
    im->next = m->instancePtr;
    m->instancePtr = im;
    
    if (ReconfigureInstance(tkwin, m, im)!=TCL_OK) {
	Tcl_SetResult(m->interp, "error in ImgCmpGet", TCL_STATIC);
	Tcl_BackgroundError(m->interp);
	return 0;
    }
    RedisplayImages(m);
    
    return (ClientData)im;
}

static int
ReconfigureInstance(Tk_Window tkwin, CompoundMaster *m, CompoundInstance *im)
{
    VirtualItem **nextInstance = &im->contents;
    VirtualItem *nextMaster = m->contents;
    
    DeleteInstance(m->interp, im->contents);
#ifdef DEBUG
    printf("Reconfiguring instance: %s\n", Tk_Name(tkwin));
#endif
    
    im->contents = 0;
    while (nextMaster) {
	VirtualItem *i = nextMaster;
	VirtualItem *vi = 0;
	XGCValues gcValues;
	switch (i->type) {
	case ITEM_TEXT:
	    {
		InstanceText *t = (InstanceText*)Tcl_Alloc(sizeof(InstanceText));
		int mask = GCForeground|GCFont;
		t->next = 0;
		vi = (VirtualItem*)t;
		if (!vi) {
		    return TCL_ERROR;
		}
		t->type = ITEM_TEXT;
		gcValues.foreground = ((MasterText*)i)->colour->pixel;
		gcValues.font = Tk_FontId(((MasterText*)i)->tkfont);
		if (((MasterText*)i)->stipple != None) {
		    gcValues.stipple = ((MasterText*)i)->stipple;
		    gcValues.fill_style = FillStippled;
		    mask |= GCStipple|GCFillStyle;
		}
		
		t->gc = 
		    Tk_GetGC(m->randomWin, mask, &gcValues);
	    }
	    break;

	case ITEM_IMAGE:
	    {
		InstanceImage *ii = (InstanceImage*)Tcl_Alloc(sizeof(InstanceImage));
		ii->next = 0;
		vi = (VirtualItem*)ii;
		
		if (!vi) {
		    return TCL_ERROR;
		}
		ii->type = ITEM_IMAGE;
		ii->image =
		    Tk_GetImage(m->interp, tkwin, 
				((MasterImage*)i)->image,
				ImageHasChanged,
				(ClientData)m);
	    }
	    break;
	default:
	    Tcl_SetResult(m->interp, "unknown type", TCL_STATIC);
	    return TCL_ERROR;
	}
	*nextInstance = vi;
	nextInstance = &vi->next;
	nextMaster = nextMaster->next;
    }
    
    return TCL_OK;
}

static void
ImgCmpDisplay(ClientData instanceData,
	      Display *display,
	      Drawable drawable,
	      int imageX,
	      int imageY,
	      int width,
	      int height,
	      int drawableX,
	      int drawableY)
{
    CompoundInstance *im = (CompoundInstance*)instanceData;
    CompoundMaster *m = im->master;
    int x = drawableX;
    int y = drawableY;
    VirtualItem *mi = m->contents;
    VirtualItem *ii = im->contents;
    while (mi) {
	switch (mi->type) {
	case ITEM_TEXT:
	    {
		MasterText *mti = (MasterText*)mi;
		mti->y = 0;
		if (m->height > mti->height) {
		    switch (mti->anchor) {
		    case TK_ANCHOR_CENTER:
		    case TK_ANCHOR_W:
		    case TK_ANCHOR_E:
			mti->y = (m->height-mti->height+0.5)/2;
			break;
		    case TK_ANCHOR_SW:
		    case TK_ANCHOR_S:
		    case TK_ANCHOR_SE:
			mti->y = m->height-mti->height;
		    }
		}
	    }
	    
	    Tk_DrawTextLayout(display, drawable, ((InstanceText*)ii)->gc,
			      ((MasterText*)mi)->layout,
			      x+((MasterText*)mi)->x, y+((MasterText*)mi)->y,
			      0, -1);
	    break;
	case ITEM_IMAGE:
	    {
		int y_offset=0;
		if (m->height>mi->height) {
		    switch (((MasterImage*)mi)->anchor) {
		    case TK_ANCHOR_CENTER:
		    case TK_ANCHOR_W:
		    case TK_ANCHOR_E:
			y_offset = (m->height-mi->height+0.5)/2;
			break;
		    case TK_ANCHOR_SW:
		    case TK_ANCHOR_S:
		    case TK_ANCHOR_SE:
			y_offset = m->height-mi->height;
		    }
		}
		Tk_RedrawImage(((InstanceImage*)ii)->image, 
			   0, 0, mi->width, mi->height, 
			       drawable, x, y+y_offset);
	    }
	    break;
	}
	x += mi->width;
	
	mi = mi->next;
	ii = ii->next;
    }
}


static void
ImgCmpFree(ClientData instanceData, Display *display)
{
    CompoundInstance *im=(CompoundInstance*)instanceData;
    
    if (im->refCount-- > 0) {
	return;
    }

    Tk_DoWhenIdle(DeleteInstanceStuff, instanceData);
}

static void
DeleteInstanceStuff(ClientData instanceData)
{
    CompoundInstance *im=(CompoundInstance*)instanceData;
    CompoundInstance **imPtr;
    for (imPtr = &im->master->instancePtr; *imPtr != im; 
	 imPtr = &(*imPtr)->next) {
	/* Nothing */
    }
    *imPtr = (*imPtr)->next;
    
    DeleteInstance(im->master->interp, im->contents);

    Tcl_Free((char*)im);
}
    
static void
ImgCmpDelete(ClientData masterData)
{
    CompoundMaster *m = (CompoundMaster*)masterData;

    DeleteMaster(m->interp, m);
    
    Tcl_Free((char*)m);
}

static void
RedisplayImagesWhenIdle(CompoundMaster *m)
{
    if (m->changing) {
	return;
    }
    m->changing = 1;
    Tcl_DoWhenIdle(RedisplayImages, (ClientData)m);
}

static void
RedisplayImages(ClientData clientData)
{
    CompoundMaster *m = (CompoundMaster*)clientData;

    m->changing = 0;
    Tk_ImageChanged(m->master, 0, 0, m->width, m->height, m->width, m->height);
}

static void
ImageHasChanged(ClientData clientData, 
		int x, int y,
		int width, int height,
		int imageWidth, int imageHeight)
{
    CompoundMaster *m = (CompoundMaster*)clientData;
    if (m->changing) {
	return;
    }
    
    ReconfigureMaster(m, Tcl_GetStringFromObj(m->desc, NULL));
    RedisplayImagesWhenIdle(m);
}

/* This deletes a list representing an instance */
static void
DeleteInstance(Tcl_Interp *interp, VirtualItem *item)
{
    while (item) {
	VirtualItem *next = item->next;
	switch (item->type) {
	case ITEM_TEXT:
	    Tk_FreeGC(Tk_Display(Tk_MainWindow(interp)),((InstanceText*)item)->gc);
	    break;
	case ITEM_IMAGE:
	    Tk_FreeImage(((InstanceImage*)item)->image);
	    break;
	}
	Tcl_Free((char*)item);
	item = next;
    }
}

/* This deletes a list representing a master.  We assume that all
   instances have already been deleted */
static void
DeleteMaster(Tcl_Interp *interp, CompoundMaster *m)
{
    VirtualItem *item=m->contents;
    
    while (item) {
	VirtualItem *next = item->next;
	switch (item->type) {
	case ITEM_TEXT:
	    {
		MasterText *it = (MasterText*)item;
		Tk_FreeTextLayout(it->layout);
		Tk_FreeOptions(textOptionSpecs, (char*)it, 
			       m->display, 0);
	    }
	    break;
	case ITEM_IMAGE:
	    {
		MasterImage *it = (MasterImage*)item;
		Tk_FreeOptions(imageOptionSpecs, (char*)it,
			       m->display, 0);
	    }
	    break;
	}
	Tcl_Free((char*)item);
	item = next;
    }
}
