#include <stdio.h>

int XScreenResourceString() { printf("XScreenResourceString called\n"); return 0; } 
int XWMGeometry() { printf("XWMGeometry called\n"); return 0; } 
int XGetIconSizes() { printf("XGetIconSizes called\n"); return 0; } 
int XQueryBestCursor() { printf("XQueryBestCursor called\n"); return 0; } 
int XSetState() { printf("XSetState called\n"); return 0; } 
int XResourceManagerString() { printf("XResourceManagerString called\n"); return 0; } 
int XrmParseCommand() { printf("XrmParseCommand called\n"); return 0; } 
int XQueryKeymap() { printf("XQueryKeymap called\n"); return 0; } 
int XGetDefault() { printf("XGetDefault called\n"); return 0; } 
int XRecolorCursor() { printf("XRecolorCursor called\n"); return 0; } 

/* stubbed out calls, need implementations*/
int XCloseIM() { printf("XCloseIM called\n"); return 0; } 
int XListExtensions() { printf("XListExtensions called\n"); return 0; } 

/* required for gtk+ 1.2.7*/
int XAutoRepeatOn() { printf("XAutoRepeatOn called\n"); return 0; } 
int XAutoRepeatOff() { printf("XAutoRepeatOff called\n"); return 0; } 
int XChangeActivePointerGrab() { printf("XChangeActivePointerGrab called\n"); return 0; } 
int XShrinkRegion() { printf("XShrinkRegion called\n"); return 0; } 

/* required for gtk+ 2.0.6*/
int XShapeCombineRectangles() { printf("XShapeCombineRectangles called\n"); return 0; } 
int XShapeGetRectangles() { printf("XShapeGetRectangles called\n"); return 0; } 
int XAddConnectionWatch() { printf("XAddConnectionWatch called\n"); return 0; } 
int XProcessInternalConnection() { printf("XProcessInternalConnection called\n"); return 0;}
int XCopyGC() { printf("XCopyGC called\n"); return 0;}
int XGetSubImage() { printf("XGetSubImage called\n"); return 0;}
int XGetMotionEvents() { printf("XGetMotionEvents called\n"); return 0;}
int XQueryExtension() { printf("XQueryExtension called\n"); return 0; } 
int XwcDrawString() { printf("XwcDrawString called\n"); return 0;}

int XwcTextExtents() { printf("XwcTextExtents called\n"); return 0;}
int XwcTextEscapement() { printf("XwcTextEscapement called\n"); return 0;}

int XmbTextPropertyToTextList() { printf("XmbTextPropertyToTextList called\n"); return 0;}
int XmbTextEscapement() { printf("XmbTextEscapement called\n"); return 0;}
int XmbResetIC() { printf("XmbResetIC called\n"); return 0; } 
int XGetICValues() { printf("XGetICValues called\n"); return 0; } 
int XFontsOfFontSet() { printf("XFontsOfFontSet called\n"); return 0;}
int XBaseFontNameListOfFontSet() { printf("XBaseFontNameListOfFontSet called\n"); return 0;}
int XkbLibraryVersion() { printf("XkbLibraryVersion called\n"); return 0; } 
int XDisplayKeycodes() { printf("XDisplayKeycodes called\n"); return 0;}
int XGetKeyboardMapping() { printf("XGetKeyboardMapping called\n"); return 0;}
int XGetKeyboardControl() { printf("XGetKeyboardControl called\n"); return 0; } 
int XShmPutImage() { printf("XShmPutImage called\n"); return 0; } 

/* other required*/
int XAddExtension() { printf("XAddExtension called\n"); return 0; } 
int XAllocColorCells() { printf("XAllocColorCells called\n"); return 0; }
int _XAllocScratch() { printf("_XAllocScratch called\n"); return 0; } 
int XAllowEvents() { printf("XAllowEvents called\n"); return 0; } 

int XCreateIC() { printf("XCreateIC called\n"); return 0; } 
int XDestroyIC() { printf("XDestroyIC called\n"); return 0; } 
int _XEatData() { printf("_XEatData called\n"); return 0; } 
int XESetCloseDisplay() { printf("XESetCloseDisplay called\n"); return 0; } 
int XESetCopyGC() { printf("XESetCopyGC called\n"); return 0; } 
int XESetCreateFont() { printf("XESetCreateFont called\n"); return 0; } 
int XESetCreateGC() { printf("XESetCreateGC called\n"); return 0; } 
int XESetError() { printf("XESetError called\n"); return 0; } 
int XESetErrorString() { printf("XESetErrorString called\n"); return 0; } 
int XESetEventToWire() { printf("XESetEventToWire called\n"); return 0; } 
int XESetFlushGC() { printf("XESetFlushGC called\n"); return 0; } 
int XESetFreeFont() { printf("XESetFreeFont called\n"); return 0; } 
int XESetFreeGC() { printf("XESetFreeGC called\n"); return 0; } 
int XESetWireToEvent() { printf("XESetWireToEvent called\n"); return 0; } 
int XExtentsOfFontSet() { printf("XExtentsOfFontSet called\n"); return 0; } 
int XFetchName() { printf("XFetchName called\n"); return 0; }
int _XFlush() { printf("_XFlush called\n"); return 0; } 
int _XFlushGCCache() { printf("_XFlushGCCache called\n"); return 0; } 
int XFreeFontSet() { printf("XFreeFontSet called\n"); return 0; } 
int XFreeStringList() { printf("XFreeStringList called\n"); return 0; } 
int _XGetBitsPerPixel() { printf("_XGetBitsPerPixel called\n"); return 0; } 
int XGetGCValues() { printf("XGetGCVAlues called\n"); return 0; }
int XGetErrorDatabaseText() { printf("XGetErrorDatabaseText called\n"); return 0; } 
int XGetErrorText() { printf("XGetErrorText called\n"); return 0; } 
int XGetIMValues() { printf("XGetIMValues called\n"); return 0; } 
int _XGetScanlinePad() { printf("_XGetScanlinePad called\n"); return 0; } 

int XGetWMHints() { printf("XGetWMHints called\n"); return 0; } 
int XGetWMNormalHints() { printf("XGetWMNormalHints called\n"); return 0; } 
int XGrabKeyboard() { printf("XGrabKeyboard called\n"); return 0; } 
int XGrabPointer() { printf("XGrabPointer called\n"); return 0; } 
int XGrabServer() { printf("XGrabServer called\n"); return 0; } 
int XIconifyWindow() { printf("XIconifyWindow called\n"); return 0; } 
int XInitExtension() { printf("XInitExtension called\n"); return 0; } 
int _XInitImageFuncPtrs() { printf("_XInitImageFuncPtrs called\n"); return 0; } 
int XKillClient() { printf("XKillClient called\n"); return 0; } 
int XMaxRequestSize() { printf("XMaxRequestSize called\n"); return 0; } 
int XmbDrawImageString() { printf("XmbDrawImageString called\n"); return 0; } 
int XmbDrawString() { printf("XmbDrawString called\n"); return 0; } 
int XmbLookupString() { printf("XmbLookupString called\n"); return 0; } 
int XmbTextExtents() { printf("XmbTextExtents called\n"); return 0; } 

int XOpenIM() { printf("XOpenIM called\n"); return 0; } 
int XParseGeometry() { printf("XParseGeometry called\n"); return 0; } 
int _XRead() { printf("_XRead called\n"); return 0; } 
int _XReadPad() { printf("_XReadPad called\n"); return 0; } 
int XRefreshKeyboardMapping() { printf("XRefreshKeyboardMapping called\n"); return 0; } 
int XRegisterIMInstantiateCallback() { printf("XRegisterIMInstantiateCallback called\n"); return 0; } 
int _XReply() { printf("_XReply called\n"); return 0; } 
int XRestackWindows() { printf("XRestackWindows called\n"); return 0; } 
int _XSend() { printf("_XSend called\n"); return 0; } 
int XSendEvent() { printf("XSendEvent called\n"); return 0; } 
int XSetArcMode() { printf("XSetArcMode called\n"); return 0; } 
int XSetCloseDownMode() { printf("XSetCloseDownMode called\n"); return 0; } 
int XSetErrorHandler() { printf("XSetErrorHandler called\n"); return 0; } 
int XSetFillRule() { printf("XSetFillRule called\n"); return 0; } 
int XSetICFocus() { printf("XSetICFocus called\n"); return 0; } 
int XSetICValues() { printf("XSetICValues called\n"); return 0; } 
int XSetIMValues() { printf("XSetIMValues called\n"); return 0; } 
int _XSetLastRequestRead() { printf("_XSetLastRequestRead called\n"); return 0; } 
int XSetLocaleModifiers() { printf("XSetLocaleModifiers called\n"); return 0; } 

int XSetStandardProperties() { printf("XSetStandardProperties called\n"); return 0; } 
int XSetNormalHints() { printf("XSetNormalHints called\n"); return 0; }
int XSetTransientForHint() { printf("XSetTransientForHint called\n"); return 0; } 
int XSetWMProtocols() { printf("XSetWMProtocols called\n"); return 0; } 
int XSupportsLocale() { printf("XSupportsLocale called\n"); return 1; } 
int XSynchronize() { printf("XSynchronize called\n"); return 0; } 
int XUngrabKeyboard() { printf("XUngrabKeyboard called\n"); return 0; } 
int XUngrabPointer() { printf("XUngrabPointer called\n"); return 0; } 
int XUngrabServer() { printf("XUngrabServer called\n"); return 0; } 
int XUnregisterIMInstantiateCallback() { printf("XUnregisterIMInstantiateCallback called\n"); return 0; } 
int XUnsetICFocus() { printf("XUnsetICFocus called\n"); return 0; } 
int XVaCreateNestedList() { printf("XVaCreateNestedList called\n"); return 0; } 
int _XVIDtoVisual() { printf("_XVIDtoVisual called\n"); return 0; } 
int XWarpPointer() { printf("XWarpPointer called\n"); return 0; } 
int XInstallColormap() { printf("XInstallColormap called\n"); return 0; } 
int XReconfigureWMWindow() { printf("XReconfigureWMWindow called\n"); return 0; } 
int XSetWindowColormap() { printf("XSetWindowColormap called\n"); return 0; } 
int XUninstallColormap() { printf("XUninstallColormap called\n"); return 0; } 
int XConfigureWindow() { printf("XConfigureWindow called\n"); return 0; } 
int XForceScreenSaver() { printf("XForceScreenSaver called\n"); return 0; } 
int XFreeModifiermap() { printf("XFreeModifiermap called\n"); return 0; } 
int XGetInputFocus() { printf("XGetInputFocus called\n"); return 0; } 
int XGetModifierMapping() { printf("XGetModifierMapping called\n"); return 0; } 
int XGetWMColormapWindows() { printf("XGetWMColormapWindows called\n"); return 0; } 
int XKeysymToString() { printf("XKeysymToString called\n"); return 0; } 
int XListHosts() { printf("XListHosts called\n"); return 0; } 
int XSetClassHint() { printf("XSetClassHint called\n"); return 0; } 
int XSetCommand() { printf("XSetCommand called\n"); return 0; } 
int XSetWindowBorderPixmap() { printf("XSetWindowBorderPixmap called\n"); return 0; } 
int XSetWMClientMachine() { printf("XSetWMClientMachine called\n"); return 0; } 
int XSetWMColormapWindows() { printf("XSetWMColormapWindows called\n"); return 0; } 
int XStoreColor() { printf("XStoreColor called\n"); return 0; }
int XStoreColors() { printf("XStoreColors called\n"); return 0; }
