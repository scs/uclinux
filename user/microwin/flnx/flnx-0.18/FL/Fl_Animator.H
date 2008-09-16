#ifndef Fl_Animator_H
#define Fl_Animator_H

#ifndef Fl_Widget_H
#include "Fl_Widget.H"
#endif

#ifndef Fl_Pixmap_H
#include "Fl_Pixmap.H"
#endif

/* 
 * FL_ANIMATOR
 * This widget shows a series of frames from an XPM
 * that looks somewhat like a movie strip 
 *
 */

/* This is derived from a box, and it draws into one too */

class Fl_Animator : public Fl_Widget
{
private:

  int _xpos;
  int _ypos;

  double _interval;  /* Gap between frames, in seconds */
  
  int _fcount;    /* The number of frames in the strip  */
  int _fwidth;    /* The xsize of the frames */
  int _fheight;   /* The ysize of the frames */
  
  Fl_Pixmap *_image; /* The actual image */
		    
  int _curframe;  /* The current frame */
  bool _playing;    

  static void run_animation(void *data);
  void draw_frame();

protected:
  virtual FL_EXPORT void draw();

public:
  
  Fl_Animator(char * const *image, int X, int Y,
	      int fcount, int fwidth, int fheight, 
	      int finterval, const char *label = 0);

  ~Fl_Animator();
  
  /* The user passes the interval in miliseconds, and we convert it */
  /* internally */

  int interval() { return((int ) (_interval * 1000)); }
  void interval(int newint) { _interval = (double) (newint / 1000); }
  
  int frame_width() { return(_fwidth); }
  void frame_width(int newwidth) { _fwidth = newwidth; }

  int frame_height() { return(_fheight); }
  void frame_height(int newheight) { _fwidth = newheight; }

  int frame() { return _curframe; }
  void frame(int newframe)
  { if (newframe > 0 && newframe < _fcount) _curframe = newframe; }

  bool is_playing() {return _playing;}

  void start_animation();
  void stop_animation();

};

#endif
