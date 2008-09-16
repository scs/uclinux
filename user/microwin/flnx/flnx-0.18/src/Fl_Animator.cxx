#include <FL/Fl.H>
#include <FL/Fl_Animator.H>

void Fl_Animator::run_animation(void *data)
{
  Fl_Animator *ani = (Fl_Animator *) data;

  ani->_curframe++;
  
  if (ani->_curframe == ani->_fcount)
    ani->_curframe = 0;
  
  ani->redraw();
  
  if (ani->_playing)
    Fl::add_timeout(ani->_interval, run_animation, data);
}
 
void Fl_Animator::draw_frame()
{
  int swidth = _curframe * _fwidth;

  _image->draw(_xpos, _ypos, 
	       _fwidth, _fheight,
	       swidth, 0);
}


Fl_Animator::Fl_Animator(char * const *image, int X, int Y,
			 int fcount, int fwidth, int fheight, 
			 int interval, const char *label)
  : Fl_Widget(X,Y,fwidth,fheight,label)
  
{
  int x, y;
  
  _image = new Fl_Pixmap(image);

  _xpos = X;
  _ypos = Y;

  _fcount = fcount;
  _fwidth = fwidth;
  _fheight = fheight;
  
  _interval = ((double) interval / 1000);

  _curframe = 0;
  
  _playing = false;
}

void Fl_Animator::draw() 
{
  /* Draw the current frame */
  if (_image) draw_frame();
}

Fl_Animator::~Fl_Animator()
{
  delete(_image);
}

void Fl_Animator::start_animation()
{
  if (_playing == true)
    return;

  _playing = true;
  Fl::add_timeout(_interval, run_animation, (void *) this);
}

void Fl_Animator::stop_animation()
{
  if (_playing == false)
    return;

  _playing = false;
  Fl::remove_timeout(run_animation, (void *) this);
}
