#ifndef Fl_Window_Resize_H
#define Fl_Window_Resize_H

#include "Fl_Window.H"
#include <iostream.h>
class Fl_Window_Resize : public Fl_Window {
  
public:
  Fl_Window_Resize(int X, int Y, int W, int H, const char* L = 0)
    : Fl_Window( X, Y, W, H, L ) {cout << "1" << endl;}

  virtual void resize_notify(int, int, int, int);

};

#endif


