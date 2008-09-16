//
// "$Id: Fl_Input.cxx,v 1.1.1.1 2003/08/07 21:18:40 jasonk Exp $"
//
// Input widget for the Fast Light Tool Kit (FLTK).
//
// Copyright 1998-1999 by Bill Spitzak and others.
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Library General Public
// License as published by the Free Software Foundation; either
// version 2 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Library General Public License for more details.
//
// You should have received a copy of the GNU Library General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
// USA.
//
// Please report all bugs and problems to "fltk-bugs@easysw.com".
//

// This is the "user interface", it decodes user actions into what to
// do to the text.  See also Fl_Input_.C, where the text is actually
// manipulated (and some ui, in particular the mouse, is done...).
// In theory you can replace this code with another subclass to change
// the keybindings.

#include <FL/Fl.H>
#include <FL/Fl_Input.H>
#include <FL/fl_draw.H>
#include <stdio.h>
#include <math.h>
#include <string.h>
#include <ctype.h>

void Fl_Input::draw() {
  if (type() == FL_HIDDEN_INPUT) return;
  Fl_Boxtype b = box();
  if (damage() & FL_DAMAGE_ALL) {
    draw_box(b, color());
  }
#ifdef PDA
	if (b == FL_BOTTOM_BOX) 
		Fl_Input_::drawtext(x()+Fl::box_dx(b)+3, y()+Fl::box_dy(b)+3,
		      w()-Fl::box_dw(b)-6, h()-Fl::box_dh(b)-6);
	else
#endif
		Fl_Input_::drawtext(x()+Fl::box_dx(b)+3, y()+Fl::box_dy(b),
		      w()-Fl::box_dw(b)-6, h()-Fl::box_dh(b));
}

// kludge so shift causes selection to extend:
int Fl_Input::shift_position(int p) {
  return position(p, Fl::event_state(FL_SHIFT) ? mark() : p);
}
int Fl_Input::shift_up_down_position(int p) {
  return up_down_position(p, Fl::event_state(FL_SHIFT));
}

////////////////////////////////////////////////////////////////
// Fltk "compose"
//
// This is a demonstration of a IMHO "correct" interface to compose
// character sequences.  It does not have a "dead key" effect: the
// user has feedback at all times, and sees exactly the symbol they
// will get if they stop typing at that point.  Notice that I totally
// ignore the horrid XIM extension!
//
// You only need to keep track of your normal text buffer and a
// single integer "state".  Call fl_compose() for each character
// keystroke.  The return value is the new "state" that must be passed
// the next time you call fl_compose().  It also returns the number of
// characters to delete to the left, a buffer of new characters, and
// the number of characters in that buffer.  Obey these editing
// instructions.  Reset the state to zero if the user types any
// function keys or clicks the mouse.
//
// Fl_Input does not call fl_compose unless you hit the "compose" key
// first.  It may be interesting and useful to always call it, though...

// Although this simple code is only for ISO-8859-1 character
// encodings, I think the interface can be expanded to UTF-8 (encoded
// Unicode) someday.

// This string lists a pair for each possible foreign letter in ISO-8859-1
// starting at code 0xa0 (nbsp).  If the second character is a space then
// only the first character needs to by typed:
static const char* const compose_pairs =
"  ! % # $ y=| & : c a <<~ - r _ * +-2 3 ' u p . , 1 o >>141234? "
"A`A'A^A~A:A*AEC,E`E'E^E:I`I'I^I:D-N~O`O'O^O~O:x O/U`U'U^U:Y'THss"
"a`a'a^a~a:a*aec,e`e'e^e:i`i'i^i:d-n~o`o'o^o~o:-:o/u`u'u^u:y'thy:";

int fl_compose(int state, char c, int& del, char* buffer, int& ins) {
  del = 0; ins = 1; buffer[0] = c;

  if (c == '"') c = ':';

  if (!state) {	// first character
    if (c == ' ') {buffer[0]=char(0xA0);return 0x100;} // space turns into nbsp
    // see if it is either character of any pair:
    state = 0;
    for (const char *p = compose_pairs; *p; p += 2) 
      if (p[0] == c || p[1] == c) {
	if (p[1] == ' ') buffer[0] = (p-compose_pairs)/2+0xA0;
	state = c;
      }
    return state;

  } else if (state == 0x100) { // third character
    return 0;

  } else { // second character
    char c1 = char(state); // first character
    // now search for the pair in either order:
    for (const char *p = compose_pairs; *p; p += 2) {
      if (p[0] == c && p[1] == c1 || p[1] == c && p[0] == c1) {
	buffer[0] = (p-compose_pairs)/2+0xA0;
	ins = del = 1;
	return 0x100;
      }
    }
    return 0;
  }
}

////////////////////////////////////////////////////////////////

#define CTRL_MODE  0x2
#define SHIFT_MODE 0x1
#define ALT_MODE   0x4

static int compose; // compose state (# of characters so far + 1)
static unsigned char modifier_state = 0;

static uchar shift_map[128] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
    0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,    
    0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
    0x28,0x29,0x2A,0x2B,0x3C,0x5F,0x3E,0x3F,
    0x29,0x21,0x40,0x23,0x24,0x25,0x5E,0x26, /* 0 1 2 3 4 5 6 7 */
    0x2A,0x28,0x3A,0x3A,0x3C,0x2B,0x3E,0x3F, /* 8 9 : ; < = > ? */
    0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47, /* @ A B C D E F G */
    0x48,0x49,0x4A,0x4B,0x4C,0x4D,0x4E,0x4F, /* H I J K L M N O */
    0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57, /* P Q R S T U V W */
    0x58,0x59,0x5A,0x7B,0x7C,0x7D,0x5E,0x5F, /* X Y Z [ \ ] ^ _ */
    0x7E,0x41,0x42,0x43,0x44,0x45,0x46,0x47, /* ` a b c d e f g */
    0x48,0x49,0x4A,0x4B,0x4C,0x4D,0x4E,0x4F, /* h i j k l m n o */
    0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57, /* p q r s t u v w */
    0x58,0x59,0x5A,0x7B,0x7C,0x7D,0x7E,0x7F  /* x y z { | } ~   */
};

// If you define this symbol as zero you will get the peculiar fltk
// behavior where moving off the end of an input field will move the
// cursor into the next field:
// define it as 1 to prevent cursor movement from going to next field:
#define NORMAL_INPUT_MOVE 0

#define ctrl(x) (x^0x40)

/* TODOTODO:  Keypad handling (It just ignores it right now) */

int Fl_Input::handle_key() {
  int i;

  int pcompose = compose; compose = 0;
  unsigned char key;
  unsigned char tbuf[20];

  /* printf("KEY = %d\n", (unsigned char) Fl::event_text()[0]); */

  /* Ok, so we have to map the shift key somehow...   */
  /* This is a slow and not elegant kudge.  Fix it    */

  if ((Fl::event_state(FL_SHIFT) || (modifier_state & SHIFT_MODE) == SHIFT_MODE) ||
      (Fl::event_state(FL_CAPS_LOCK)))
    {
      for(i = 0; i < Fl::event_length(); i++)
	{
	  unsigned char nkey;

	  if ((nkey = Fl::event_text()[i]) <= 128)
	    tbuf[i] = shift_map[nkey];
	  else
	    tbuf[i] = nkey;
	}

      modifier_state &= ~SHIFT_MODE;
    }
  else
    {
      for(i = 0; i < Fl::event_length(); i++)
	tbuf[i] = Fl::event_text()[i];    }

  key = tbuf[0];

  if (pcompose && Fl::event_length()) {
    char buf[20]; int ins; int del;

    /* JHC 09/20/00 - Check for shift mode here */

    compose = fl_compose(pcompose-1, key, del, buf, ins);
    if (compose) {
      replace(position(), del ? position()-del : mark(), buf, ins);
      compose++; // store value+1 so 1 can initialize compose state
      return 1;
    } else {
      if (pcompose==1)	// compose also acts as quote-next:
	return replace(position(),mark(),(char *) tbuf,Fl::event_length());
    }
  }

  if (Fl::event_state(FL_ALT|FL_META)) { // reserved for shortcuts
    compose = pcompose;
    return 0;
  }

  switch (Fl::event_key()) {
  case FL_Left:
    key = ctrl('B'); break;
  case FL_Right:
    key = ctrl('F'); break;
  case FL_Up:
    key = ctrl('P'); break;
  case FL_Down:
    key = ctrl('N'); break;
  case FL_Delete:
    key = ctrl('D'); break;
  case FL_Home:
    key = ctrl('A'); break;
  case FL_End:
    key = ctrl('E'); break;
  case FL_BackSpace:
    if (mark() != position()) cut();
    else cut(-1);
    return 1;
  case FL_Enter:
  case FL_KP_Enter:
    if (when() & FL_WHEN_ENTER_KEY) {
      position(size(), 0);
      maybe_do_callback();
      return 1;
    } else if (type() == FL_MULTILINE_INPUT)
      return replace(position(), mark(), "\n", 1);
    else 
      return 0;	// reserved for shortcuts
  case FL_Tab:
    if (Fl::event_state(FL_CTRL) || type()!=FL_MULTILINE_INPUT) return 0;
    break;
  case FL_Escape:
    return 0;	// reserved for shortcuts (Forms cleared field)

  case FL_Caps_Lock:
    return(1);

  case FL_Shift_L:
  case FL_Shift_R:
    modifier_state |= SHIFT_MODE;
    return(1);

  case FL_Control_L:
  case FL_Control_R:
    modifier_state |= CTRL_MODE;
    return(1);

  case FL_Alt_L:
  case FL_Alt_R:
    return(1);

  default:
    if (Fl::event_key() & 0xFF00)
      return(0);
  }

  if (Fl::event_state(FL_CTRL) || (modifier_state & CTRL_MODE) == CTRL_MODE)
    {
      /* For the moment, we will translate the key to uppercase */
      /* because thats what the stuff below wants.              */
      
      key = ctrl(shift_map[key]);

      /* Further ctrl-<key> presses are handled by the event state */
      modifier_state &= ~CTRL_MODE;
    }

  switch(key) {
  case 0:	// key did not translate to any text
    compose = pcompose; // allow user to hit shift keys after ^Q
    return 0;
  case ctrl('A'):
    if (type() == FL_MULTILINE_INPUT)
      for (i=position(); i && index(i-1)!='\n'; i--) ;
    else
      i = 0;
    return shift_position(i) + NORMAL_INPUT_MOVE;
  case ctrl('B'):
    return shift_position(position()-1) + NORMAL_INPUT_MOVE;
  case ctrl('C'): // copy
    return copy();
  case ctrl('D'):
    if (mark() != position()) return cut();
    else return cut(1);
  case ctrl('E'):
    if (type() == FL_MULTILINE_INPUT)
      for (i=position(); index(i) && index(i)!='\n'; i++) ;
    else
      i = size();
    return shift_position(i) + NORMAL_INPUT_MOVE;
  case ctrl('F'):
    return shift_position(position()+1) + NORMAL_INPUT_MOVE;
  case ctrl('K'):
    if (position()>=size()) return 0;
    if (type() == FL_MULTILINE_INPUT) {
      if (index(position()) == '\n')
	i = position() + 1;
      else 
	for (i=position()+1; index(i) && index(i) != '\n'; i++);
    } else
      i = size();
    cut(position(), i);
    return copy_cuts();
  case ctrl('N'):
    if (type()!=FL_MULTILINE_INPUT) return 0;
    for (i=position(); index(i)!='\n'; i++)
      if (!index(i)) return NORMAL_INPUT_MOVE;
    shift_up_down_position(i+1);
    return 1;
  case ctrl('P'):
    if (type()!=FL_MULTILINE_INPUT) return 0;
    for (i = position(); i > 0 && index(i-1) != '\n'; i--) ;
    if (!i) return NORMAL_INPUT_MOVE;
    shift_up_down_position(i-1);
    return 1;
  case ctrl('Q'):
    compose = 1;
    return 1;
  case ctrl('U'):
    return cut(0, size());
  case ctrl('V'):
  case ctrl('Y'):
    Fl::paste(*this);
    return 1;
  case ctrl('X'):
  case ctrl('W'):
    copy();
    return cut();
  case ctrl('Z'):
  case ctrl('_'):
    return undo();
  }

  // skip all illegal characters
  // this could be improved to make sure characters are inserted at
  // legal positions...
  if (type() == FL_FLOAT_INPUT) {
    if (!strchr("0123456789.eE+-", key)) return 0;
  } else if (type() == FL_INT_INPUT) {
    if (!position() && (key == '+' || key == '-'));
    else if (key >= '0' && key <= '9');
    // we allow 0xabc style hex numbers to be typed:
    else if (position()==1 && index(0)=='0' && (key == 'x' || key == 'X'));
    else if (position()>1 && index(0)=='0' && (index(1)=='x'||index(1)=='X')
           && (key>='A'&& key<='F' || key>='a'&& key<='f'));
    else return 0;
  }

  return replace(position(), mark(), (char *) tbuf, Fl::event_length());
}

int Fl_Input::handle(int event) {

  switch (event) {

  case FL_FOCUS:
    switch (Fl::event_key()) {
    case FL_Right:
      position(0);
      break;
    case FL_Left:
      position(size());
      break;
    case FL_Down:
      up_down_position(0);
      break;
    case FL_Up:
      up_down_position(size());
      break;
    case FL_Tab:
    case 0xfe20: // XK_ISO_Left_Tab
      position(size(),0);
      break;
    }
    break;

  case FL_UNFOCUS:
    compose = 0;
    break;

  case FL_KEYBOARD:
    return handle_key();

  case FL_PUSH:
    if (Fl::focus() != this) {
      Fl::focus(this);
      handle(FL_FOCUS);
      // Windoze-style: select everything on first click:
      if (type() != FL_MULTILINE_INPUT) {
        position(0, size()); // select everything
        return 1;
      }
    }
    compose = 0;
    break;

  case FL_RELEASE:
    if (Fl::event_button() == 2) {
      Fl::event_is_click(0); // stop double click from picking a word
      Fl::paste(*this);
    } else if (!Fl::event_is_click()) {
      // copy drag-selected text to the clipboard.
      //copy();
    }

    return 1;

  }
  Fl_Boxtype b = box();
  return Fl_Input_::handletext(event,
	x()+Fl::box_dx(b)+3, y()+Fl::box_dy(b),
	w()-Fl::box_dw(b)-6, h()-Fl::box_dh(b));
}

Fl_Input::Fl_Input(int x, int y, int w, int h, const char *l)
: Fl_Input_(x, y, w, h, l) {
}

//
// End of "$Id: Fl_Input.cxx,v 1.1.1.1 2003/08/07 21:18:40 jasonk Exp $".
//
