/* Sysdep cpu capabilities object

   Copyright 2004-2005 Hans de Goede
   
   This file and the acompanying files in this directory are free software;
   you can redistribute them and/or modify them under the terms of the GNU
   Library General Public License as published by the Free Software Foundation;
   either version 2 of the License, or (at your option) any later version.

   These files are distributed in the hope that they will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with these files; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.
*/
#ifndef __SYSDEP_CPU_H
#define __SYSDEP_CPU_H
#include "begin_code.h"

#define SYSDEP_CPU_MMX 0x01

extern int sysdep_cpu_caps;

void sysdep_cpu_init(void);

#include "end_code.h"
#endif
