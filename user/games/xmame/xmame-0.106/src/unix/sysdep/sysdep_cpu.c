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
#include <stdio.h>
#include <string.h>
#include "sysdep_cpu.h"

#ifdef EFFECT_MMX_ASM
int sysdep_cpu_caps = 0;

void sysdep_cpu_init(void)
{
#ifdef __ARCH_linux
  FILE *f;
  char buf[512];
  
  f = fopen("/proc/cpuinfo", "r");
  if (!f)
  {
    fprintf(stderr,
      "Warning couldn't open /proc/cpuinfo, assuming cpu has no special capabilities\n");
    return;
  }
  
  while(fgets(buf, 512, f))
  {
    if (strncmp(buf, "flags\t\t: ", 9) == 0)
    {
      if(strstr(buf, " mmx "))
        sysdep_cpu_caps |= SYSDEP_CPU_MMX;
    }
  }
  
  fclose(f);
#else
  /* for now just asume mmx is available on other archs, if not you should
     compile without EFFECT_MMX_ASM defined */
  sysdep_cpu_caps = SYSDEP_CPU_MMX;
#endif
}

#endif
