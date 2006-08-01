/*
 * File:         drivers/char/bfin_pflags.h
 * Based on:
 * Author:       Michael Hennerich <hennerich@blackfin.org>
 *
 * Created:      Fri Jan 14 12:40:55 CEST 2005
 * Description:  pfbits driver for bf53x
 *
 * Rev:          $Id$
 *
 * Modified:
 *               Copyright 2005-2006 Analog Devices Inc.
 *
 * Bugs:         Enter bugs at http://blackfin.uclinux.org/
 *
 * This program is free software ;  you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation ;  either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY ;  without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program ;  see the file COPYING.
 * If not, write to the Free Software Foundation,
 * 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifndef __BFIN_PFLAGS_H__
#define __BFIN_PFLAGS_H__

#define SET_FIO_DIR                		1  // Peripheral Flag Direction Register
#define SET_FIO_POLAR              		2  // Flag Source Polarity Register
#define SET_FIO_EDGE               		3  // Flag Source Sensitivity Register
#define SET_FIO_BOTH               		4  // Flag Set on BOTH Edges Register
#define SET_FIO_INEN					5  // Flag Input Enable Register 


#define INPUT							0 // SET_FIO_DIR
#define OUTPUT							1

#define ACTIVEHIGH_RISINGEDGE			0 // SET_FIO_POLAR
#define ACTIVELOW_FALLINGEDGE			1

#define LEVEL							0 // SET_FIO_EDGE
#define EDGE							1

#define SINGLEEDGE						0 // SET_FIO_BOTH
#define BOTHEDGES						1

#define INPUT_DISABLE					0 // SET_FIO_INEN
#define INPUT_ENABLE					1

#endif
