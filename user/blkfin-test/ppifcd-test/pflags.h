/*
 *
 *    File:         pflags.h
 *    Rev:          0.1
 *    Created:      Fri Jan 14 12:40:55 CEST 2005
 *    Author:       Michael Hennerich
 *    mail:         hennerich@blackfin.org
 *    Description:  pfbits driver for bf53x
 *                  
 *   Copyright (C) 2005 Michael Hennerich/Analog Devices Inc.
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *
 ****************************************************************************
 * MODIFICATION HISTORY:
 * Jan 10, 2005   pflags.c Changed Michael Hennerich, Analog Devices Inc. 
 **************************************************************************** 
 */

#define SET_FIO_DIR                		1  // Peripheral Flag Direction Register
#define SET_FIO_POLAR              		2  // Flag Source Polarity Register
#define SET_FIO_EDGE               		3  // Flag Source Sensitivity Register
#define SET_FIO_BOTH               		4  // Flag Set on BOTH Edges Register
#define SET_FIO_INEN					5  // Flag Input Enable Register 


#define INPUT							0
#define OUTPUT							1
#define ACTIVEHIGH_RISINGEDGE			0
#define ACTIVELOW_FALLINGEDGE			1
#define LEVEL							0
#define EDGE							1

#define SINGLEEDGE						0
#define BOTHEDGES						1

#define INPUT_DISABLE					0
#define INPUT_ENABLE					1





