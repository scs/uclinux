/*********************************************************************
 *                
 * Filename:      obex_connect.h
 * Version:       
 * Description:   
 * Status:        Experimental.
 * Author:        Dag Brattli <dagb@cs.uit.no>
 * Created at:    Wed May  5 11:55:41 1999
 * CVS ID:        $Id: obex_connect.h,v 1.4 2002/10/28 21:51:18 holtmann Exp $
 * 
 *     Copyright (c) 1999 Dag Brattli, All Rights Reserved.
 *     
 *     This program is free software; you can redistribute it and/or 
 *     modify it under the terms of the GNU General Public License as 
 *     published by the Free Software Foundation; either version 2 of 
 *     the License, or (at your option) any later version.
 * 
 *     This program is distributed in the hope that it will be useful,
 *     but WITHOUT ANY WARRANTY; without even the implied warranty of
 *     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *     GNU General Public License for more details.
 * 
 *     You should have received a copy of the GNU General Public License 
 *     along with this program; if not, write to the Free Software 
 *     Foundation, Inc., 59 Temple Place, Suite 330, Boston, 
 *     MA 02111-1307 USA
 *     
 ********************************************************************/

#ifndef OBEX_CONNECT_H
#define OBEX_CONNECT_H

#include "obex_main.h"

int obex_insert_connectframe(obex_t *self, obex_object_t *object);
int obex_parse_connect_header(obex_t *self, GNetBuf *msg);

#endif

