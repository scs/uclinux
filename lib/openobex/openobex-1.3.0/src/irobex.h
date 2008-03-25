/*********************************************************************
 *                
 * Filename:      irobex.h
 * Version:       
 * Description:   
 * Status:        Experimental.
 * Author:        Dag Brattli <dagb@cs.uit.no>
 * Created at:    Fri Apr 23 14:32:31 1999
 * CVS ID:        $Id: irobex.h,v 1.8 2002/10/28 21:51:18 holtmann Exp $
 * 
 *     Copyright (c) 1999 Dag Brattli, All Rights Reserved.
 *     
 *     This library is free software; you can redistribute it and/or
 *     modify it under the terms of the GNU Lesser General Public
 *     License as published by the Free Software Foundation; either
 *     version 2 of the License, or (at your option) any later version.
 *
 *     This library is distributed in the hope that it will be useful,
 *     but WITHOUT ANY WARRANTY; without even the implied warranty of
 *     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *     Lesser General Public License for more details.
 *
 *     You should have received a copy of the GNU Lesser General Public
 *     License along with this library; if not, write to the Free Software
 *     Foundation, Inc., 59 Temple Place, Suite 330, Boston, 
 *     MA  02111-1307  USA
 *     
 ********************************************************************/

#ifndef IROBEX_H
#define IROBEX_H

#define MAX_DEVICES 10     /* Max devices to discover */

void irobex_prepare_connect(obex_t *self, const char *service);
void irobex_prepare_listen(obex_t *self, const char *service);
int irobex_listen(obex_t *self);
int irobex_connect_request(obex_t *self);
int irobex_disconnect_request(obex_t *self);
int irobex_accept(obex_t *self);
int irobex_disconnect_server(obex_t *self);

#endif
