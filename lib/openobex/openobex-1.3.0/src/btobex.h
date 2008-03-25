/*********************************************************************
 *                
 * Filename:      btobex.h
 * Version:       
 * Description:   
 * Status:        Experimental.
 * Author:        Marcel Holtmann <marcel@holtmann.org>
 * Created at:    Fri Aug 23 14:32:31 2002
 * CVS ID:        $Id: btobex.h,v 1.3 2002/11/01 12:10:59 holtmann Exp $
 * 
 *     Copyright (c) 2002 Marcel Holtmann, All Rights Reserved.
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

#ifndef BTOBEX_H
#define BTOBEX_H

void btobex_prepare_connect(obex_t *self, bdaddr_t *src, bdaddr_t *dst, uint8_t channel);
void btobex_prepare_listen(obex_t *self, bdaddr_t *src, uint8_t channel);
int btobex_listen(obex_t *self);
int btobex_connect_request(obex_t *self);
int btobex_disconnect_request(obex_t *self);
int btobex_accept(obex_t *self);
int btobex_disconnect_server(obex_t *self);

#endif
