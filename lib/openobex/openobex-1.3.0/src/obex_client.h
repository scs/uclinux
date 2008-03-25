/*********************************************************************
 *                
 * Filename:      obex_client.h
 * Version:	  
 * Description:   
 * Status:        Stable.
 * Author:        Pontus Fuchs <pontus@tactel.se>
 * Created at:    Thu Nov 11 20:58:00 1999
 * CVS ID:        $Id: obex_client.h,v 1.3 2002/10/28 21:51:18 holtmann Exp $
 * 
 *     Copyright (c) 1999-2000 Pontus Fuchs, All Rights Reserved.
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

#ifndef OBEX_CLIENT_H
#define OBEX_CLIENT_H

int obex_client(obex_t *self, GNetBuf *msg, int final);

#endif
