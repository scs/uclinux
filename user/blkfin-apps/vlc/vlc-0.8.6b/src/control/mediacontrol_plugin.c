/*****************************************************************************
 * plugin.c: Core functions : init, playlist, stream management
 *****************************************************************************
 * Copyright (C) 2005 the VideoLAN team
 * $Id: mediacontrol_plugin.c 17322 2006-10-28 14:49:42Z jpsaman $
 *
 * Authors: Olivier Aubert <olivier.aubert@liris.univ-lyon1.fr>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston MA 02110-1301, USA.
 *****************************************************************************/

#include <mediacontrol_internal.h>
#include <vlc/mediacontrol.h>
#include <vlc/intf.h>

mediacontrol_Instance* mediacontrol_new( char** args, mediacontrol_Exception *exception )
{
    exception->code = mediacontrol_InternalException;
    exception->message = strdup( "The mediacontrol extension was compiled for plugin usage only." );
    return NULL;
};

void
mediacontrol_exit( mediacontrol_Instance *self )
{
    vlc_mutex_lock( &self->p_intf->change_lock );
    self->p_intf->b_die = 1;
    vlc_mutex_unlock( &self->p_intf->change_lock );
}
