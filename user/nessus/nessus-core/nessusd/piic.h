/* Nessus
 * Copyright (C) 1998 Renaud Deraison
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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Plugins Inter Communication
 * -   -   -     -
 *
 * This set of functions just read what the plugin writes on its pipe,
 * and put it in an arglist
 */ 
 
#ifndef NESSUSD_PIIC_H
#define NESSUSD_PIIC_H

void piic_parse(struct arglist*, struct arglist *, int, char *);
void piic_arglist(struct arglist *, int, char *);
char * key_missing(struct arglist *, struct arglist *);
char * key_present(struct arglist *, struct arglist *);
struct arglist * get_required_keys(struct arglist *);
struct arglist * get_excluded_keys(struct arglist *);
struct arglist * get_required_ports(struct arglist *);
struct arglist * get_required_udp_ports(struct arglist *);
int get_closed_ports(struct arglist *, struct arglist *, struct arglist *);
int get_closed_udp_ports(struct arglist *, struct arglist *, struct arglist *);
int piic_read_socket(struct arglist*, struct arglist *, int);
int common_required_ports(struct arglist*, struct arglist *);
#endif
