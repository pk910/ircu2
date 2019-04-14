/*
 * IRC - Internet Relay Chat, include/s_routing.h
 * Copyright (C) 2019 Philipp Kreil
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 1, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
/** @file
 * @brief message index structures and declarations
 * @version $Id$
 */
#ifndef INCLUDED_s_routing_h
#define INCLUDED_s_routing_h


struct RouteIdxLink {
  struct RouteIdxLink *next;
  char server_xyy[3];
  unsigned int msgidx;
};





#endif /* INCLUDED_s_routing_h */
