/*
 * IRC - Internet Relay Chat, ircd/m_netroute.c
 * Copyright (C) 2010 Kevin L. Mitchell <klmitch@mit.edu>
 *
 * See file AUTHORS in IRC package for additional names of
 * the programmers.
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
 *
 * $Id$
 */

/*
 * m_functions execute protocol messages on this server:
 *
 *    cptr    is always NON-NULL, pointing to a *LOCAL* client
 *            structure (with an open socket connected!). This
 *            identifies the physical socket where the message
 *            originated (or which caused the m_function to be
 *            executed--some m_functions may call others...).
 *
 *    sptr    is the source of the message, defined by the
 *            prefix part of the message if present. If not
 *            or prefix not found, then sptr==cptr.
 *
 *            (!IsServer(cptr)) => (cptr == sptr), because
 *            prefixes are taken *only* from servers...
 *
 *            (IsServer(cptr))
 *                    (sptr == cptr) => the message didn't
 *                    have the prefix.
 *
 *                    (sptr != cptr && IsServer(sptr) means
 *                    the prefix specified servername. (?)
 *
 *                    (sptr != cptr && !IsServer(sptr) means
 *                    that message originated from a remote
 *                    user (not local).
 *
 *            combining
 *
 *            (!IsServer(sptr)) means that, sptr can safely
 *            taken as defining the target structure of the
 *            message in this server.
 *
 *    *Always* true (if 'parse' and others are working correct):
 *
 *    1)      sptr->from == cptr  (note: cptr->from == cptr)
 *
 *    2)      MyConnect(sptr) <=> sptr == cptr (e.g. sptr
 *            *cannot* be a local connection, unless it's
 *            actually cptr!). [MyConnect(x) should probably
 *            be defined as (x == x->from) --msa ]
 *
 *    parc    number of variable parameter strings (if zero,
 *            parv is allowed to be NULL)
 *
 *    parv    a NULL terminated list of parameter pointers,
 *
 *                    parv[0], sender (prefix string), if not present
 *                            this points to an empty string.
 *                    parv[1]...parv[parc-1]
 *                            pointers to additional parameters
 *                    parv[parc] == NULL, *always*
 *
 *            note:   it is guaranteed that parv[0]..parv[parc-1] are all
 *                    non-NULL pointers.
 */
#include "config.h"

#include "client.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_routing.h"
#include "send.h"

#include <string.h>

/*
 * ms_netroute - broadcast route announcement
 *
 * parv[0] = sender prefix
 * parv[1] = source numnick
 * parv[2] = route index
 * parv[3] = route length / "+" if chunked
 * parv[4] = route data (if length > 0)
 */
int ms_netroute(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  if(parc < 4)
    return need_more_params(sptr, "NETROUTE");
  
  struct Client* acptr;
  if(!(acptr = FindNServer(parv[1])))
    return 0;
  
  unsigned int routeidx = atoi(parv[2]);
  if(cli_serv(acptr)->fwd_route && routeidx <= cli_serv(acptr)->fwd_route->route_idx && 
    !(routeidx == 1 && cli_serv(acptr)->fwd_route->route_idx >= ROUTE_INDEX_ROLLOVER) // index overflow
   ) {
    return 0; // ignore - we already have a newer route from acptr
  }
  
  unsigned int routelen = atoi(parv[3]);
  if(routelen > NN_MAX_SERVER) {
    protocol_violation(cptr, "route too long.");
    return 0;
  }
  
  struct RouteInfo *netroute = MyCalloc(1, sizeof(struct RouteInfo));
  netroute->route_idx = routeidx;
  netroute->route_len = routelen;
  
  if(routelen > 0) {
    int datalen = (routelen * 2) + 1;
    netroute->is_ptrdata = 1;
    netroute->route_data = MyMalloc(datalen);
    memcpy(netroute->route_data, parv[4], datalen);
  }
  
  update_server_netroute(acptr, cptr, netroute);
  return 0;
}
