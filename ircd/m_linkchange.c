/*
 * IRC - Internet Relay Chat, ircd/m_linkchange.c
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
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "send.h"
#include "s_misc.h"
#include "s_routing.h"

#include <string.h>

/*
 * ms_linkchange - uplink change announcement
 *
 * parv[0] = sender prefix
 * parv[1] = data
 */
int ms_linkchange(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  if(parc < 2)
    return need_more_params(sptr, "LINKCHANGE");
  
  struct Client* acptr;
  struct Client* parent;
  int i;
  unsigned int linkcost;
  char *msgdata, *numpath;
  char *announce, tmpch;
  
  msgdata = parv[1];
  if((numpath = strchr(msgdata, ':'))) {
    *numpath = '\0';
    numpath++;
    for(i = 0; numpath[i]; i+=2) {
      if(RouteLinkNumIs((numpath + i), &me))
        return 0; // ignore if i have already touched it before
    }
  }
  
  msgdata = strtok(msgdata, " ");
  while (msgdata) {
    announce = msgdata;
    msgdata = strtok(NULL, " ");
    if(strlen(announce) < 5)
      continue;
    
    tmpch = announce[2];
    announce[2] = '\0';
    acptr = FindNServer(announce);
    announce[2] = tmpch;
    announce += 2;
    if(!acptr)
      continue;
    if(acptr == &me)
      continue;
    
    tmpch = announce[2];
    announce[2] = '\0';
    parent = FindNServer(announce);
    announce[2] = tmpch;
    announce += 2;
    
    if(parent == &me)
      continue;
    
    if(*announce == '-') {
      denounce_server_route(cptr, acptr, cli_yxx(parent), numpath);
    }
    else if(*announce == '0') {
      update_server_route(cptr, acptr, cptr, NULL, 0, numpath);
    }
    else {
      linkcost = atoi(announce);
      linkcost += cli_linkcost(cptr);
      
      update_server_route(cptr, acptr, cptr, parent, linkcost, numpath);
    }
  }
  
  flush_link_announcements();
  return 0;
}
