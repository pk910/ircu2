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
 * parv[1] = target server
 * parv[2] = parent uplink of server
 * parv[3] = link cost or '-'
 * parv[parc-1] = comment if link cost = '-'
 */
int ms_linkchange(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  if(parc < 4)
    return need_more_params(sptr, "LINKCHANGE");
  
  struct Client* acptr;
  if(!(acptr = FindNServer(parv[1])))
    return 0;
  
  struct Client* parent;
  if(!(parent = FindNServer(parv[2])))
    return send_reply(sptr, ERR_NOSUCHNICK, parv[2]);
  
  unsigned int linkcost;
  const char *comment;
  if(*parv[3] == '-') {
    // link de-announced
    linkcost = 0;
    if(parc > 4)
      comment = parv[4];
    else
      comment = "lost uplink";
  }
  else {
    linkcost = atoi(parv[3]);
    linkcost += cli_linkcost(cptr);
    comment = "routing failed";
  }
  
  if(update_server_route(acptr, cptr, (linkcost ? parent : NULL), linkcost))
    sendcmdto_neighbours_butone(&me, CMD_LINKCHANGE, cptr, "%C %C %u", acptr, cli_serv(acptr)->up, cli_linkcost(acptr));
  else if(!cli_serv(acptr)->routes)
    exit_client(cptr, acptr, parent, comment);
  
  return 0;
}
