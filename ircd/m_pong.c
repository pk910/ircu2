/*
 * IRC - Internet Relay Chat, ircd/m_pong.c
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
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
#if 0
/*
 * No need to include handlers.h here the signatures must match
 * and we don't need to force a rebuild of all the handlers everytime
 * we add a new one to the list. --Bleep
 */
#include "handlers.h"
#endif /* 0 */
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_user.h"
#include "send.h"

#include <assert.h>
#include <string.h>
#include <stdlib.h>

/*
 * ms_pong - server message handler template
 *
 * parv[0] = sender prefix
 * parv[1] = origin
 * parv[2] = destination
 */
int ms_pong(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  char*          origin;
  char*          destination;
  assert(0 != cptr);
  assert(0 != sptr);
  assert(IsServer(cptr));

  if (parc < 2 || EmptyString(parv[1])) {
#if 0
    /*
     * ignore there is nothing the server sending it can do about it
     */
    sendto_one(sptr, err_str(ERR_NOORIGIN), me.name, parv[0]);
#endif
    return 0;
  }
  origin      = parv[1];
  destination = parv[2];
  cptr->flags &= ~FLAGS_PINGSENT;
  sptr->flags &= ~FLAGS_PINGSENT;

  if (!EmptyString(destination) && 0 != ircd_strcmp(destination, me.name)) {
    struct Client* acptr;
    if ((acptr = FindClient(destination))) {
      if (MyUser(acptr))
        sendto_one(acptr, ":%s PONG %s %s", sptr->name, origin, destination);
      else
        sendto_one(acptr, "%s " TOK_PONG " %s %s", NumServ(sptr), origin, destination);
    }
  }
  return 0;
}

/*
 * mr_pong - registration message handler
 *
 * parv[0] = sender prefix
 * parv[1] = pong response echo
 * NOTE: cptr is always unregistered here
 */
int mr_pong(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  assert(0 != cptr);
  assert(cptr == sptr);
  assert(!IsRegistered(sptr));

  cptr->flags &= ~FLAGS_PINGSENT;
  /*
   * Check to see if this is a PONG :cookie reply from an
   * unregistered user.  If so, process it. -record
   */
  if (0 != sptr->cookie && COOKIE_VERIFIED != sptr->cookie) {
    if (parc > 1 && sptr->cookie == atol(parv[parc - 1])) {
      sptr->cookie = COOKIE_VERIFIED;
      if (sptr->user && *sptr->user->host && sptr->name[0])
        /*
         * NICK and USER OK
         */
        return register_user(cptr, sptr, sptr->name, sptr->user->username);
    }
    else  
      sendto_one(sptr, ":%s %d %s :To connect, type /QUOTE PONG %u",
                 me.name, ERR_BADPING, (sptr->name) ? sptr->name : "*",
                 sptr->cookie);
  }
  return 0;
}

/*
 * m_pong - normal message handler
 *
 * parv[0] = sender prefix
 * parv[1] = origin
 * parv[2] = destination
 */
int m_pong(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  assert(0 != cptr);
  assert(cptr == sptr);
  cptr->flags &= ~FLAGS_PINGSENT;
  return 0;
}


#if 0
/*
 * m_pong
 *
 * parv[0] = sender prefix
 * parv[1] = origin
 * parv[2] = destination
 */
int m_pong(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  struct Client *acptr;
  char *origin, *destination;

  if (MyUser(sptr))
    return 0;

  /* Check to see if this is a PONG :cookie reply from an
   * unregistered user.  If so, process it. -record       */

  if ((!IsRegistered(sptr)) && (sptr->cookie != 0) &&
      (sptr->cookie != COOKIE_VERIFIED) && (parc > 1))
  {
    if (atol(parv[parc - 1]) == (long)sptr->cookie)
    {
      sptr->cookie = COOKIE_VERIFIED;
      if (sptr->user && *sptr->user->host && sptr->name[0])        /* NICK and
                                                                   USER OK */
        return register_user(cptr, sptr, sptr->name, sptr->user->username);
    }
    else
      sendto_one(sptr, ":%s %d %s :To connect, type /QUOTE PONG %u",
          me.name, ERR_BADPING, sptr->name, sptr->cookie);

    return 0;
  }

  if (parc < 2 || *parv[1] == '\0')
  {
    sendto_one(sptr, err_str(ERR_NOORIGIN), me.name, parv[0]);
    return 0;
  }

  origin = parv[1];
  destination = parv[2];
  cptr->flags &= ~FLAGS_PINGSENT;
  sptr->flags &= ~FLAGS_PINGSENT;

  if (!EmptyString(destination) && 0 != ircd_strcmp(destination, me.name))
  {
    if ((acptr = FindClient(destination)))
      sendto_one(acptr, ":%s PONG %s %s", parv[0], origin, destination);
    else
    {
      sendto_one(sptr, err_str(ERR_NOSUCHSERVER),
          me.name, parv[0], destination);
      return 0;
    }
  }
#ifdef        DEBUGMODE
  else
    Debug((DEBUG_NOTICE, "PONG: %s %s",
        origin, destination ? destination : "*"));
#endif
  return 0;
}
#endif /* 0 */