/*
 * IRC - Internet Relay Chat, ircd/m_part.c
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
#include "channel.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "numeric.h"
#include "numnicks.h"
#include "send.h"

#include <assert.h>
#include <string.h>

/*
 * m_part - generic message handler
 *
 * parv[0] = sender prefix
 * parv[1] = channel
 * parv[parc - 1] = comment
 */
int m_part(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Channel* chptr;
  struct Membership* member;
  char*           p = 0;
  char*           name;
  char            pbuf[BUFSIZE];
  char*           comment = (parc > 2 && !EmptyString(parv[parc - 1])) ? parv[parc - 1] : 0;

  *pbuf = '\0';                 /* Initialize the part buffer... -Kev */

  sptr->flags &= ~FLAGS_TS8;

  if (parc < 2 || parv[1][0] == '\0')
    return need_more_params(sptr, "PART");

  for (; (name = ircd_strtok(&p, parv[1], ",")); parv[1] = 0)
  {
    chptr = get_channel(sptr, name, CGT_NO_CREATE);
    if (!chptr) {
      sendto_one(sptr, err_str(ERR_NOSUCHCHANNEL), me.name, parv[0], name);
      continue;
    }
    if (*name == '&' && !MyUser(sptr))
      continue;
    /*
     * Do not use find_channel_member here: zombies must be able to part too
     */
    if (!(member = find_member_link(chptr, sptr)))
    {
      /* Normal to get when our client did a kick
       * for a remote client (who sends back a PART),
       * so check for remote client or not --Run
       */
      if (MyUser(sptr))
        sendto_one(sptr, err_str(ERR_NOTONCHANNEL), me.name, parv[0],
            chptr->chname);
      continue;
    }
    /* Recreate the /part list for sending to servers */
    if (*name != '&')
    {
      if (*pbuf)
        strcat(pbuf, ",");
      strcat(pbuf, name);
    }
    if (IsZombie(member)
        || !member_can_send_to_channel(member))  /* Returns 1 if we CAN send */
      comment = 0;
    /* Send part to all clients */
    if (!IsZombie(member))
    {
      if (comment)
        sendto_channel_butserv(chptr, sptr, PartFmt2, parv[0], chptr->chname,
                               comment);
      else
        sendto_channel_butserv(chptr, sptr, PartFmt1, parv[0], chptr->chname);
    }
    else if (MyUser(sptr))
    {
      if (comment)
        sendto_one(sptr, PartFmt2, parv[0], chptr->chname, comment);
      else
        sendto_one(sptr, PartFmt1, parv[0], chptr->chname);
    }
    remove_user_from_channel(sptr, chptr);
  }
  /* Send out the parts to all servers... -Kev */
  if (*pbuf)
  {
    if (comment)
      sendto_serv_butone(cptr, PartFmt2serv, NumNick(sptr), pbuf, comment);
    else
      sendto_serv_butone(cptr, PartFmt1serv, NumNick(sptr), pbuf);
  }
  return 0;
}

/*
 * ms_part - server message handler
 *
 * parv[0] = sender prefix
 * parv[1] = channel
 * parv[parc - 1] = comment
 */
int ms_part(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Channel* chptr;
  struct Membership* member;
  char*           p = 0;
  char*           name;
  char            pbuf[BUFSIZE];
  char*           comment = (parc > 2 && !EmptyString(parv[parc - 1])) ? parv[parc - 1] : 0;

  *pbuf = '\0';                 /* Initialize the part buffer... -Kev */

  sptr->flags &= ~FLAGS_TS8;

  if (parc < 2 || parv[1][0] == '\0')
    return need_more_params(sptr, "PART");

  for (; (name = ircd_strtok(&p, parv[1], ",")); parv[1] = 0)
  {
    chptr = get_channel(sptr, name, CGT_NO_CREATE);
    if (!chptr) {
      sendto_one(sptr, err_str(ERR_NOSUCHCHANNEL), me.name, parv[0], name);
      continue;
    }
    if (*name == '&' && !MyUser(sptr))
      continue;
    /*
     * Do not use find_channel_member here: zombies must be able to part too
     */
    if (!(member = find_member_link(chptr, sptr)))
    {
      /* Normal to get when our client did a kick
       * for a remote client (who sends back a PART),
       * so check for remote client or not --Run
       */
      if (MyUser(sptr))
        sendto_one(sptr, err_str(ERR_NOTONCHANNEL), me.name, parv[0],
            chptr->chname);
      continue;
    }
    /* Recreate the /part list for sending to servers */
    if (*name != '&')
    {
      if (*pbuf)
        strcat(pbuf, ",");
      strcat(pbuf, name);
    }
    if (IsZombie(member)
        || !member_can_send_to_channel(member))  /* Returns 1 if we CAN send */
      comment = 0;
    /* Send part to all clients */
    if (!IsZombie(member))
    {
      if (comment)
        sendto_channel_butserv(chptr, sptr, PartFmt2, parv[0], chptr->chname,
                               comment);
      else
        sendto_channel_butserv(chptr, sptr, PartFmt1, parv[0], chptr->chname);
    }
    else if (MyUser(sptr))
    {
      if (comment)
        sendto_one(sptr, PartFmt2, parv[0], chptr->chname, comment);
      else
        sendto_one(sptr, PartFmt1, parv[0], chptr->chname);
    }
    remove_user_from_channel(sptr, chptr);
  }
  /* Send out the parts to all servers... -Kev */
  if (*pbuf)
  {
    if (comment)
      sendto_serv_butone(cptr, PartFmt2serv, NumNick(sptr), pbuf, comment);
    else
      sendto_serv_butone(cptr, PartFmt1serv, NumNick(sptr), pbuf);
  }
  return 0;
}

#if 0
/*
 * m_part
 *
 * parv[0] = sender prefix
 * parv[1] = channel
 * parv[parc - 1] = comment
 */
int m_part(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  struct Channel* chptr;
  struct Membership* member;
  char*           p = 0;
  char*           name;
  char            pbuf[BUFSIZE];
  char*           comment = (parc > 2 && !EmptyString(parv[parc - 1])) ? parv[parc - 1] : 0;

  *pbuf = '\0';                 /* Initialize the part buffer... -Kev */

  sptr->flags &= ~FLAGS_TS8;

  if (parc < 2 || parv[1][0] == '\0')
    return need_more_params(sptr, "PART");

  for (; (name = ircd_strtok(&p, parv[1], ",")); parv[1] = 0)
  {
    chptr = get_channel(sptr, name, CGT_NO_CREATE);
    if (!chptr) {
      sendto_one(sptr, err_str(ERR_NOSUCHCHANNEL), me.name, parv[0], name);
      continue;
    }
    if (*name == '&' && !MyUser(sptr))
      continue;
    /*
     * Do not use find_channel_member here: zombies must be able to part too
     */
    if (!(member = find_member_link(chptr, sptr)))
    {
      /* Normal to get when our client did a kick
       * for a remote client (who sends back a PART),
       * so check for remote client or not --Run
       */
      if (MyUser(sptr))
        sendto_one(sptr, err_str(ERR_NOTONCHANNEL), me.name, parv[0],
            chptr->chname);
      continue;
    }
    /* Recreate the /part list for sending to servers */
    if (*name != '&')
    {
      if (*pbuf)
        strcat(pbuf, ",");
      strcat(pbuf, name);
    }
    if (IsZombie(member)
        || !member_can_send_to_channel(member))  /* Returns 1 if we CAN send */
      comment = 0;
    /* Send part to all clients */
    if (!IsZombie(member))
    {
      if (comment)
        sendto_channel_butserv(chptr, sptr, PartFmt2, parv[0], chptr->chname,
                               comment);
      else
        sendto_channel_butserv(chptr, sptr, PartFmt1, parv[0], chptr->chname);
    }
    else if (MyUser(sptr))
    {
      if (comment)
        sendto_one(sptr, PartFmt2, parv[0], chptr->chname, comment);
      else
        sendto_one(sptr, PartFmt1, parv[0], chptr->chname);
    }
    remove_user_from_channel(sptr, chptr);
  }
  /* Send out the parts to all servers... -Kev */
  if (*pbuf)
  {
    if (comment)
      sendto_serv_butone(cptr, PartFmt2serv, NumNick(sptr), pbuf, comment);
    else
      sendto_serv_butone(cptr, PartFmt1serv, NumNick(sptr), pbuf);
  }
  return 0;
}
#endif /* 0 */