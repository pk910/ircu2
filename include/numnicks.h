/*
 * IRC - Internet Relay Chat, include/h.h
 * Copyright (C) 1996 - 1997 Carlo Wood
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
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
 * @brief Interface for numeric nickname functions.
 * @version $Id$
 */
#ifndef INCLUDED_numnicks_h
#define INCLUDED_numnicks_h
#ifndef INCLUDED_client_h
#include "client.h"
#endif
#ifndef INCLUDED_sys_types_h
#include <sys/types.h>
#define INCLUDED_sys_types_h
#endif

/*
 * General defines
 */
/* These must be the same on ALL servers ! Do not change ! */

/** Number of bits encoded in one numnick character. */
#define NUMNICKLOG 6
/** Bitmask to select value of next numnick character. */
#define NUMNICKMASK 63          /* (NUMNICKBASE-1) */
/** Number of servers representable in a numnick. */
#define NN_MAX_SERVER 4096      /* (NUMNICKBASE * NUMNICKBASE) */
/** Number of clients representable in a numnick. */
#define NN_MAX_CLIENT 262144    /* NUMNICKBASE ^ 3 */

/*
 * used for buffer size calculations in channel.c
 */
/** Maximum length of a full user numnick. */
#define NUMNICKLEN 5            /* strlen("YYXXX") */

/*
 * Macros
 */

/** Provide format string arguments for a user's numnick.
 * Use this macro as follows: sprintf(buf, "%s%s ...", NumNick(cptr), ...);
 */
#define NumNick(c) cli_yxx((cli_user(c))->server), cli_yxx(c)

/** Provide format string arguments for a server's numnick.
 * Use this macro as follows: sprintf(buf, "%s ...", NumServ(cptr), ...);
 */
#define NumServ(c) cli_yxx(c)

/** Provide format string arguments for a server's capacity mask.
 * Use this macro as follows: sprintf(buf, "%s%s ...", NumServCap(cptr), ...);
 */
#define NumServCap(c) cli_yxx(c), (cli_serv(c))->nn_capacity

/*
 * Structures
 */
struct Client;

/*
 * Proto types
 */
extern void SetRemoteNumNick(struct Client* cptr, const char* yxx);
extern int  SetLocalNumNick(struct Client* cptr);
extern void RemoveYXXClient(struct Client* server, const char* yxx);
extern void RegisterYXXClient(struct Client* acptr);
extern void SetServerYXX(struct Client* cptr, 
                         struct Client* server, const char* yxx);
extern void ClearServerYXX(const struct Client* server);

extern void SetYXXCapacity(struct Client* myself, unsigned int max_clients);
extern void SetYXXServerName(struct Client* myself, unsigned int numeric);

extern int            markMatchexServer(const char* cmask, int minlen);
extern struct Client* find_match_server(char* mask);
extern struct Client* findNUser(const char* yxx);
extern struct Client* FindNServer(const char* numeric);

extern unsigned int   base64toint(const char* str);
extern const char*    inttobase64(char* buf, unsigned int v, unsigned int count);
extern const char* iptobase64(char* buf, const struct irc_in_addr* addr, unsigned int count, int v6_ok);
extern void base64toip(const char* s, struct irc_in_addr* addr);

#endif /* INCLUDED_numnicks_h */

