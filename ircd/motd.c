/*
 * IRC - Internet Relay Chat, ircd/motd.c
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
 * Copyright (C) 2000 Kevin L. Mitchell <klmitch@mit.edu>
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
#include "motd.h"
#include "class.h"
#include "client.h"
#include "fileio.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "match.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_conf.h"
#include "s_debug.h"
#include "s_user.h"
#include "send.h"

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static struct {
  struct Motd*	local;
  struct Motd*	remote;
  struct Motd*	other;
  struct Motd*	freelist;
} MotdList;

/* Create a struct Motd and initialize it */
static struct Motd *
motd_create(const char *hostmask, const char *path, int maxcount)
{
  struct Motd* tmp;
  int type = MOTD_UNIVERSAL;
  const char* s;

  assert(0 != path);

  if (hostmask) { /* figure out if it's a class or hostmask */
    type = MOTD_CLASS; /* all digits, convert to class */

    for (s = hostmask; *s; s++)
      if (!IsDigit(*s)) { /* not a digit, not a class... */
	type = MOTD_HOSTMASK;
	break;
      }
  }

  /* allocate memory and initialize the structure */
  if (MotdList.freelist) {
    tmp = MotdList.freelist;
    MotdList.freelist = tmp->next;
  } else
    tmp = (struct Motd *)MyMalloc(sizeof(struct Motd));

  tmp->next = 0;
  tmp->type = type;

  switch (type) {
  case MOTD_HOSTMASK:
    DupString(tmp->id.hostmask, hostmask);
    break;

  case MOTD_CLASS:
    tmp->id.class = atoi(hostmask);
    break;
  }

  DupString(tmp->path, path);
  tmp->maxcount = maxcount;
  tmp->cache = 0;

  return tmp;
}

/* This function reads a motd out of a file (if needed) and caches it */
static struct MotdCache *
motd_cache(struct Motd *motd)
{
  FBFILE*		file;
  struct MotdCache*	cache;
  struct stat		sb;
  char			line[MOTD_LINESIZE + 2]; /* \r\n */
  char*			tmp;
  int			i;

  assert(0 != motd);
  assert(0 != motd->path);

  if (motd->cache)
    return motd->cache;

  /* gotta read in the file, now */
  if (!(file = fbopen(motd->path, "r"))) {
    Debug((DEBUG_ERROR, "Couldn't open \"%s\": %s", motd->path,
	   strerror(errno)));
    return 0;
  }

  /* need the file's modification time */
  if (-1 == fbstat(&sb, file)) {
    fbclose(file);
    return 0;
  }

  /* Ok, allocate a structure; we'll realloc later to trim memory */
  cache = (struct MotdCache *)MyMalloc(sizeof(struct MotdCache) +
				       (MOTD_LINESIZE * (MOTD_MAXLINES - 1)));

  cache->modtime = *localtime((time_t *) &sb.st_mtime); /* store modtime */

  cache->count = 0;
  while (cache->count < motd->maxcount && fbgets(line, sizeof(line), file)) {
    /* copy over line, stopping when we overflow or hit line end */
    for (tmp = line, i = 0;
	 i < (MOTD_LINESIZE - 1) && *tmp && *tmp != '\r' && *tmp != '\n';
	 tmp++, i++)
      cache->motd[cache->count][i] = *tmp;
    cache->motd[cache->count][i] = '\0';

    cache->count++;
  }

  fbclose(file); /* close the file */

  /* trim memory usage a little */
  motd->cache = (struct MotdCache *)MyRealloc(cache, sizeof(struct MotdCache) +
					      (MOTD_LINESIZE *
					       (cache->count - 1)));

  return motd->cache;
}

static void
motd_decache(struct Motd *motd)
{
  struct MotdCache* cache;

  assert(0 != motd);

  if (!(cache = motd->cache)) /* we can be called for records with no cache */
    return;

  motd->cache = 0; /* zero the cache */

  MyFree(cache); /* very simple for a reason... */
}

/* This function destroys a struct Motd, destroying the cache if needed */
static void
motd_destroy(struct Motd *motd)
{
  assert(0 != motd);

  MyFree(motd->path); /* we always must have a path */
  if (motd->type == MOTD_HOSTMASK) /* free a host mask if any */
    MyFree(motd->id.hostmask);
  if (motd->cache) /* drop the cache */
    motd_decache(motd);

  motd->next = MotdList.freelist;
  MotdList.freelist = motd;
}

/* We use this routine to look up the struct Motd to send to any given
 * user.
 */
static struct Motd *
motd_lookup(struct Client *cptr)
{
  struct Motd *ptr;
  int class = -1;

  assert(0 != cptr);

  if (!MyUser(cptr)) /* not my user, always return remote motd */
    return MotdList.remote;

  class = get_client_class(cptr);

  /* check the T-lines first */
  for (ptr = MotdList.other; ptr; ptr = ptr->next) {
    if (ptr->type == MOTD_CLASS && ptr->id.class == class)
      return ptr;
    else if (ptr->type == MOTD_HOSTMASK &&
	     !match(ptr->id.hostmask, cli_sockhost(cptr)))
      return ptr;
  }

  return MotdList.local; /* Ok, return the default motd */
}

/* Here is a routine that takes a MotdCache and sends it to a user */
static int
motd_forward(struct Client *cptr, struct MotdCache *cache)
{
  int i;

  assert(0 != cptr);

  if (!cache) /* no motd to send */
    return send_reply(cptr, ERR_NOMOTD);

  /* send the motd */
  send_reply(cptr, RPL_MOTDSTART, cli_name(&me));
  send_reply(cptr, SND_EXPLICIT | RPL_MOTD, ":- %d-%d-%d %d:%02d",
	     cache->modtime.tm_year + 1900, cache->modtime.tm_mon + 1,
	     cache->modtime.tm_mday, cache->modtime.tm_hour,
	     cache->modtime.tm_min);

  for (i = 0; i < cache->count; i++)
    send_reply(cptr, RPL_MOTD, cache->motd[i]);

  return send_reply(cptr, RPL_ENDOFMOTD); /* end */
}

/* This routine is used to send the MOTD off to a user. */
int
motd_send(struct Client* cptr)
{
  assert(0 != cptr);

  return motd_forward(cptr, motd_cache(motd_lookup(cptr)));
}

/* This routine sends the MOTD or something to newly-registered users. */
void
motd_signon(struct Client* cptr)
{
  struct MotdCache *cache;

  cache = motd_cache(motd_lookup(cptr));

#ifdef NODEFAULTMOTD
  send_reply(cptr, RPL_MOTDSTART, cli_name(&me));
  send_reply(cptr, SND_EXPLICIT | RPL_MOTD, ":\002Type /MOTD to read the AUP "
	     "before continuing using this service.\002");
  send_reply(cptr, SND_EXPLICIT | RPL_MOTD, ":The message of the day was last "
	     "changed: %d-%d-%d %d:%d", cache->modtime.tm_year + 1900,
	     cache->modtime.tm_mon + 1, cache->modtime.tm_mday,
	     cache->modtime.tm_hour, cache->modtime.tm_min);
  send_reply(cptr, RPL_ENDOFMOTD);
#else
  motd_forward(cptr, cache);
#endif
}

/* motd_recache causes all the MOTD caches to be cleared */
void
motd_recache(void)
{
  struct Motd* tmp;

  motd_decache(MotdList.local); /* decache local and remote MOTDs */
  motd_decache(MotdList.remote);

  for (tmp = MotdList.other; tmp; tmp = tmp->next) /* now all the others */
    motd_decache(tmp);

  /* now recache local and remote MOTDs */
  motd_cache(MotdList.local);
  motd_cache(MotdList.remote);
}

/* motd_init initializes the MOTD routines, including reading the
 * ircd.motd and remote.motd files into cache
 */
void
motd_init(void)
{
  MotdList.local = motd_create(0, MPATH, MOTD_MAXLINES); /* init local */
  motd_cache(MotdList.local); /* and cache it */

  MotdList.remote = motd_create(0, RPATH, MOTD_MAXREMOTE); /* init remote */
  motd_cache(MotdList.remote); /* and cache it */

  MotdList.other = 0; /* no T-lines processed yet */
}

/* This routine adds a MOTD */
void
motd_add(const char *hostmask, const char *path)
{
  struct Motd *tmp;

  tmp = motd_create(hostmask, path, MOTD_MAXLINES); /* create the motd */

  tmp->next = MotdList.other; /* link it into the list */
  MotdList.other = tmp;
}

/* This routine clears the list of MOTDs */
void
motd_clear(void)
{
  struct Motd *ptr, *next;

  motd_decache(MotdList.local); /* decache local and remote MOTDs */
  motd_decache(MotdList.remote);

  if (MotdList.other) /* destroy other MOTDs */
    for (ptr = MotdList.other; ptr; ptr = next) {
      next = ptr->next;
      motd_destroy(ptr);
    }

  MotdList.other = 0;

  /* now recache local and remote MOTDs */
  motd_cache(MotdList.local);
  motd_cache(MotdList.remote);
}

/* This is called to report T-lines */
void
motd_report(struct Client *to)
{
  struct Motd *ptr;

  for (ptr = MotdList.other; ptr; ptr = ptr->next) {
    if (ptr->type == MOTD_CLASS) /* class requires special handling */
      send_reply(to, SND_EXPLICIT | RPL_STATSTLINE, "T %d %s", ptr->id.class,
		 ptr->path);
    else if (ptr->type == MOTD_HOSTMASK)
      send_reply(to, RPL_STATSTLINE, 'T', ptr->id.hostmask, ptr->path);
  }
}