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

struct Client;

#define ROUTE_INDEX_ROLLOVER 4000000000

/* broadcast & multicast routing info struct
* list of all server numerics to forward messages to when originating from the server which references this RouteInfo 
*/
struct RouteInfo {
  unsigned int is_ptrdata    :  1; /**< does route_data need to be freed */
  unsigned int is_deprecated :  1; /**< is route deprecated (needs rebuild) */
  unsigned int is_announced  :  1; /**< is route announced to client */
  unsigned int route_len     : 28; /**< number of numnicks in route_xyy */
  unsigned int route_idx     : 32; /**< incremental version index of this route */
  char         route_src      [ 2];/**< numnick of the server we received this route from */
  char        *route_data;
};

/* route list node struct
* node struct for a list of all neighbours I can see the server on (the server which references this list)
*/
struct RouteList {
  unsigned int link_islocal  :  1; /**< is a local link (server directly connected to me) */
  unsigned int link_cost     : 31; /**< total const to send to server via   */
  char link_client[2];
  char link_parent[2];
  struct RouteList *next;
};

/* macro for numnick compare with client */
#define RouteLinkNumIs(num, cli) (num[0] == cli_yxx(cli)[0] && num[1] == cli_yxx(cli)[1])
/* macro for numnick copy from client */
#define RouteLinkNumSet(num, cli) (memcpy(num, cli_yxx(cli), 2))

/* routing functions */
extern int update_server_route(struct Client *cptr, struct Client *server, struct Client *uplink, struct Client *parent, unsigned int linkcost, const char *comment);
extern void remove_uplink_routes(struct Client *uplink, const char *comment);
extern void free_server_routes(struct Client *uplink);
extern void impersonate_client(struct Client *client, struct Client *victim);

extern struct RouteInfo *build_broadcast_route(struct Client *server);
extern struct RouteInfo *build_forward_route(struct Client *uplink, struct RouteInfo *netroute, int *routehint, struct RouteInfo *outbuf);

extern void update_server_netroute(struct Client *server, struct Client *uplink, struct RouteInfo *netroute);

extern int check_forward_to_server_route(struct Client *server, struct Client *uplink);
extern int check_received_from_server_route(struct Client *server, struct Client *source);

#endif /* INCLUDED_s_routing_h */
