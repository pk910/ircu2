/*
 * IRC - Internet Relay Chat, ircd/s_routing.c
 * Copyright (C) 2019 Philipp Kreil
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
 */
/** @file
 * @brief Message routing functions.
 * @version $Id$
 */
#include "config.h"

#include "s_routing.h"
#include "channel.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_log.h"
#include "ircd_string.h"
#include "ircd_snprintf.h"
#include "ircd_crypt.h"
#include "list.h"
#include "match.h"
#include "msg.h"
#include "msgq.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_bsd.h"
#include "send.h"
#include "struct.h"
#include "sys.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <stdlib.h>
#include <string.h>

// own route version index counter
static int build_router_version_counter = 1;

// static buffer for route builder
static char build_route_buf[(NN_MAX_SERVER*2)+1];
static int build_route_buflen;

// internal function declarations
static void update_server_parent(struct Client *server);
static void update_downlink_hopcount_recursive(struct Client *downlink, unsigned int hopcount);
static void deprecate_broadcast_routes();
static void update_server_uplink(struct Client *server, struct Client *new_uplink);
static void update_client_connection_recursive(struct Client *server, struct Client *uplink);
static void remove_uplink_routes_recursive(struct Client *uplink, struct Client *client, const char *comment);
static void free_routeinfo(struct RouteInfo *routeinfo);
static void build_route_recursive(struct Client *server, struct RouteInfo *netroute, int *routehint_ptr);
static void announce_server_route(struct Client *client, struct Client *server, struct RouteInfo *routeinfo);

/** Handle link announcement from uplink for server.
 * 
 * @param server The client which is announced in the announcement
 * @param uplink The client which sent the announcement to us
 * @param parent The parent server which is directly connected to the client
 * @param linkcost The cost to send data to server via uplink
 * @return 1 if the update changed something on the primary uplink (update should be propagated)
 *         0 otherwise
 */
int update_server_route(struct Client *server, struct Client *uplink, struct Client *parent, unsigned int linkcost) {
  struct RouteLinkInfo *cnode, *link_node = NULL, *prev_node = NULL, *link_prev = NULL, *cost_prev = NULL;
  //struct Client *cfrom;
  int is_local_route = (server == uplink);  // is the updated route a local route?
  int is_lowest_cost = 0; // is the updated route the best one?
  int new_lowest_link = 0; // has the lowest link to the server changed?
  int do_reinsert_route = 0; // need to remove (if existing) and reinsert (if not a de-announcement) route to routes list (ensuring list order)
  int do_reparent_server = 0; // need to reparent the server in the local server link tree
  assert(0 != cli_serv(server));
  assert(0 != cli_local(uplink) || 0 == parent);
  
  if(is_local_route)
    is_lowest_cost = 1;
  if(!parent)
    do_reinsert_route = 1;
  
  //if(!cli_serv(server)->routes || !(cfrom = FindNServer(cli_serv(server)->routes->link_client)))
  //  cfrom = cli_from(server);
  
  // search existing link and determinate new position in sorted list
  for(cnode = cli_serv(server)->routes; cnode; cnode = cnode->next) {
    
    if(!(is_lowest_cost || cost_prev || !parent) && (
      cnode->link_cost > linkcost
    )) { // current entry has higher cost, so need to insert this route before
      if(prev_node)
        cost_prev = prev_node;
      else
        is_lowest_cost = 1;
    }
    
    if(RouteLinkNumIs(cnode->link_client, uplink)) {
      // found existing route for this uplink
      link_node = cnode;
      link_prev = prev_node;
      
      if(!parent)
        // de-announcement - we just had to find the node in the list, no need to update
        break;
      
      // check if route position is still ok, or if we need to reorder the list
      if(cnode->link_cost != linkcost) {
        cnode->link_cost = linkcost; // cost changed - now check if list position is still acceptable
        
        if(linkcost < cnode->link_cost && prev_node && 
          (prev_node->link_cost > linkcost && (!prev_node->link_islocal || is_local_route))
        ) // linkcost decreased and previous node has higher cost now, so we need to reorder
          do_reinsert_route = 1;
        
        else if(linkcost > cnode->link_cost && cnode->next && (cnode->next->link_cost < linkcost && (!is_local_route || cnode->next->link_islocal)))
          // linkcost increased and next node has lower cost, so we need to reorder
          do_reinsert_route = 1;
      }
      
      // check if parent server changed
      if(!RouteLinkNumIs(cnode->link_parent, parent)) {
        // set new parent in route
        RouteLinkNumSet(cnode->link_parent, parent);
        
        if(!prev_node) // this is the primary link, so we need to reparent the server in the local link tree
          do_reparent_server = 1;
      }
      
      if(!do_reinsert_route && !do_reparent_server)
        return 0; // no structural update - just return here
    }
    else
      prev_node = cnode;
  }
  
  if(!cnode) {
    if(!parent) // de-announcement for a link we don't even know about
      return 0;
    
    // create new link node
    cnode = (struct RouteLinkInfo*) MyCalloc(1, sizeof(*cnode));
    cnode->link_islocal = is_local_route ? 1 : 0;
    cnode->link_cost = linkcost;
    RouteLinkNumSet(cnode->link_client, uplink);
    RouteLinkNumSet(cnode->link_parent, parent);
  }
  else if(do_reinsert_route) {
    // remove link node from list
    if(link_prev)
      link_prev->next = cnode->next;
    else {
      new_lowest_link = 1;
      cli_serv(server)->routes = cnode->next;
    }
  }
  
  if(!parent) {
    // de-announcement of a link - free route node
    MyFree(cnode);
    cnode = NULL;
  }
  else {
    if(!cost_prev && !is_lowest_cost) {
      if(prev_node && (!is_local_route || prev_node->link_islocal))
        // the worst route for this server
        cost_prev = prev_node;
      else
        // the first route for this server
        is_lowest_cost = 1;
    }
    // insert link node to list (sorted by link cost)
    if(is_lowest_cost) {
      new_lowest_link = 1;
      cnode->next = cli_serv(server)->routes;
      cli_serv(server)->routes = cnode;
    }
    else {
      cnode->next = cost_prev->next;
      cost_prev->next = cnode;
    }
  }
  
  if((cnode = cli_serv(server)->routes)) {
    // update position in local server tree if needed
    if(do_reparent_server || new_lowest_link)
      update_server_parent(server);
    
    if(new_lowest_link) {
      // update primary uplink if needed
      if(RouteLinkNumIs(cnode->link_client, uplink) || (uplink = FindNServer(cnode->link_client)))
        update_server_uplink(server, uplink);
      
      // set new link parameters
      cli_linkcost(server) = cnode->link_cost;
      
      // mark broadcast routes as deprecated
      deprecate_broadcast_routes();
      
      return 1;
    }
  }
  return 0;
}

void remove_uplink_routes(struct Client *uplink, const char *comment) {
  struct DLink *link, *nextlink;
  
  remove_uplink_routes_recursive(&me, uplink, comment);
  
  if(update_server_route(uplink, uplink, NULL, 0)) {
    sendcmdto_neighbours_buttwo(&me, CMD_LINKCHANGE, uplink, cli_from(uplink), "%C %C %u", uplink, cli_serv(uplink)->up, cli_linkcost(uplink));
    sendcmdto_one(&me, CMD_LINKCHANGE, cli_from(uplink), "%C %C - :%s", uplink, cli_serv(uplink)->up, comment);
  }
}

static void remove_uplink_routes_recursive(struct Client *uplink, struct Client *client, const char *comment) {
  struct DLink *link, *nextlink;
  struct Client *lncli;
  
  // loop through all servers and remove uplink route if set
  for (link = cli_serv(client)->down; link; link = nextlink) {
    lncli = link->value.cptr;
    nextlink = link->next;
    
    // recursively remove from downlinks first
    remove_uplink_routes_recursive(uplink, lncli, comment);
    
    /* remove uplink route (parent = NULL)
     * this may change the position of lncli in the server link tree,
     * so it could be that it is no longer a downlink of `uplink`
     */
    if(update_server_route(lncli, uplink, NULL, 0)) {
      sendcmdto_neighbours_buttwo(&me, CMD_LINKCHANGE, uplink, cli_from(lncli), "%C %C %u", lncli, cli_serv(lncli)->up, cli_linkcost(lncli));
      sendcmdto_one(&me, CMD_LINKCHANGE, cli_from(lncli), "%C %C - :%s", lncli, cli_serv(lncli)->up, comment);
    }
  }
}

void free_server_routes(struct Client *uplink) {
  struct RouteLinkInfo *link, *next_link;
  for(link = cli_serv(uplink)->routes; link; link = next_link) {
    next_link = link->next;
    MyFree(link);
  }
  cli_serv(uplink)->routes = NULL;
  
  if(cli_serv(uplink)->fwd_route) {
    free_routeinfo(cli_serv(uplink)->fwd_route);
    cli_serv(uplink)->fwd_route = NULL;
  }
  if(cli_serv(uplink)->own_route) {
    free_routeinfo(cli_serv(uplink)->own_route);
    cli_serv(uplink)->own_route = NULL;
  }
}

static void update_server_parent(struct Client *server) {
  struct Client *old_parent = cli_serv(server)->up;
  struct Client *new_parent = FindNServer(cli_serv(server)->routes->link_parent);
  
  if(!old_parent || !new_parent || old_parent == new_parent)
    return;
  
  /* Remove downlink list node from old parent server */
  remove_dlink(&(cli_serv(old_parent)->down), cli_serv(server)->updown);
  
  /* Add downlink list node to new parent server */
  cli_serv(server)->updown = add_dlink(&(cli_serv(new_parent))->down, server);
  cli_serv(server)->up = new_parent;
  
  update_downlink_hopcount_recursive(server, cli_hopcount(new_parent) + 1);
}

static void update_downlink_hopcount_recursive(struct Client *downlink, unsigned int hopcount) {
  struct DLink *link;
  
  // update client hopcount
  cli_hopcount(downlink) = hopcount;
  
  // mark own broadcast route as deprecated
  if(cli_serv(downlink)->own_route)
    cli_serv(downlink)->own_route->is_deprecated = 1;
  
  // loop through all downlinks
  for (link = cli_serv(downlink)->down; link; link = link->next)
    update_downlink_hopcount_recursive(link->value.cptr, hopcount + 1);
}

static void deprecate_broadcast_routes() {
  struct DLink *link;
  struct Client *lncli;
  
  // loop through all local downlinks
  for (link = cli_serv(&me)->down; link; link = link->next) {
    lncli = link->value.cptr;
    if(cli_serv(lncli)->own_route)
      cli_serv(lncli)->own_route->is_deprecated = 1;
  }
}

void impersonate_client(struct Client *client, struct Client *victim) {
  assert(0 != cli_local(client));
  
  if(cli_local(victim)) {
    // close victim connection first
    close_connection(victim);
    ClrFlag(victim, FLAG_DEADSOCKET);
  }
  
  // update cli_connect references
  LocalClientArray[cli_fd(client)] = victim;
  update_client_connection_recursive(victim, client);
  cli_from(victim) = victim;
  cli_status(client) = STAT_UNKNOWN;
  
  // mark as impersonating 
  // this will make the packet read loop breaking after this message 
  // and restarts in next event loop with proper client pointer
  cli_connect(client)->con_impcli = victim;
  SetFlag(client, FLAG_IMPERSONATING);
}

static void update_server_uplink(struct Client *server, struct Client *new_uplink) {
  struct DLink *link;
  struct Client *lncli;
  struct Client **acptrp;
  int i;
  if(cli_connect(new_uplink) == cli_connect(server))
    return;

  if(IsServer(server) && cli_local(server)) {
    /* Lost direct connection to the server. 
      We want to keep the Client alive as it is still reachable via another link,
      therefore we have to free the Connection struct ourselve here. */
    close_connection(server);
    cli_from(server) = 0;
    ClrFlag(server, FLAG_DEADSOCKET);
  }
  
  /* Set uplink connection */
  update_client_connection_recursive(server, new_uplink);
}

static void update_client_connection_recursive(struct Client *server, struct Client *uplink) {
  struct DLink *link;
  struct Client **acptrp;
  int i;
  
  // update connection of server
  cli_connect(server) = cli_connect(uplink);
  
  // loop through all downlinks
  for (link = cli_serv(server)->down; link; link = link->next) {
    update_client_connection_recursive(link->value.cptr, uplink);
  }
  // loop through all clients of server
  acptrp = cli_serv(server)->client_list;
  for (i = 0; i <= cli_serv(server)->nn_mask; ++acptrp, ++i) {
    if (*acptrp)
      cli_connect(*acptrp) = cli_connect(uplink);
  }
}

static void free_routeinfo(struct RouteInfo *routeinfo) {
  if(routeinfo->is_ptrdata)
    MyFree(routeinfo->route_data);
  MyFree(routeinfo);
}

struct RouteInfo *build_broadcast_route(struct Client *server) {
  struct RouteInfo *routeinfo;
  
  build_route_buflen = 0;
  build_route_recursive(server, NULL, NULL);
  build_route_buf[build_route_buflen] = 0;
  
  if(cli_serv(server)->own_route)
    MyFree(cli_serv(server)->own_route);
  
  routeinfo = MyCalloc(1, sizeof(struct RouteInfo));
  routeinfo->route_len = build_route_buflen / 2;
  routeinfo->route_idx = build_router_version_counter++;
  
  routeinfo->route_data = MyMalloc(build_route_buflen+1);
  routeinfo->is_ptrdata = 1;
  memcpy(routeinfo->route_data, build_route_buf, build_route_buflen+1);
  
  return cli_serv(server)->own_route = routeinfo;
}

struct RouteInfo *build_forward_route(struct Client *uplink, struct RouteInfo *netroute, int *routehint, struct RouteInfo *outbuf) {
  struct RouteInfo *routeinfo;
  
  int rthint = 0;
  if(!routehint)
    routehint = &rthint;
  
  /* build relevant netroute part to forward via this uplink according to the netroute */
  build_route_buflen = 0;
  build_route_recursive(uplink, netroute, routehint);
  build_route_buf[build_route_buflen] = 0;
  
  routeinfo = outbuf ? outbuf : MyCalloc(1, sizeof(struct RouteInfo));
  routeinfo->route_idx = netroute->route_idx;
  routeinfo->route_len = build_route_buflen / 2;
  routeinfo->route_data = build_route_buf;
  return routeinfo;
}

static void build_route_recursive(struct Client *server, struct RouteInfo *netroute, int *routehint_ptr) {
  struct DLink *link;
  struct Client *lncli;
  int rtidx = 0, rtfound = 1;
  int routestrlen = (netroute ? (netroute->route_len * 2) : 0);
  int routehint;
  
  if(routehint_ptr) {
    routehint = *routehint_ptr;
    if(routehint < 0 || routehint >= routestrlen)
      routehint = 0;
  }
  else
    routehint = 0;
  
  // add all down links
  for (link = cli_serv(server)->down; link; link = link->next) {
    lncli = link->value.cptr;
    
    if(netroute) {
      rtfound = 0;
      for(rtidx = routehint; rtidx < routestrlen; rtidx += 2) {
        if(RouteLinkNumIs((netroute->route_data + rtidx), lncli)) {
          rtfound = 1;
          break;
        }
      }
      if(!rtfound && routehint > 0) {
        for(rtidx = 0; rtidx < routehint; rtidx += 2) {
          if(RouteLinkNumIs((netroute->route_data + rtidx), lncli)) {
            rtfound = 1;
            break;
          }
        }
      }
    }
    
    if(rtfound) {
      // add link numeric to buffer
      build_route_buf[build_route_buflen++] = lncli->cli_yxx[0];
      build_route_buf[build_route_buflen++] = lncli->cli_yxx[1];
      
      if(routehint_ptr)
        *routehint_ptr = rtidx+2;
      
      // add all down links of down links
      build_route_recursive(link->value.cptr, netroute, routehint_ptr);
    }
  }
}

void update_server_netroute(struct Client *server, struct Client *uplink, struct RouteInfo *netroute) {
  struct DLink *link;
  struct Client *lncli;
  int rtidx, rtfound, rthint = 0;
  struct RouteInfo *subroute;
  struct RouteInfo routebuf;
  unsigned int routelen = netroute->route_len * 2;
  
  if(routelen > 0) {
    memset(&routebuf, 0, sizeof(struct RouteInfo));
    routebuf.route_idx = netroute->route_idx;
    
    /* forward the route to our down links if they're part of the netroute */
    for (link = cli_serv(&me)->down; link; link = link->next) {
      lncli = link->value.cptr;
      if(lncli == uplink)
        continue;
      
      rtfound = 0;
      if(rthint > routelen)
        rthint = routelen;
      for(rtidx = rthint; rtidx < routelen; rtidx += 2) {
        if(RouteLinkNumIs((netroute->route_data + rtidx), lncli)) {
          rtfound = 1;
          break;
        }
      }
      if(!rtfound && rthint > 0) {
        for(rtidx = 0; rtidx < rthint; rtidx += 2) {
          if(RouteLinkNumIs((netroute->route_data + rtidx), lncli)) {
            rtfound = 1;
            break;
          }
        }
      }
      
      if(rtfound) {
        rthint = rtidx + 2;
        subroute = build_forward_route(lncli, netroute, &rthint, &routebuf);
      }
      else {
        if(check_forward_to_server(server, lncli)) {
          subroute = &routebuf;
          subroute->route_len = 0;
        }
        else
          subroute = NULL;
      }
      
      if(subroute)
        announce_server_route(lncli, server, subroute);
    }
  }
  
  // store the new route for server
  if(cli_serv(server)->fwd_route)
    free_routeinfo(cli_serv(server)->fwd_route);
  cli_serv(server)->fwd_route = netroute;
}

int check_forward_to_server(struct Client *server, struct Client *uplink) {
  if(IsUser(server))
    server = cli_user(server)->server;
  
  if(!cli_serv(server)->fwd_route)
    return 1;
  if(cli_serv(server)->fwd_route->route_len == 0)
    return 0;
  
  const char *netroute = cli_serv(server)->fwd_route->route_data;
  int i;
  
  for(i = 0; netroute[i]; i+=2) {
    if(RouteLinkNumIs((netroute + i), uplink))
      return 1;
  }
  return 0;
}

void ensure_route_announced(struct Client *server) {
  struct RouteInfo *routeinfo;
  
  assert(0 != server);
  if(!cli_serv(server))
    return;
  
  if(!(routeinfo = cli_serv(server)->own_route) || cli_serv(server)->own_route->is_deprecated)
    routeinfo = build_broadcast_route(server);
  
  if(routeinfo && !routeinfo->is_announced) {
    routeinfo->is_announced = 1;
    announce_server_route(server, &me, routeinfo);
  }
}

static void announce_server_route(struct Client *client, struct Client *server, struct RouteInfo *routeinfo) {
  unsigned int routepos, routelen;
  unsigned int routestrlen;
  
  if(routeinfo->route_len == 0) {
    // empty route
    sendcmdto_prio_one(server, CMD_NETROUTE, client, "%u 0", routeinfo->route_idx);
    return;
  }
  
  // send in chunks if too long
  routepos = 0;
  routestrlen = routeinfo->route_len * 2;
  do {
    if((routelen = routestrlen - routepos) > BUFSIZE - 30)
      routelen = BUFSIZE - 30; // leave some space for header
    
    if(routepos == 0)
      sendcmdto_prio_one(server, CMD_NETROUTE, client, "%u %u %.*s", routeinfo->route_idx, routeinfo->route_len, routelen, routeinfo->route_data);
    else
      sendcmdto_prio_one(server, CMD_NETROUTE, client, "%u + %.*s", routeinfo->route_idx, routelen, routeinfo->route_data + routepos);
    
    routepos += routelen;
  } while(routepos < routestrlen);
}
