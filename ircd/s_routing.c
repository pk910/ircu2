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
#include "s_debug.h"
#include "s_misc.h"
#include "send.h"
#include "struct.h"
#include "sys.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// own route version index counter
static int build_router_version_counter = 1;

// static buffer for route builder
static char build_route_buf[(NN_MAX_SERVER*2)+1];
static int build_route_buflen;

// internal function declarations
static void update_server_parent(struct Client *server);
static void update_server_parent_recursive(struct Client *downlink, unsigned int hopcount);
static void update_server_uplink(struct Client *server);
static void update_server_uplink_recursive(struct Client *server, struct Client *uplink);
static void deprecate_own_server_routes();
static void remove_uplink_routes_recursive(struct LinkAnnounceDst **lnabuf, struct Client *uplink, struct Client *client, unsigned int linkcost);
static void free_routeinfo(struct RouteInfo *routeinfo);
static void build_route_recursive(struct Client *server, struct RouteInfo *netroute, int *routehint_ptr);
static void announce_server_route(struct Client *client, struct Client *server, struct RouteInfo *routeinfo);

/** Handle link announcement from uplink for and remember as route.
 *
 * Routes is a list of all paths to server from my point of view in the network.
 *
 * Each entry in the list represents a local client that can be used to reach server.
 * The list is ordered by linkcost so the best route should always be the first.
 *
 * Unfortunately there are big problems when a locally connected server gets a better link
 * via a remote uplink (think about PINGs and other stuff which is handled per connection) so
 * we ensure that entries via local uplinks are always at the top even if there is a better
 * route available via another server.
 *
 * @param cptr The client we're receiving the announcement on
 * @param server The client which is got announced
 * @param uplink The local client we're receiving the announcement from
 * @param parent The client which is announced to be directly connected to `server`
 *               or null if link to `server` via `uplink` is denounced
 * @param linkcost The cost to send to `server` via `uplink`
 * @param comment The reason for the denouncement or numeric path if announcement
 * @return 1 if the update changed something and forwarded the update to our neighbours
           2 if the update changed something and no more uplink route present for server
 *         0 otherwise
 */
int update_server_route(struct LinkAnnounceDst **lnabuf, struct Client *cptr, struct Client *server, struct Client *uplink, struct Client *parent, unsigned int linkcost) {
  struct RouteList *cnode, *link_node = NULL, *prev_node = NULL, *link_prev = NULL, *cost_prev = NULL;
  int is_local_route = (server == uplink);  // is the updated route a local route?
  int is_lowest_cost = 0; // is this route the best one?
  int new_lowest_link = 0; // has the lowest link to the server changed?
  int do_reinsert_route = 0; // need to remove (if existing) and reinsert (if not denounced) route to routes list (ensuring list order)
  int do_reparent_server = 0; // need to reparent the server in the local server link tree
  int route_count = 0;
  int forward_advertisement = 0; // do we have forwarded this update to our neighbours?
  int forward_loopadvert = 0; // do we have forwarded this loop route to our neighbours?
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
    route_count++;
    
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
        // denounced - we just had to find the route entry in the list, no need to update
        continue;
        
      // update our information about the route
      if(cnode->link_cost != linkcost) {
        cnode->link_cost = linkcost; // cost changed
        
        // ensure propagation if primary link cost changed
        if(!prev_node)
          new_lowest_link = 1;
        
        // check if route position in ordered list is still ok, or if we need to reorder
        if(linkcost < cnode->link_cost && prev_node && 
          (prev_node->link_cost > linkcost && (!prev_node->link_islocal || is_local_route))
        ) // linkcost decreased and previous node has higher cost now, so we need to reorder
          do_reinsert_route = 1;
        else if(linkcost > cnode->link_cost && cnode->next && 
          (cnode->next->link_cost < linkcost && (!is_local_route || cnode->next->link_islocal))
        ) // linkcost increased and next node has lower cost, so we need to reorder
          do_reinsert_route = 1;
      }
      
      // check if parent of server in route changed
      if(!RouteLinkNumIs(cnode->link_parent, parent)) {
        // set new parent numnick in route
        RouteLinkNumSet(cnode->link_parent, parent);
        
        // if this is the primary uplink we need to reparent the server in the local server tree
        if(!prev_node)
          do_reparent_server = 1;
      }
    }
    else
      prev_node = cnode;
  }
  
  if(!link_node) {
    if(!parent) {
      // link is denounced but we didn't even know the link...
      // we must have missed a advertisement or there is something else terribly wrong
      Debug((DEBUG_ERROR, "Received denounce to %C from %C, but I don't know about this route.", uplink, server));
      do_reinsert_route = 0;
    }
    else {
      // create new entry in the routes list
      link_node = (struct RouteList*) MyCalloc(1, sizeof(*link_node));
      link_node->link_islocal = is_local_route ? 1 : 0;
      link_node->link_cost = linkcost;
      RouteLinkNumSet(link_node->link_client, uplink);
      RouteLinkNumSet(link_node->link_parent, parent);
      do_reinsert_route = 1;
    }
  }
  else if(do_reinsert_route) {
    // remove the entry from the list (position invalid or denounced)
    if(link_prev) {
      link_prev->next = link_node->next;
      if(link_prev == cli_serv(server)->routes)
        forward_loopadvert = 1;
    }
    else {
      new_lowest_link = 1;
      if(cli_serv(server)->routes = link_node->next)
        forward_loopadvert = 1;
    }
    route_count--;
    
    if(!parent) {
      // link denouncement - free list entry and do not add it to the list anymore
      MyFree(link_node);
      link_node = NULL;
      do_reinsert_route = 0;
    }
  }
  
  if(do_reinsert_route) {
    // insert the entry at the right position into the list
    
    if(!cost_prev && !is_lowest_cost) {
      if(prev_node && (!is_local_route || prev_node->link_islocal))
        // the worst route for this server
        cost_prev = prev_node;
      else
        // the first route for this server
        is_lowest_cost = 1;
    }
    // insert link node to list
    route_count++;
    if(is_lowest_cost) { // as first
      new_lowest_link = 1;
      if(link_node->next = cli_serv(server)->routes)
        forward_loopadvert = 1;
      cli_serv(server)->routes = link_node;
    }
    else { // after cost_prev entry
      link_node->next = cost_prev->next;
      cost_prev->next = link_node;
      
      if(cost_prev == cli_serv(server)->routes) {
        // second entry, notify primary about this backup link
        forward_loopadvert = 1;
      }
    }
  }
  
  if(route_count > 1)
    SetRoutingEnabled(server);
  else
    ClearRoutingEnabled(server);
  
  // check if there is still a route present
  if(route_count) {
    cnode = cli_serv(server)->routes;
    
    // update position in local server tree if needed
    if(do_reparent_server || new_lowest_link) {
      cli_linkcost(server) = cnode->link_cost;
      deprecate_own_server_routes();
      
      update_server_parent(server);
    }
    
    // update primary uplink if needed
    if(new_lowest_link) {
      update_server_uplink(server);
      forward_advertisement = 1;
    }
    
    if(forward_advertisement) {
      // forward to neighbours
      send_announce_to_neighbours_buf(lnabuf, cptr, cli_from(server), cli_yxx(server), cnode->link_parent, cli_linkcost(server));
    }
    
    if(forward_loopadvert) {
      // forward secondary link updates (we notify the primary uplink that he can use us as uplink as well)
      if(cnode->next)
        send_announce_to_one_buf(lnabuf, cli_from(server), cli_yxx(server), cnode->next->link_parent, cnode->next->link_cost);
      else
        // we no longer have an alternative link to server (notifythe primary uplink about it)
        send_announce_to_one_buf(lnabuf, cli_from(server), cli_yxx(server), cnode->link_parent, 0);
    }
  }
  else if(!parent) {
    // no more neighbours but uplink must assume there is still one (would have sent a SQUIT if not)
    // probably a timing issue, so we exit the server ourself to ensure this is properly propagated
    if(!linkcost)
      exit_client(cptr, server, uplink, "no route to server");
    forward_advertisement = 2;
  }
  
  return forward_advertisement;
}

void send_announce_to_neighbours_buf(struct LinkAnnounceDst **lnabuf, struct Client *skip1, struct Client *skip2, const char *servernum, const char *parentnum, unsigned int linkcost) {
  struct DLink *lp;
  for (lp = cli_serv(&me)->down; lp; lp = lp->next) {
    if (skip1 && lp->value.cptr == skip1)
      continue;
    if (skip2 && lp->value.cptr == skip2)
      continue;
    
    send_announce_to_one_buf(lnabuf, lp->value.cptr, servernum, parentnum, linkcost);
  }
}

void send_announce_to_one_buf(struct LinkAnnounceDst **lnabuf, struct Client *client, const char *servernum, const char *parentnum, unsigned int linkcost) {
  if(RouteLinkNumIs(servernum, client))
    return;
  
  struct LinkAnnounceBuf *cbuf = MyMalloc(sizeof(*cbuf));
  struct LinkAnnounceDst *cbufdst, *pbufdst = NULL;
  for(cbufdst = *lnabuf; cbufdst; cbufdst = cbufdst->next) {
    if(cbufdst->client == client)
      break;
    pbufdst = cbufdst;
  }
  if(!cbufdst) {
    cbufdst = MyMalloc(sizeof(*cbufdst));
    cbufdst->client = client;
    cbufdst->first = cbuf;
    cbufdst->next = NULL;
    if(pbufdst)
      pbufdst->next = cbufdst;
    else
      *lnabuf = cbufdst;
  }
  else {
    cbufdst->last->next = cbuf;
  }
  
  cbuf->next = NULL;
  cbuf->length = sprintf(cbuf->data, "%.2s%.2s%u", servernum, parentnum, linkcost);
  cbufdst->last = cbuf;
}

void flush_link_announcements(struct LinkAnnounceDst *lnabuf, const char *numpath) {
  struct LinkAnnounceDst *cbufdst, *nbufdst;
  struct LinkAnnounceBuf *cbuf, *nbuf;
  
  for(cbufdst = lnabuf; cbufdst; cbufdst = nbufdst) {
    nbufdst = cbufdst->next;
    // pack announcements into one message
    build_route_buflen = 0;
    
    for(cbuf = cbufdst->first; cbuf; cbuf = nbuf) {
      nbuf = cbuf->next;
      if(build_route_buflen)
        build_route_buf[build_route_buflen++] = ' ';
      
      memcpy(build_route_buf + build_route_buflen, cbuf->data, cbuf->length);
      build_route_buflen += cbuf->length;
      
      if(build_route_buflen >= 256) {
        build_route_buf[build_route_buflen] = '\0';
        sendcmdto_prio_one(&me, CMD_LINKCHANGE, cbufdst->client, "%s :%s%.2s", build_route_buf, numpath, cli_yxx(&me));
        build_route_buflen = 0;
      }
      
      MyFree(cbuf);
    }
    if(build_route_buflen) {
      build_route_buf[build_route_buflen] = '\0';
      sendcmdto_prio_one(&me, CMD_LINKCHANGE, cbufdst->client, "%s :%s%.2s", build_route_buf, numpath, cli_yxx(&me));
      build_route_buflen = 0;
    }
    
    MyFree(cbufdst);
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
  
  update_server_parent_recursive(server, cli_hopcount(new_parent) + 1);
}

static void update_server_parent_recursive(struct Client *server, unsigned int hopcount) {
  struct DLink *link;
  
  // update client hopcount
  cli_hopcount(server) = hopcount;
  
  // loop through all downlinks
  for (link = cli_serv(server)->down; link; link = link->next)
    update_server_parent_recursive(link->value.cptr, hopcount + 1);
}

static void update_server_uplink(struct Client *server) {
  struct DLink *link;
  struct Client *lncli;
  struct Client *new_uplink;
  struct Client **acptrp;
  int i;
  
  new_uplink = FindNServer(cli_serv(server)->routes->link_client);
  if(!new_uplink || cli_connect(new_uplink) == cli_connect(server))
    return;

  if(IsServer(server) && cli_local(server)) {
    /* Lost direct connection to the server. 
      We want to keep the Client alive as it is still reachable via another link,
      therefore we have to delink it from the old dying connection struct here.
    */
    close_connection(server);
    cli_from(server) = 0;
    ClrFlag(server, FLAG_DEADSOCKET);
  }
  
  /* Set uplink connection on server and all associated clients */
  update_server_uplink_recursive(server, new_uplink);
}

static void update_server_uplink_recursive(struct Client *server, struct Client *uplink) {
  struct DLink *link;
  struct Client **acptrp;
  int i;
  
  // update connection of server
  cli_connect(server) = cli_connect(uplink);
  
  // loop through all downlinks
  for (link = cli_serv(server)->down; link; link = link->next) {
    update_server_uplink_recursive(link->value.cptr, uplink);
  }
  // loop through all clients of server
  acptrp = cli_serv(server)->client_list;
  for (i = 0; i <= cli_serv(server)->nn_mask; ++acptrp, ++i) {
    if (*acptrp)
      cli_connect(*acptrp) = cli_connect(uplink);
  }
}

static void deprecate_own_server_routes() {
  // mark own broadcast routes as deprecated
  struct DLink *link;
  for (link = cli_serv(&me)->down; link; link = link->next) {
    if(cli_serv(link->value.cptr)->own_route)
      cli_serv(link->value.cptr)->own_route->is_deprecated = 1;
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
  update_server_uplink_recursive(victim, client);
  cli_from(victim) = victim;
  cli_status(client) = STAT_UNKNOWN;
  
  // mark as impersonating 
  // this will make the packet read loop breaking after this message 
  // and restarts in next event loop with proper client pointer
  cli_connect(client)->con_impcli = victim;
  SetFlag(client, FLAG_IMPERSONATING);
}

/** Remove routes that used uplink from all servers
 * @param uplink The uplink that is removed
 * @param comment The remove reason
 * @return 1 if the update changed something on the primary uplink (update should be propagated)
 *         0 otherwise
 */
void remove_uplink_routes(struct Client *uplink, const char *comment) {
  struct DLink *link, *nextlink;
  struct Client *lncli;
  struct LinkAnnounceDst *lnabuf = NULL;
  
  // denounce primary routes via uplink (but do not exit any client)
  remove_uplink_routes_recursive(&lnabuf, uplink, uplink, 1);
  
  // denounce non-primary routes via uplink
  for (link = cli_serv(&me)->down; link; link = nextlink) {
    lncli = link->value.cptr;
    nextlink = link->next;
    if(lncli == uplink)
      continue;
    remove_uplink_routes_recursive(&lnabuf, uplink, lncli, 0);
  }
  
  if(lnabuf)
    flush_link_announcements(lnabuf, "");
}

static void remove_uplink_routes_recursive(struct LinkAnnounceDst **lnabuf, struct Client *uplink, struct Client *client, unsigned int linkcost) {
  struct DLink *link, *nextlink;
  struct Client *lncli;
  
  // loop through all downlinks and remove uplink route if set
  for (link = cli_serv(client)->down; link; link = nextlink) {
    lncli = link->value.cptr;
    nextlink = link->next;
    
    // recursively remove from downlinks first
    remove_uplink_routes_recursive(lnabuf, uplink, lncli, linkcost);
  }
  
  /* remove uplink route (parent = NULL)
   * this may change the position of lncli in the server link tree,
   * so it could be that it is no longer a downlink of `uplink`
   */
  update_server_route(lnabuf, uplink, client, uplink, NULL, linkcost);
}

/** Clear all routing related structs and clear references in server struct
 * @param uplink The client to clear
 * @return
 */
void free_server_routes(struct Client *uplink) {
  struct RouteList *link, *next_link;
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
      // check if downlink is part of the route - do not forward if not
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
  
  RouteLinkNumSet(netroute->route_src, uplink);
  
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
        if(check_forward_to_server_route(server, lncli)) {
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

int check_forward_to_server_route(struct Client *source, struct Client *target) {
  struct Client *server, *uplink;
  struct RouteInfo *routeinfo;
  int i;
  if(IsUser(source))
    source = cli_user(source)->server;
  
  if(IsUser(target))
    server = cli_user(target)->server;
  else if(IsServer(target))
    server = target;
  else
    return 1;
  if(server == &me)
    return 1;
  uplink = cli_from(server);
  
  if(source == &me) {
    if(!(routeinfo = cli_serv(uplink)->own_route) || cli_serv(uplink)->own_route->is_deprecated)
      routeinfo = build_broadcast_route(uplink);
    if(!routeinfo->is_announced) {
      announce_server_route(uplink, &me, routeinfo);
      routeinfo->is_announced = 1;
    }
    return 1;
  }
  else {
    if(!(routeinfo = cli_serv(source)->fwd_route))
      return 1;
    if(routeinfo->route_len == 0)
      return 0;
    
    for(i = 0; routeinfo->route_data[i]; i+=2) {
      if(RouteLinkNumIs((routeinfo->route_data + i), uplink))
        return 1;
    }
    return 0;
  }
}

static void announce_server_route(struct Client *client, struct Client *server, struct RouteInfo *routeinfo) {
  unsigned int routepos, routelen;
  unsigned int routestrlen;
  
  if(routeinfo->route_len == 0) {
    // empty route
    sendcmdto_prio_one(&me, CMD_NETROUTE, client, "%C %u 0", server, routeinfo->route_idx);
    return;
  }
  
  // send in chunks if too long
  routepos = 0;
  routestrlen = routeinfo->route_len * 2;
  do {
    if((routelen = routestrlen - routepos) > BUFSIZE - 30)
      routelen = BUFSIZE - 30; // leave some space for header
    
    if(routepos == 0)
      sendcmdto_prio_one(&me, CMD_NETROUTE, client, "%C %u %u %.*s", server, routeinfo->route_idx, routeinfo->route_len, routelen, routeinfo->route_data);
    else
      sendcmdto_prio_one(&me, CMD_NETROUTE, client, "%C %u + %.*s", server, routeinfo->route_idx, routelen, routeinfo->route_data + routepos);
    
    routepos += routelen;
  } while(routepos < routestrlen);
}

int check_received_from_server_route(struct Client *client, struct Client *source) {
  struct RouteInfo *routeinfo;
  struct RouteList *cnode;
  if(IsUser(source))
    source = cli_user(source)->server;
  
  if(!(routeinfo = cli_serv(source)->fwd_route))
    return 0;
  if(RouteLinkNumIs(routeinfo->route_src, client))
    return 1;
  
  // check if we can see source on client links
  for(cnode = cli_serv(source)->routes; cnode; cnode = cnode->next) {
    if(RouteLinkNumIs(cnode->link_client, client))
      return 1;
  }
  
  return 0;
}
