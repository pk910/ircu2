/*
 * IRC - Internet Relay Chat, ircd/ssl.c
 * Copyright (C) 2012 pk910 (Philipp Kreil)
 * This patch heavily relies on the OGN SSL patch.
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
 * @brief Implementation of functions for handling local clients.
 * @version $Id$
 */
#include "config.h"

#include "client.h"
#include "ssl.h"
#include "class.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "list.h"
#include "msgq.h"
#include "numeric.h"
#include "s_conf.h"
#include "s_debug.h"
#include "send.h"
#include "struct.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <string.h>

#ifndef IOV_MAX
#define IOV_MAX 16  /**< minimum required length of an iovec array */
#endif

#if defined(HAVE_OPENSSL_SSL_H)

struct SSLPendingConections {
  struct SSLConnection *connection;
  struct SSLPendingConections *next;
  
  void *data;
};

struct SSLPendingConections *firstPendingConection = NULL;
int ssl_is_initialized = 0;

static void ssl_init() {
  if(ssl_is_initialized)
    return;
  ssl_is_initialized = 1;
  SSL_library_init();
  OpenSSL_add_all_algorithms(); /* load & register all cryptos, etc. */
  SSL_load_error_strings();
}

void ssl_free_connection(struct SSLConnection *connection) {
  SSL_CTX *context = NULL;
  if(FlagHas(&connection->flags, SSLFLAG_OUTGOING)) {
    struct SSLOutConnection *outconn = (struct SSLOutConnection *)connection;
    context = outconn->context;
  }
  SSL_shutdown(connection->session);
  SSL_free(connection->session);
  if(context)
    SSL_CTX_free(context);
  free(connection);
}

void ssl_free_listener(struct SSLListener *listener) {
  SSL_CTX_free(listener->context);
  free(listener);
}

static void ssl_handshake_completed(struct SSLConnection *connection, int success) {
  struct SSLPendingConections *pending, *lastPending = NULL;
  for(pending = firstPendingConection; pending; pending = pending->next) {
    if(pending->connection == connection) {
      if(lastPending)
        lastPending->next = pending->next;
      else
        firstPendingConection = pending->next;
      
      struct Client *cptr = (struct Client *) pending->data;
      if(success && FlagHas(&connection->flags, SSLFLAG_INCOMING)) {
        start_auth(cptr);
      }
      free(pending);
    }
    lastPending = pending;
  }
}

static int ssl_handshake_outgoing(struct SSLConnection *connection) {
  int ret = SSL_do_handshake(connection->session);
  FlagClr(&connection->flags, SSLFLAG_HANDSHAKE_R);
  FlagClr(&connection->flags, SSLFLAG_HANDSHAKE_W);
  
  switch(SSL_get_error(connection->session, ret)) {
    case SSL_ERROR_NONE:
      FlagClr(&connection->flags, SSLFLAG_HANDSHAKE);
      FlagSet(&connection->flags, SSLFLAG_READY);
      
      ssl_handshake_completed(connection, 1);
      return 0;
    case SSL_ERROR_WANT_READ:
      FlagSet(&connection->flags, SSLFLAG_HANDSHAKE_R);
      return 1;
    case SSL_ERROR_WANT_WRITE:
      FlagSet(&connection->flags, SSLFLAG_HANDSHAKE_W);
      return 1;
    default:
      return -1;
  }
}

struct SSLConnection *ssl_create_connect(int fd, void *data) {
  struct SSLOutConnection *connection = malloc(sizeof(*connection));
  struct SSLConnection *sslconn = (struct SSLConnection *)connection;
  struct SSLPendingConections *pending = NULL;
  
  if(!connection)
    return NULL;
  
  if(!ssl_is_initialized)
    ssl_init();
  
  connection->context = SSL_CTX_new(SSLv23_client_method());
  if(!connection->context) {
    goto ssl_create_connect_failed;
  }
  connection->session = SSL_new(connection->context);
  if(!connection->session) {
    goto ssl_create_connect_failed;
  }
  if(!SSL_set_fd(connection->session, fd)) {
    goto ssl_create_connect_failed;
  }
  SSL_set_connect_state(connection->session);
  FlagSet(&connection->flags, SSLFLAG_OUTGOING);
  FlagSet(&connection->flags, SSLFLAG_HANDSHAKE);
  
  pending = malloc(sizeof(*pending));
  if(!pending) {
    goto ssl_create_connect_failed;
  }
  pending->connection = sslconn;
  pending->next = firstPendingConection;
  firstPendingConection = pending;
  
  pending->data = data;
  
  return sslconn;
ssl_create_connect_failed:
  free(connection);
  return NULL;
}

void ssl_start_handshake_connect(struct SSLConnection *connection) {
  ssl_handshake_outgoing(connection);
}

struct SSLListener *ssl_create_listener() {
  if(!ssl_is_initialized)
    ssl_init();
  
  struct SSLListener *listener = calloc(1, sizeof(*listener));
  listener->context = SSL_CTX_new(SSLv23_server_method());
  if(!listener->context) {
    goto ssl_create_listener_failed;
  }
  
  char *certfile = conf_get_local()->sslcertfile;
  char *keyfile = conf_get_local()->sslkeyfile;
  char *cafile = conf_get_local()->sslcafile;
  
  if(!certfile) {
    goto ssl_create_listener_failed;
  }
  if(!keyfile) {
    keyfile = certfile;
  }
  
  /* load certificate */
  if(SSL_CTX_use_certificate_file(listener->context, certfile, SSL_FILETYPE_PEM) <= 0) {
    goto ssl_create_listener_failed;
  }
  /* load keyfile */
  if(SSL_CTX_use_PrivateKey_file(listener->context, keyfile, SSL_FILETYPE_PEM) <= 0) {
    goto ssl_create_listener_failed;
  }
  /* check certificate and keyfile */
  if(!SSL_CTX_check_private_key(listener->context)) {
    goto ssl_create_listener_failed;
  }
  /* load cafile */
  if(cafile && cafile[0] && SSL_CTX_load_verify_locations(listener->context, cafile, NULL) <= 0) {
    goto ssl_create_listener_failed;
  }
  FlagSet(&listener->flags, SSLFLAG_READY);
  return listener;
ssl_create_listener_failed:
  free(listener);
  return NULL;
}

static int ssl_handshake_incoming(struct SSLConnection *connection) {
  int result = SSL_accept(connection->session);
  FlagClr(&connection->flags, SSLFLAG_HANDSHAKE_R);
  FlagClr(&connection->flags, SSLFLAG_HANDSHAKE_W);
  switch(SSL_get_error(connection->session, result)) {
    case SSL_ERROR_NONE:
      FlagClr(&connection->flags, SSLFLAG_HANDSHAKE);
      FlagSet(&connection->flags, SSLFLAG_READY);
      
      ssl_handshake_completed(connection, 1);
      return 0;
    case SSL_ERROR_WANT_READ:
      FlagSet(&connection->flags, SSLFLAG_HANDSHAKE_R);
      return 1;
    case SSL_ERROR_WANT_WRITE:
      FlagSet(&connection->flags, SSLFLAG_HANDSHAKE_W);
      return 1;
    default:
      //unset connection! 
      //Handshake error!
      ssl_handshake_completed(connection, 0);
      return -1;
  }
}

struct SSLConnection *ssl_start_handshake_listener(struct SSLListener *listener, int fd, void *data) {
  if(!listener)
    return NULL;
  struct SSLPendingConections *pending = NULL;
  struct SSLConnection *connection = malloc(sizeof(*connection));
  connection->session = SSL_new(listener->context);
  if(!connection->session) {
    goto ssl_start_handshake_listener_failed;
  }
  if(!SSL_set_fd(connection->session, fd)) {
    goto ssl_start_handshake_listener_failed;
  }
  FlagSet(&connection->flags, SSLFLAG_INCOMING);
  FlagSet(&connection->flags, SSLFLAG_HANDSHAKE);
  FlagSet(&connection->flags, SSLFLAG_HANDSHAKE_R);
  
  pending = malloc(sizeof(*pending));
  if(!pending) {
    goto ssl_start_handshake_listener_failed;
  }
  pending->connection = connection;
  pending->next = firstPendingConection;
  firstPendingConection = pending;
  
  pending->data = data;
  
  ssl_handshake_incoming(connection);
  return connection;
ssl_start_handshake_listener_failed:
  free(connection);
  return NULL;
}

IOResult ssl_recv_decrypt(struct SSLConnection *connection, char *buf, unsigned int buflen, unsigned int *len) {
  if(FlagHas(&connection->flags, SSLFLAG_HANDSHAKE)) {
    if(FlagHas(&connection->flags, SSLFLAG_INCOMING)) {
      if(ssl_handshake_incoming(connection) < 0)
        return IO_FAILURE;
      else
        return IO_BLOCKED;
    }
    if(FlagHas(&connection->flags, SSLFLAG_OUTGOING)) {
      if(ssl_handshake_outgoing(connection) < 0)
        return IO_FAILURE;
      else
        return IO_BLOCKED;
    }
  }
  
  *len = SSL_read(connection->session, buf, buflen);
  FlagClr(&connection->flags, SSLFLAG_HANDSHAKE_R);
  int err = SSL_get_error(connection->session, *len);
  switch(err) {
    case SSL_ERROR_NONE:
      return IO_SUCCESS;
    case SSL_ERROR_ZERO_RETURN:
      return IO_FAILURE;
    case SSL_ERROR_WANT_READ:
      FlagSet(&connection->flags, SSLFLAG_HANDSHAKE_R);
      return IO_BLOCKED;
    case SSL_ERROR_WANT_WRITE:
      FlagSet(&connection->flags, SSLFLAG_HANDSHAKE_W);
      return IO_BLOCKED;
    case SSL_ERROR_SYSCALL:
      return IO_FAILURE;
    default:
      return IO_FAILURE;
  }
}

static ssize_t ssl_writev(SSL *ssl, const struct iovec *vector, int count) {
  char *buffer;
  register char *bp;
  size_t bytes, to_copy;
  int i;

  /* Find the total number of bytes to be written.  */
  bytes = 0;
  for (i = 0; i < count; ++i)
    bytes += vector[i].iov_len;

  /* Allocate a temporary buffer to hold the data.  */
  buffer = (char *) alloca (bytes);

  /* Copy the data into BUFFER.  */
  to_copy = bytes;
  bp = buffer;
  for (i = 0; i < count; ++i) {
    size_t copy = ((vector[i].iov_len) > (to_copy) ? (to_copy) : (vector[i].iov_len));
    memcpy ((void *) bp, (void *) vector[i].iov_base, copy);
    bp += copy;
    to_copy -= copy;
    if (to_copy == 0)
      break;
  }
  return SSL_write(ssl, buffer, bytes);
}

IOResult ssl_send_encrypt_plain(struct SSLConnection *connection, char* buf, int len) {
  return SSL_write(connection->session, buf, len);
}

IOResult ssl_send_encrypt(struct SSLConnection *connection, struct MsgQ* buf, unsigned int *count_in, unsigned int *count_out) {
  int res;
  int count;
  struct iovec iov[IOV_MAX];

  assert(0 != buf);
  assert(0 != count_in);
  assert(0 != count_out);

  *count_in = 0;
  count = msgq_mapiov(buf, iov, IOV_MAX, count_in);
  res = ssl_writev(connection->session, iov, count);

  switch(SSL_get_error(connection->session, res)) {
    case SSL_ERROR_NONE:
    case SSL_ERROR_ZERO_RETURN:
      *count_out = (unsigned) res;
      return IO_SUCCESS;
    case SSL_ERROR_WANT_READ:
      FlagSet(&connection->flags, SSLFLAG_HANDSHAKE_R);
      return IO_BLOCKED;
    case SSL_ERROR_WANT_WRITE:
      FlagSet(&connection->flags, SSLFLAG_HANDSHAKE_W);
      return IO_BLOCKED;
    default:
      *count_out = 0;
      return IO_FAILURE;
  }
}

int ssl_connection_flush(struct SSLConnection *connection) {
  if(connection) {
    if(ssl_handshake(connection)) {
      if(FlagHas(&connection->flags, SSLFLAG_INCOMING)) {
        return ssl_handshake_incoming(connection);
      }
      if(FlagHas(&connection->flags, SSLFLAG_OUTGOING)) {
        return ssl_handshake_outgoing(connection);
      }
    }
  } else {
    struct SSLPendingConections *curr, *last = NULL, *next;
    for(curr = firstPendingConection; curr; curr = next) {
      next = curr->next;
      if(!ssl_connection_flush(curr->connection)) {
        // connection is already in auth process here, curr is freed!
        continue;
      }
      last = curr;
    }
  }
  return 0;
}

#else
// fallback dummy implementation

void ssl_free_connection(struct SSLConnection *connection) {};
void ssl_free_listener(struct SSLListener *listener) {};

struct SSLListener *ssl_create_listener() { return NULL; };
struct SSLConnection *ssl_create_connect(int fd, void *data) { return NULL };

struct SSLConnection *ssl_start_handshake_listener(struct SSLListener *listener, int fd, void *data) { return NULL; };
void ssl_start_handshake_connect(struct SSLConnection *connection) {};

IOResult ssl_recv_decrypt(struct SSLConnection *connection, char *buf, unsigned int buflen, unsigned int *len) { return IO_FAILURE; };
IOResult ssl_send_encrypt(struct SSLConnection *connection, struct MsgQ* buf, unsigned int *count_in, unsigned int *count_out) { return IO_FAILURE; };
IOResult ssl_send_encrypt_plain(struct SSLConnection *connection, char *buf, int len) { return IO_FAILURE; };
int ssl_connection_flush(struct SSLConnection *connection) { return 0; };
#endif

