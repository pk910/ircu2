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
#include "ircd_alloc.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "list.h"
#include "listener.h"
#include "msgq.h"
#include "numeric.h"
#include "s_auth.h"
#include "s_bsd.h"
#include "s_conf.h"
#include "s_debug.h"
#include "send.h"
#include "struct.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <string.h>

#ifndef IOV_MAX
#define IOV_MAX 1024  /**< minimum required length of an iovec array */
#endif

#if defined(HAVE_OPENSSL_SSL_H)
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

struct SSLPendingConections {
  struct SSLConnection *connection;
  struct SSLPendingConections *next;
  struct SSLListener *listener;
  
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

static void ssl_free_config(struct SSLConf *target) {
  MyFree(target->certfile);
  MyFree(target->keyfile);
  MyFree(target->cafile);
  MyFree(target->certfp);
  MyFree(target->ciphers);
  MyFree(target->options);
  MyFree(target->protocol);
  MyFree(target->minproto);
  MyFree(target->maxproto);
  MyFree(target->curves);
}

void ssl_free_connection(struct SSLConnection *connection) {
  SSL_CTX *context = NULL;
  if(FlagHas(&connection->flags, SSLFLAG_OUTGOING)) {
    struct SSLOutConnection *outconn = (struct SSLOutConnection *)connection;
    context = outconn->context;
    
    ssl_free_config(&outconn->conf);
    if(outconn->cacert)
      X509_free(outconn->cacert);
  }
  SSL_shutdown(connection->session);
  SSL_free(connection->session);
  
  if(context)
    SSL_CTX_free(context);
  MyFree(connection);
}

void ssl_free_listener(struct SSLListener *listener) {
  ssl_free_config(&listener->conf);
  if(listener->cacert)
    X509_free(listener->cacert);
  SSL_CTX_free(listener->context);
  MyFree(listener);
}

static void ssl_merge_config(struct SSLConf *target, const struct SSLConf *source) {
  target->flags |= source->flags;
  if(source->cafile) {
    MyFree(target->cafile);
    DupString(target->cafile, source->cafile);
  }
  if(source->certfp) {
    MyFree(target->certfp);
    DupString(target->certfp, source->certfp);
  }
  if(source->ciphers) {
    MyFree(target->ciphers);
    DupString(target->ciphers, source->ciphers);
  }
  if(source->options) {
    MyFree(target->options);
    DupString(target->options, source->options);
  }
  if(source->protocol) {
    MyFree(target->protocol);
    DupString(target->protocol, source->protocol);
  }
  if(source->minproto) {
    MyFree(target->minproto);
    DupString(target->minproto, source->minproto);
  }
  if(source->maxproto) {
    MyFree(target->maxproto);
    DupString(target->maxproto, source->maxproto);
  }
  if(source->curves) {
    MyFree(target->curves);
    DupString(target->curves, source->curves);
  }
}

static void ssl_merge_cert_config(struct SSLConf *target, const struct SSLConf *source) {
  if(source->certfile) {
    MyFree(target->certfile);
    DupString(target->certfile, source->certfile);
  }
  if(source->keyfile) {
    MyFree(target->keyfile);
    DupString(target->keyfile, source->keyfile);
  }
}

static void ssl_apply_ctx_config(SSL_CTX *ctx, struct SSLConf *config) {
  /* apply options */
  SSL_CONF_CTX * const cctx = SSL_CONF_CTX_new();
  SSL_CONF_CTX_set_ssl_ctx(cctx, ctx);
  SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_FILE);
  if(config->ciphers)
    SSL_CONF_cmd(cctx, "CipherString", config->ciphers);
  if(config->options)
    SSL_CONF_cmd(cctx, "Options", config->options);
  if(config->protocol)
    SSL_CONF_cmd(cctx, "Protocol", config->protocol);
  if(config->minproto)
    SSL_CONF_cmd(cctx, "MinProtocol", config->minproto);
  if(config->maxproto)
    SSL_CONF_cmd(cctx, "MaxProtocol", config->maxproto);
  if(config->curves)
    SSL_CONF_cmd(cctx, "Curves", config->curves);
  
  SSL_CONF_CTX_free(cctx);
}

static X509 *ssl_load_certificate(char *filename) {
  BIO *certbio = BIO_new(BIO_s_file());
  BIO_read_filename(certbio, filename);
  X509 *cert = PEM_read_bio_X509(certbio, NULL, 0, NULL);
  BIO_free(certbio);
  return cert;
}

static void binary_to_hex(unsigned char *bin, char *hex, int length) {
  static const char trans[] = "0123456789ABCDEF";
  int i;

  for(i = 0; i < length; i++) {
    hex[i  << 1]      = trans[bin[i] >> 4];
    hex[(i << 1) + 1] = trans[bin[i] & 0xf];
  }

  hex[i << 1] = '\0';
}

static const char *ssl_cert_fingerprint(X509* cert) {
  unsigned int n = 0;
  unsigned char md[EVP_MAX_MD_SIZE];
  const EVP_MD *digest = EVP_sha256();
  static char hex[BUFSIZE + 1];

  if (!cert)
    return NULL;
  if (!X509_digest(cert, digest, md, &n))
    return NULL;
  
  binary_to_hex(md, hex, n);
  return hex;
}

static int ssl_verify_cert_is_signed(X509 *cert, X509 *cacert, const char **errmsg) {
  int res;
  X509_STORE *store;
  X509_STORE_CTX *ctx;

  store = X509_STORE_new();
  X509_STORE_add_cert(store, cacert);

  ctx = X509_STORE_CTX_new();
  X509_STORE_CTX_init(ctx, store, cert, NULL);

  res = X509_verify_cert(ctx);
  if(res <= 0 && errmsg) {
    int err = X509_STORE_CTX_get_error(ctx);
    *errmsg = X509_verify_cert_error_string(err);
  }
  if(res < 0)
    res = 0;
  
  X509_STORE_CTX_free(ctx);
  X509_STORE_free(store);
  return res;
}

static int ssl_verify_peer_certificate(struct SSLListener *listener, X509 *peer_cert, const char **errmsg) {
  int valid = 1;
  
  if(valid && (listener->conf.flags & CONF_VERIFYCA)) {
    if(!listener->cacert) {
      if(!listener->conf.cafile) {
        if(errmsg)
          *errmsg = "CA verification failed: cafile not set.";
        valid = 0;
      }
      if(!(listener->cacert = ssl_load_certificate(listener->conf.cafile))) {
        if(errmsg)
          *errmsg = "CA verification failed: could not load cafile.";
        valid = 0;
      }
    }
    if(!ssl_verify_cert_is_signed(peer_cert, listener->cacert, errmsg))
      valid = 0;
  }
  if(valid && (listener->conf.flags & CONF_VERIFYCERT)) {
    if(!listener->conf.certfp || !*listener->conf.certfp) {
      if(errmsg)
        *errmsg = "CertFP verification failed: fingerprint not set.";
      valid = 0;
    }
    else if(strcmp(listener->conf.certfp, ssl_cert_fingerprint(peer_cert))) {
      if(errmsg)
        *errmsg = "CertFP verification failed: fingerprint does not match.";
      valid = 0;
    }
  }
  
  return valid;
}
static int ssl_verify_server_certificate(struct SSLOutConnection *connection, X509 *server_cert, const char **errmsg) {
  int valid = 1;
  
  if(valid && (connection->conf.flags & CONF_VERIFYCA)) {
    if(!connection->cacert) {
      if(!connection->conf.cafile) {
        if(errmsg)
          *errmsg = "CA verification failed: cafile not set.";
        valid = 0;
      }
      if(!(connection->cacert = ssl_load_certificate(connection->conf.cafile))) {
        if(errmsg)
          *errmsg = "CA verification failed: could not load cafile.";
        valid = 0;
      }
    }
    if(!ssl_verify_cert_is_signed(server_cert, connection->cacert, errmsg))
      valid = 0;
  }
  if(valid && (connection->conf.flags & CONF_VERIFYCERT)) {
    if(!connection->conf.certfp || !*connection->conf.certfp) {
      if(errmsg)
        *errmsg = "CertFP verification failed: fingerprint not set.";
      valid = 0;
    }
    else if(strcmp(connection->conf.certfp, ssl_cert_fingerprint(server_cert))) {
      if(errmsg)
        *errmsg = "CertFP verification failed: fingerprint does not match.";
      valid = 0;
    }
  }
  
  return valid;
}

static int ssl_complete_client_outgoing(struct SSLOutConnection *connection, struct Client *cptr) {
  const char *errmsg;
  if(!ssl_verify_server_certificate(connection, SSL_get_peer_certificate(connection->session), &errmsg)) {
    
    return -1;
  }
  if(!completed_connection(cptr))
    return -1;
  return 0;
}

static int ssl_complete_client_incoming(struct SSLConnection *connection, struct SSLListener *listener, struct Client *cptr) {
  const char *errmsg;
  if(!ssl_verify_peer_certificate(listener, SSL_get_peer_certificate(connection->session), &errmsg)) {
    
    return -1;
  }
  if(!FlagHas(&connection->flags, SSLFLAG_STARTTLS))
    start_auth(cptr);
  return 0;
}

static int ssl_handshake_completed(struct SSLConnection *connection, int success) {
  struct SSLPendingConections *pending, *lastPending = NULL;
  int ret = 0;
  for(pending = firstPendingConection; pending; pending = pending->next) {
    if(pending->connection == connection) {
      if(lastPending)
        lastPending->next = pending->next;
      else
        firstPendingConection = pending->next;
      
      struct Client *cptr = (struct Client *) pending->data;
      if(success) {
        if(FlagHas(&connection->flags, SSLFLAG_INCOMING)) {
          ret = ssl_complete_client_incoming(connection, pending->listener, cptr);
        }
        else if(FlagHas(&connection->flags, SSLFLAG_OUTGOING)) {
          ret = ssl_complete_client_outgoing((struct SSLOutConnection *)connection, cptr);
        }
      }
      MyFree(pending);
      break;
    }
    lastPending = pending;
  }
  return ret;
}

static int ssl_handshake_outgoing(struct SSLConnection *connection) {
  int ret = SSL_do_handshake(connection->session);
  FlagClr(&connection->flags, SSLFLAG_HANDSHAKE_R);
  FlagClr(&connection->flags, SSLFLAG_HANDSHAKE_W);
  
  switch(SSL_get_error(connection->session, ret)) {
    case SSL_ERROR_NONE:
      FlagClr(&connection->flags, SSLFLAG_HANDSHAKE);
      FlagSet(&connection->flags, SSLFLAG_READY);
      
      return ssl_handshake_completed(connection, 1);
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

struct SSLConnection *ssl_create_connect(int fd, void *data, struct SSLConf *localcfg) {
  struct SSLOutConnection *connection = MyCalloc(1, sizeof(*connection));
  struct SSLConnection *sslconn = (struct SSLConnection *)connection;
  struct SSLPendingConections *pending = NULL;
  
  if(!connection)
    return NULL;
  ssl_merge_config(&connection->conf, &conf_get_local()->ssl);
  ssl_merge_config(&connection->conf, localcfg);
  ssl_merge_cert_config(&connection->conf, localcfg);
  
  if(!ssl_is_initialized)
    ssl_init();
  
  connection->context = SSL_CTX_new(SSLv23_client_method());
  if(!connection->context) {
    goto ssl_create_connect_failed;
  }
  
  ssl_apply_ctx_config(connection->context, &connection->conf);
  if(connection->conf.certfile && connection->conf.keyfile) {
    /* load client certificate */
    if(SSL_CTX_use_certificate_file(connection->context, connection->conf.certfile, SSL_FILETYPE_PEM) <= 0) {
      goto ssl_create_connect_failed;
    }
    /* load client keyfile */
    if(SSL_CTX_use_PrivateKey_file(connection->context, connection->conf.keyfile, SSL_FILETYPE_PEM) <= 0) {
      goto ssl_create_connect_failed;
    }
    /* check client certificate and keyfile */
    if(!SSL_CTX_check_private_key(connection->context)) {
      goto ssl_create_connect_failed;
    }
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
  
  pending = MyMalloc(sizeof(*pending));
  if(!pending) {
    goto ssl_create_connect_failed;
  }
  pending->connection = sslconn;
  pending->next = firstPendingConection;
  firstPendingConection = pending;
  
  pending->data = data;
  
  return sslconn;
ssl_create_connect_failed:
  MyFree(connection);
  return NULL;
}

int ssl_start_handshake_connect(struct SSLConnection *connection) {
  return ssl_handshake_outgoing(connection);
}

struct SSLListener *ssl_create_listener(struct SSLConf *localcfg) {
  if(!ssl_is_initialized)
    ssl_init();
  
  struct SSLListener *listener = MyCalloc(1, sizeof(*listener));
  listener->context = SSL_CTX_new(SSLv23_server_method());
  if(!listener->context) {
    goto ssl_create_listener_failed;
  }
  
  ssl_merge_config(&listener->conf, &conf_get_local()->ssl);
  ssl_merge_cert_config(&listener->conf, &conf_get_local()->ssl);
  ssl_merge_config(&listener->conf, localcfg);
  ssl_merge_cert_config(&listener->conf, localcfg);
  
  char *certfile = listener->conf.certfile;
  char *keyfile = listener->conf.keyfile;
  char *cafile = listener->conf.cafile;
  
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
  
  ssl_apply_ctx_config(listener->context, &listener->conf);
  
  FlagSet(&listener->flags, SSLFLAG_READY);
  return listener;
ssl_create_listener_failed:
  MyFree(listener);
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
      
      return ssl_handshake_completed(connection, 1);
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
  struct SSLConnection *connection = MyCalloc(1, sizeof(*connection));
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
  
  pending = MyMalloc(sizeof(*pending));
  if(!pending) {
    goto ssl_start_handshake_listener_failed;
  }
  pending->listener = listener;
  pending->connection = connection;
  pending->next = firstPendingConection;
  firstPendingConection = pending;
  
  pending->data = data;
  
  ssl_handshake_incoming(connection);
  return connection;
ssl_start_handshake_listener_failed:
  MyFree(connection);
  return NULL;
}

int ssl_client_starttls(struct Client *client) {
  if(!cli_local(client))
    return 0;
  
  struct Connection *connect;
  struct Listener *listener;
  struct SSLPendingConections *pending = NULL;
  if(!(connect = cli_connect(client)) || con_ssl(connect))
    return 0;
  if(!(listener = con_listener(connect)))
    return 0;
  
  if(!FlagHas(&listener->flags, LISTEN_STARTTLS) || !listener->ssl_listener) {
    send_reply(client, ERR_STARTTLS, "STARTTLS not supported or disabled");
    return 0;
  }
  
  struct SSLConnection *connection = MyCalloc(1, sizeof(*connection));
  connection->session = SSL_new(listener->ssl_listener->context);
  if(!connection->session) {
    goto ssl_client_starttls_failed;
  }
  if(!SSL_set_fd(connection->session, cli_fd(client))) {
    goto ssl_client_starttls_failed;
  }
  FlagSet(&connection->flags, SSLFLAG_INCOMING);
  FlagSet(&connection->flags, SSLFLAG_STARTTLS);
  FlagSet(&connection->flags, SSLFLAG_HANDSHAKE);
  FlagSet(&connection->flags, SSLFLAG_HANDSHAKE_R);
  
  DBufClear(&(cli_recvQ(client)));

	send_reply(client, RPL_STARTTLS);
  send_queued(client);
  
  pending = MyMalloc(sizeof(*pending));
  if(!pending) {
    goto ssl_client_starttls_failed;
  }
  pending->listener = listener->ssl_listener;
  pending->connection = connection;
  pending->next = firstPendingConection;
  firstPendingConection = pending;
  
  pending->data = client;
  
  ssl_handshake_incoming(connection);
  return 1;
ssl_client_starttls_failed:
  MyFree(connection);
  return 0;
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

IOResult ssl_send_encrypt_plain(struct SSLConnection *connection, const char* buf, int len) {
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

const char *ssl_get_current_cipher(struct SSLConnection *connection) {
  return SSL_get_cipher_name(connection->session);
}

const char *ssl_get_fingerprint(struct SSLConnection *connection) { 
  return NULL; 
}

#else
// fallback dummy implementation

void ssl_free_connection(struct SSLConnection *connection) {};
void ssl_free_listener(struct SSLListener *listener) {};

struct SSLListener *ssl_create_listener() { return NULL; };
struct SSLConnection *ssl_create_connect(int fd, void *data) { return NULL; };

struct SSLConnection *ssl_start_handshake_listener(struct SSLListener *listener, int fd, void *data) { return NULL; };
int ssl_start_handshake_connect(struct SSLConnection *connection) { return -1; };
int ssl_client_starttls(struct Client *client) {
  send_reply(client, ERR_STARTTLS, "STARTTLS not supported");
  return 0;
}

IOResult ssl_recv_decrypt(struct SSLConnection *connection, char *buf, unsigned int buflen, unsigned int *len) { return IO_FAILURE; };
IOResult ssl_send_encrypt(struct SSLConnection *connection, struct MsgQ* buf, unsigned int *count_in, unsigned int *count_out) { return IO_FAILURE; };
IOResult ssl_send_encrypt_plain(struct SSLConnection *connection, const char *buf, int len) { return IO_FAILURE; };
int ssl_connection_flush(struct SSLConnection *connection) { return 0; };

const char *ssl_get_current_cipher(struct SSLConnection *connection) { return NULL; };
const char *ssl_get_fingerprint(struct SSLConnection *connection) { return NULL; };
#endif

