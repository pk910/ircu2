/** @file ssl.h
 * @brief Declarations for ssl handler.
 * @version $Id$
 */
#ifndef INCLUDED_ssl_h
#define INCLUDED_ssl_h
#include "ircd_osdep.h"
#include "s_conf.h"

enum SSLFlag {
  SSLFLAG_INCOMING,
  SSLFLAG_OUTGOING,
  SSLFLAG_STARTTLS,
  SSLFLAG_READY,
  SSLFLAG_HANDSHAKE,
  SSLFLAG_HANDSHAKE_R,
  SSLFLAG_HANDSHAKE_W,
  SSLFLAG_VERIFYCA,

  SSLFLAG_LAST
};

/** Declare flagset type for ssl flags. */
DECLARE_FLAGSET(SSLFlags, SSLFLAG_LAST);

#if defined(HAVE_OPENSSL_SSL_H)
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

struct SSLConnection {
  struct SSLFlags flags;
  SSL *session;
};

struct SSLOutConnection {
  struct SSLFlags flags;
  SSL *session;
  
  SSL_CTX *context;
  struct SSLConf conf;
  X509 *cacert;
};

struct SSLListener {
  struct SSLFlags flags;
  
  SSL *listener;
  SSL_CTX *context;
  
  struct SSLConf conf;
  X509 *cacert;
};

#else

struct SSLConnection {
  struct SSLFlags flags;
  //just unused
};

struct SSLOutConnection {
  struct SSLFlags flags;
  //just unused
};

struct SSLListener {
  struct SSLFlags flags;
  //just unused
};
#endif

#define ssl_handshake(x)   (FlagHas(&(x)->flags, SSLFLAG_HANDSHAKE))
#define ssl_wantwrite(x)   (FlagHas(&(x)->flags, SSLFLAG_HANDSHAKE_W))
#define ssl_wantread(x)   (FlagHas(&(x)->flags, SSLFLAG_HANDSHAKE_R))


extern void ssl_free_connection(struct SSLConnection *connection);
extern void ssl_free_listener(struct SSLListener *listener);

extern struct SSLListener *ssl_create_listener(struct SSLConf *config);
extern struct SSLConnection *ssl_create_connect(int fd, void *data, struct SSLConf *config);
extern int ssl_client_starttls(struct Client *client);

extern struct SSLConnection *ssl_start_handshake_listener(struct SSLListener *listener, int fd, void *data);
extern int ssl_start_handshake_connect(struct SSLConnection *connection);

IOResult ssl_recv_decrypt(struct SSLConnection *connection, char *buf, unsigned int buflen, unsigned int *len);
IOResult ssl_send_encrypt(struct SSLConnection *connection, struct MsgQ* buf, unsigned int *count_in, unsigned int *count_out);
IOResult ssl_send_encrypt_plain(struct SSLConnection *connection, const char *buf, int len);
extern int ssl_connection_flush(struct SSLConnection *connection);

extern const char *ssl_get_current_cipher(struct SSLConnection *connection);
extern const char *ssl_get_fingerprint(struct SSLConnection *connection);

#endif /* INCLUDED_parse_h */
