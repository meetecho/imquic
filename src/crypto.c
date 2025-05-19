/*! \file   crypto.c
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright MIT License
 * \brief  QUIC cryptographic utilities
 * \details Cryptographic utilities for QUIC. This is where contexts for
 * taking care of header protection and encryption at different levels
 * are provided, with helper functions exposed to the internal QUIC stack.
 *
 * \ingroup Core
 */

#include "internal/quic.h"
#include "internal/crypto.h"
#include "internal/qlog.h"
#include "internal/utils.h"
#include "internal/version.h"
#include "imquic/debug.h"

/* https://www.rfc-editor.org/rfc/rfc9001#section-5.2 */
static const uint8_t imquicv1_salt[20] = {
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
	0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a
};

/* https://www.rfc-editor.org/rfc/rfc9001#section-5.8 */
static const uint8_t imquicv1_retry_key[16] = {
	0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a,
	0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e
};
static const uint8_t imquicv1_retry_nonce[12] = {
	0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63,
	0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb
};

/* SSL encryption levels as a string */
const char *imquic_encryption_level_str(enum ssl_encryption_level_t level) {
	switch(level) {
		case ssl_encryption_initial:
			return "initial";
		case ssl_encryption_early_data:
			return "early_data";
		case ssl_encryption_handshake:
			return "handshake";
		case ssl_encryption_application:
			return "application";
		default: break;
	}
	return NULL;
}

const char *imquic_encryption_key_type_str(enum ssl_encryption_level_t level, gboolean server) {
	switch(level) {
		case ssl_encryption_initial:
			return server ? "server_initial_secret" : "client_initial_secret";
		case ssl_encryption_early_data:
			return server ? "server_0rtt_secret" : "client_0rtt_secret";
		case ssl_encryption_handshake:
			return server ? "server_handshake_secret" : "client_handshake_secret";
		case ssl_encryption_application:
			return server ? "server_1rtt_secret" : "client_1rtt_secret";
		default: break;
	}
	return NULL;
}

/* Callbacks to handle QUIC encryption */
static int imquic_tls_set_read_secret(SSL *ssl, enum ssl_encryption_level_t level,
	const SSL_CIPHER *cipher, const uint8_t *read_secret, size_t secret_len);
static int imquic_tls_set_write_secret(SSL *ssl, enum ssl_encryption_level_t level,
	const SSL_CIPHER *cipher, const uint8_t *write_secret, size_t secret_len);
#ifndef IMQUIC_BORINGSSL
static int imquic_tls_set_encryption_secrets(SSL *ssl, enum ssl_encryption_level_t level,
	const uint8_t *read_secret, const uint8_t *write_secret, size_t secret_len);
#endif
static int imquic_tls_add_handshake_data(SSL *ssl, enum ssl_encryption_level_t level,
	const uint8_t *data, size_t len);
static int imquic_tls_flush_flight(SSL *ssl);
static int imquic_tls_send_alert(SSL *ssl, enum ssl_encryption_level_t level, uint8_t alert);
static const SSL_QUIC_METHOD imquic_quic_method = {
#ifdef IMQUIC_BORINGSSL
	.set_read_secret = imquic_tls_set_read_secret,
	.set_write_secret = imquic_tls_set_write_secret,
#else
	.set_encryption_secrets = imquic_tls_set_encryption_secrets,
#endif
	.add_handshake_data = imquic_tls_add_handshake_data,
	.flush_flight = imquic_tls_flush_flight,
	.send_alert = imquic_tls_send_alert
};

/* TLS */
static FILE *keylog_file = NULL;
static void imquic_keylog_cb(const SSL *ssl, const char *line) {
	if(keylog_file != NULL) {
		fprintf(keylog_file, "%s\n", line);
		fflush(keylog_file);
	}
}
static int imquic_tls_load_keys(const char *server_pem, const char *server_key, const char *password,
		X509 **certificate, EVP_PKEY **private_key) {
	FILE *f = fopen(server_pem, "r");
	if(f == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_FATAL, "Error opening certificate file (%s)\n", g_strerror(errno));
		goto error;
	}
	*certificate = PEM_read_X509(f, NULL, NULL, NULL);
	if(*certificate == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_FATAL, "PEM_read_X509 failed\n");
		goto error;
	}
	fclose(f);
	f = fopen(server_key, "r");
	if(f == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_FATAL, "Error opening key file (%s)\n", g_strerror(errno));
		goto error;
	}
	*private_key = PEM_read_PrivateKey(f, NULL, NULL, (void *)password);
	if(*private_key == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_FATAL, "PEM_read_PrivateKey failed\n");
		goto error;
	}
	fclose(f);
	/* Done */
	return 0;

error:
	if(*certificate) {
		X509_free(*certificate);
		*certificate = NULL;
	}
	if(*private_key) {
		EVP_PKEY_free(*private_key);
		*private_key = NULL;
	}
	return -1;
}
static const char *h3_alpn = "h3";
static int imquic_select_alpn(SSL *ssl, const unsigned char **out, unsigned char *outlen,
		const unsigned char *in, unsigned int inlen, void *arg) {
	imquic_connection *conn = SSL_get_app_data(ssl);
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "[%s] ALPN selection (inlen=%u)\n",
		imquic_get_connection_name(conn), inlen);
	imquic_print_hex(IMQUIC_LOG_HUGE, (uint8_t *)in, inlen);
	uint8_t lp;
	char alpn[256];
	size_t alpn_len = sizeof(alpn);
	const unsigned char *p = in, *selected = NULL;
	unsigned int tot = inlen, selected_len = 0;
	while(tot > 0) {
		lp = *p;
		if(lp == 0)
			break;
		p++;
		g_snprintf(alpn, alpn_len, "%.*s", lp, (char *)p);
		IMQUIC_LOG(IMQUIC_LOG_HUGE, "[%s][%u] %s\n",
			imquic_get_connection_name(conn), lp, alpn);
		if(conn->socket->raw_quic && !strcasecmp(alpn, conn->socket->alpn)) {
			IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Negotiated ALPN: %s\n",
				imquic_get_connection_name(conn), alpn);
			conn->alpn_negotiated = TRUE;
			selected = p;
			selected_len = lp;
			break;
		}
		if(conn->socket->webtransport && !strcasecmp(alpn, h3_alpn)) {
			IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Negotiated ALPN: %s\n",
				imquic_get_connection_name(conn), alpn);
			conn->alpn_negotiated = TRUE;
			conn->http3 = imquic_http3_connection_create(conn, conn->socket->subprotocol);
			selected = p;
			selected_len = lp;
			break;
		}
		tot -= (lp + 1);
		p += lp;
	}
	if(selected == NULL || selected_len == 0) {
		/* No match */
		return SSL_TLSEXT_ERR_ALERT_FATAL;
	}
#ifdef HAVE_QLOG
	if(conn->qlog != NULL && conn->qlog->quic) {
		imquic_qlog_alpn_information(conn->qlog,
			conn->alpn.buffer, conn->alpn.length, (uint8_t *)in, inlen, alpn);
	}
#endif
	/* Return the selected ALPN */
	if(out)
		*out = selected;
	if(outlen)
		*outlen = selected_len;
	return SSL_TLSEXT_ERR_OK;
}

/* TLS stack init */
int imquic_tls_init(const char *secrets_log) {
	SSL_load_error_strings();
	ERR_load_crypto_strings();
	if(keylog_file != NULL)
		return -1;
	if(secrets_log) {
		keylog_file = fopen(secrets_log, "a");
		if(keylog_file == NULL) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "Couldn't create secrets log file '%s'... %d (%s)\n",
				secrets_log, errno, g_strerror(errno));
			return -1;
		}
	}
	return 0;
}

void imquic_tls_deinit(void) {
	if(keylog_file != NULL)
		fclose(keylog_file);
}

/* TLS context management */
imquic_tls *imquic_tls_create(gboolean is_server, const char *server_pem, const char *server_key, const char *password) {
	if(is_server && (server_pem == NULL || server_key == NULL)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "Missing certificate/key for server TLS stack\n");
		return NULL;
	}
	imquic_tls *tls = g_malloc0(sizeof(imquic_tls));
	tls->is_server = is_server;
	tls->ssl_ctx = SSL_CTX_new(is_server ? TLS_server_method() : TLS_client_method());
	SSL_CTX_set_keylog_callback(tls->ssl_ctx, imquic_keylog_cb);
	SSL_CTX_set_default_verify_paths(tls->ssl_ctx);
	SSL_CTX_set_verify(tls->ssl_ctx, SSL_VERIFY_NONE, NULL);
	SSL_CTX_set_min_proto_version(tls->ssl_ctx, TLS1_3_VERSION);
	SSL_CTX_set_max_proto_version(tls->ssl_ctx, TLS1_3_VERSION);
	SSL_CTX_set_quic_method(tls->ssl_ctx, &imquic_quic_method);
#ifndef IMQUIC_BORINGSSL
	SSL_CTX_set_ciphersuites(tls->ssl_ctx, "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256");
#endif
	if(is_server) {
		SSL_CTX_set_options(tls->ssl_ctx,
			(SSL_OP_ALL & ~SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS)
				| SSL_OP_SINGLE_ECDH_USE
				| SSL_OP_CIPHER_SERVER_PREFERENCE
#ifndef IMQUIC_BORINGSSL
				| SSL_OP_NO_ANTI_REPLAY
#endif
		);
#ifndef IMQUIC_BORINGSSL
		SSL_CTX_clear_options(tls->ssl_ctx, SSL_OP_ENABLE_MIDDLEBOX_COMPAT);
#endif
		SSL_CTX_set_mode(tls->ssl_ctx, SSL_MODE_RELEASE_BUFFERS);
		SSL_CTX_set_alpn_select_cb(tls->ssl_ctx, imquic_select_alpn, NULL);
	}
	if(server_pem != NULL && server_key != NULL) {
		IMQUIC_LOG(IMQUIC_LOG_VERB, "Using certificate file '%s'\n", server_pem);
		IMQUIC_LOG(IMQUIC_LOG_VERB, "Using key file '%s'\n", server_key);
		if(imquic_tls_load_keys(server_pem, server_key, password, &tls->ssl_cert, &tls->ssl_key) != 0) {
			imquic_tls_destroy(tls);
			return NULL;
		}
		if(SSL_CTX_use_certificate(tls->ssl_ctx, tls->ssl_cert) == 0) {
			IMQUIC_LOG(IMQUIC_LOG_FATAL, "Certificate error (%s)\n", ERR_reason_error_string(ERR_get_error()));
			imquic_tls_destroy(tls);
			return NULL;
		}
		if(SSL_CTX_use_PrivateKey(tls->ssl_ctx, tls->ssl_key) == 0) {
			IMQUIC_LOG(IMQUIC_LOG_FATAL, "Certificate key error (%s)\n", ERR_reason_error_string(ERR_get_error()));
			imquic_tls_destroy(tls);
			return NULL;
		}
		if(SSL_CTX_check_private_key(tls->ssl_ctx) == 0) {
			IMQUIC_LOG(IMQUIC_LOG_FATAL, "Certificate check error (%s)\n", ERR_reason_error_string(ERR_get_error()));
			imquic_tls_destroy(tls);
			return NULL;
		}
	} else {
		tls->ssl_cert = NULL;
		tls->ssl_key = NULL;
	}
	/* Done */
	return tls;
}

SSL *imquic_tls_new_ssl(imquic_tls *tls) {
	if(tls == NULL || tls->ssl_ctx == NULL)
		return NULL;
	SSL *ssl = SSL_new(tls->ssl_ctx);
	if(ssl == NULL)
		return NULL;
	SSL_clear_options(ssl, SSL_OP_NO_TLSv1_3);
#ifndef IMQUIC_BORINGSSL
	SSL_set_quic_transport_version(ssl, 1);
#endif
	if(tls->is_server) {
		SSL_set_accept_state(ssl);
		if(tls->early_data) {
#ifndef IMQUIC_BORINGSSL
			/* Enable early data */
			SSL_set_quic_early_data_enabled(ssl, 1);
#endif
		}
	} else {
		SSL_set_connect_state(ssl);
		if(tls->early_data) {
#ifndef IMQUIC_BORINGSSL
			/* Early data is enabled, try reading the ticket file */
			BIO *f = BIO_new_file(tls->ticket_file, "r");
			if(f == NULL) {
				/* Maybe this is the first time, and we don't have a ticket file yet? */
				IMQUIC_LOG(IMQUIC_LOG_VERB, "Error reading ticket file: %s\n", g_strerror(errno));
			} else {
				/* Read the session and restore it */
				SSL_SESSION *session = PEM_read_bio_SSL_SESSION(f, NULL, 0, NULL);
				BIO_free(f);
				if(!SSL_set_session(ssl, session)) {
					IMQUIC_LOG(IMQUIC_LOG_WARN, "Could not restore session\n");
				} else if(SSL_SESSION_get_max_early_data(session)) {
					SSL_set_quic_early_data_enabled(ssl, 1);
				}
				SSL_SESSION_free(session);
			}
#endif
		}
	}
	return ssl;
}

void imquic_tls_destroy(imquic_tls *tls) {
	if(tls == NULL)
		return;
	if(tls->ssl_cert != NULL)
		X509_free(tls->ssl_cert);
	if(tls->ssl_key != NULL)
		EVP_PKEY_free(tls->ssl_key);
	if(tls->ssl_ctx != NULL)
		SSL_CTX_free(tls->ssl_ctx);
	g_free(tls->ticket_file);
	g_free(tls);
}

/* Early data management */
#ifndef IMQUIC_BORINGSSL
static int imquic_tls_new_session_cb(SSL *ssl, SSL_SESSION *session) {
	imquic_connection *conn = SSL_get_app_data(ssl);
	/* FIXME Should we give up is max_early_data_size is not what it should be? */
	if(SSL_SESSION_get_max_early_data(session) != 0xffffffff) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] Server isn't advertising support for early-data\n", conn->name);
	}
	/* Save the ticket data to file */
	BIO *f = BIO_new_file(conn->socket->tls->ticket_file, "w");
	if(f == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] Couldn't open file: %s\n", conn->name, g_strerror(errno));
		return 0;
	}
	if(!PEM_write_bio_SSL_SESSION(f, session)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] Couldn't save TLS session to file\n", conn->name);
	}
	BIO_free(f);
	return 0;
}

static int imquic_tls_generate_ticket_cb(SSL *ssl, void *arg) {
	return SSL_SESSION_set1_ticket_appdata(SSL_get0_session(ssl),
		imquic_name, strlen(imquic_name));
}

static SSL_TICKET_RETURN imquic_tls_decrypt_ticket_cb(SSL *ssl, SSL_SESSION *session,
		const unsigned char *keyname, size_t keynamelen, SSL_TICKET_STATUS status, void *arg) {
	imquic_connection *conn = SSL_get_app_data(ssl);
	if(status == SSL_TICKET_EMPTY || status == SSL_TICKET_NO_DECRYPT)
		return SSL_TICKET_RETURN_IGNORE_RENEW;
	char *name = NULL;
	size_t name_len = 0;
	if(SSL_SESSION_get0_ticket_appdata(session, (void **)&name, &name_len) == 0) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] SSL_SESSION_get0_ticket_appdata failed\n", conn->name);
		if(status == SSL_TICKET_SUCCESS)
			return SSL_TICKET_RETURN_IGNORE;
		return SSL_TICKET_RETURN_IGNORE_RENEW;
	}
	if(status == SSL_TICKET_SUCCESS)
		return SSL_TICKET_RETURN_USE;
	return SSL_TICKET_RETURN_USE_RENEW;
}
#endif

int imquic_tls_enable_early_data(imquic_tls *tls, const char *ticket_file) {
	if(tls == NULL || tls->early_data)
		return -1;
#ifdef IMQUIC_BORINGSSL
	IMQUIC_LOG(IMQUIC_LOG_WARN, "Early data currently unsupported when using BoringSSL\n");
	return -1;
#else
	tls->early_data = TRUE;
	if(ticket_file != NULL)
		tls->ticket_file = g_strdup(ticket_file);
	if(tls->is_server) {
		/* Advertise support for early data, and configure the ticket callbacks */
		SSL_CTX_set_session_id_context(tls->ssl_ctx, (const unsigned char *)imquic_name, strlen(imquic_name));
		SSL_CTX_set_max_early_data(tls->ssl_ctx, 0xffffffff);
		SSL_CTX_set_session_ticket_cb(tls->ssl_ctx,
			imquic_tls_generate_ticket_cb, imquic_tls_decrypt_ticket_cb, NULL);
	} else {
		/* Enable caching and intercept the session to save it to file */
		SSL_CTX_set_session_cache_mode(tls->ssl_ctx, SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL);
		SSL_CTX_sess_set_new_cb(tls->ssl_ctx, imquic_tls_new_session_cb);
	}
	return 0;
#endif
}

/* HKDF utilities */
int imquic_build_hkdf_label(const char *label, uint8_t *hkdf_label, size_t buflen, size_t outlen) {
	/* TODO We should ensure we don't overflow hkdf_label (whose size is buflen) */
	const char *prefix = "tls13 ";
	size_t plen = strlen(prefix);
	size_t llen = strlen(label);
	size_t len = 2 + 1 + plen + llen + 1;
	outlen = g_htons(outlen);
	memcpy(&hkdf_label[0], &outlen, 2);
	hkdf_label[2] = plen + llen;
	memcpy(&hkdf_label[3], prefix, plen);
	memcpy(&hkdf_label[3 + plen], label, llen);
	hkdf_label[3 + plen + llen] = 0;	/* FIXME */
	return len;
}

int imquic_hkdf_extract(const EVP_MD *digest, uint8_t *key, size_t keylen, uint8_t *out, size_t *outlen) {
#ifdef IMQUIC_BORINGSSL
	int res = HKDF_extract(out, outlen, digest, key, keylen, (uint8_t *)&imquicv1_salt, sizeof(imquicv1_salt));
	return res == 0 ? -1 : 0;
#else
	EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
	if(pctx == NULL)
		return -1;
	if(EVP_PKEY_derive_init(pctx) <= 0 ||
			EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) <= 0 ||
			EVP_PKEY_CTX_set_hkdf_md(pctx, digest) <= 0 ||
			EVP_PKEY_CTX_set1_hkdf_key(pctx, key, keylen) <= 0 ||
			EVP_PKEY_CTX_set1_hkdf_salt(pctx, (uint8_t *)&imquicv1_salt, sizeof(imquicv1_salt)) <= 0 ||
			EVP_PKEY_derive(pctx, out, outlen) <= 0) {
		EVP_PKEY_CTX_free(pctx);
		return -1;
	}
	EVP_PKEY_CTX_free(pctx);
	return 0;
#endif
}

int imquic_hkdf_expand_label(const EVP_MD *digest, uint8_t *key, size_t keylen, const char *label, uint8_t *out, size_t outlen) {
	uint8_t hkdf_label[30];
	size_t hkdf_label_len = imquic_build_hkdf_label(label, hkdf_label, sizeof(hkdf_label), outlen);
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- HKDF Label (%s, %zu)\n", label, hkdf_label_len);
	imquic_print_hex(IMQUIC_LOG_HUGE, hkdf_label, hkdf_label_len);
#ifdef IMQUIC_BORINGSSL
	int res = HKDF_expand(out, outlen, digest, key, keylen, hkdf_label, hkdf_label_len);
	return res == 0 ? -1 : 0;
#else
	EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
	if(pctx == NULL)
		return -1;
	if(EVP_PKEY_derive_init(pctx) <= 0 ||
			EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) <= 0 ||
			EVP_PKEY_CTX_set_hkdf_md(pctx, digest) <= 0 ||
			EVP_PKEY_CTX_set1_hkdf_key(pctx, key, keylen) <= 0 ||
			EVP_PKEY_CTX_add1_hkdf_info(pctx, hkdf_label, hkdf_label_len) <= 0 ||
			EVP_PKEY_derive(pctx, out, &outlen) <= 0) {
		EVP_PKEY_CTX_free(pctx);
		return -1;
	}
	EVP_PKEY_CTX_free(pctx);
	return 0;
#endif
}

int imquic_derive_initial_secret(imquic_protection *p, uint8_t *dcid, size_t dcid_len, gboolean is_server) {
	if(p == NULL)
		return -1;
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- Deriving initial secret from Destination ID (%zu)\n", dcid_len);
	imquic_print_hex(IMQUIC_LOG_HUGE, dcid, dcid_len);
	/* Prepare the digest */
	const EVP_MD *md = EVP_sha256();
	/* Initial secret first */
	uint8_t initial[32];
	size_t initial_len = sizeof(initial);
	if(imquic_hkdf_extract(md, dcid, dcid_len, initial, &initial_len) < 0) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "imquic_hkdf_extract error: %s\n", ERR_reason_error_string(ERR_get_error()));
		return -1;
	}
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- Initial Secret (%zu)\n", initial_len);
	imquic_print_hex(IMQUIC_LOG_HUGE, initial, initial_len);

	p->local.md = p->remote.md = md;
	p->local.secret_len = p->remote.secret_len = 32;
	p->local.key_len = p->remote.key_len = 16;
	p->local.iv_len = p->remote.iv_len = 12;
	p->local.hp_len = p->remote.hp_len = 16;

	/* Client initial secret */
	uint8_t *client_secret = is_server ? p->remote.secret[0] : p->local.secret[0];
	size_t client_secret_len = is_server ? p->remote.secret_len : p->local.secret_len;
	if(imquic_hkdf_expand_label(md, initial, initial_len, "client in", client_secret, client_secret_len) < 0) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "imquic_hkdf_expand_label error: %s\n", ERR_reason_error_string(ERR_get_error()));
		return -1;
	}
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- Client Initial Secret (%zu)\n", client_secret_len);
	imquic_print_hex(IMQUIC_LOG_HUGE, client_secret, client_secret_len);

	/* Server initial secret */
	uint8_t *server_secret = is_server ? p->local.secret[0] : p->remote.secret[0];
	size_t server_secret_len = is_server ? p->local.secret_len : p->remote.secret_len;
	if(imquic_hkdf_expand_label(md, initial, initial_len, "server in", server_secret, server_secret_len) < 0) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "imquic_hkdf_expand_label error: %s\n", ERR_reason_error_string(ERR_get_error()));
		return -1;
	}
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- Server Initial Secret (%zu)\n", server_secret_len);
	imquic_print_hex(IMQUIC_LOG_HUGE, server_secret, server_secret_len);

	/* Now expand the key, iv and hp for both */
	int ret = imquic_expand_secret("Client", &p->remote, TRUE, 0);
	if(ret < 0)
		return ret;
	return imquic_expand_secret("Server", &p->local, TRUE, 0);
}

int imquic_expand_secret(const char *name, imquic_encryption *e, gboolean expand_hp, gboolean phase) {
	if(e == NULL)
		return -1;
	/* Client key, iv, hp */
	if(imquic_hkdf_expand_label(e->md, e->secret[phase], e->secret_len, "quic key", e->key[phase], e->key_len) < 0) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "imquic_hkdf_expand_label error: %s\n", ERR_reason_error_string(ERR_get_error()));
		return -1;
	}
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- %s key (%zu)\n", name, e->key_len);
	imquic_print_hex(IMQUIC_LOG_HUGE, e->key[phase], e->key_len);
	if(imquic_hkdf_expand_label(e->md, e->secret[phase], e->secret_len, "quic iv", e->iv[phase], e->iv_len) < 0) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "imquic_hkdf_expand_label error: %s\n", ERR_reason_error_string(ERR_get_error()));
		return -1;
	}
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- %s iv (%zu)\n", name, e->iv_len);
	imquic_print_hex(IMQUIC_LOG_HUGE, e->iv[phase], e->iv_len);
	if(expand_hp) {
		if(imquic_hkdf_expand_label(e->md, e->secret[phase], e->secret_len, "quic hp", e->hp, e->hp_len) < 0) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "imquic_hkdf_expand_label error: %s\n", ERR_reason_error_string(ERR_get_error()));
			return -1;
		}
		IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- %s hp (%zu)\n", name, e->hp_len);
		imquic_print_hex(IMQUIC_LOG_HUGE, e->hp, e->hp_len);
	}
	/* Done */
	return 0;
}

/* Key update */
int imquic_update_keys(imquic_protection *p, gboolean phase) {
	/* https://www.rfc-editor.org/rfc/rfc9001#section-6.1
	 * secret_<n+1> = HKDF-Expand-Label(secret_<n>, "quic ku", "", Hash.length) */
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "Updating keys to phase %d\n", phase);
	if(imquic_hkdf_expand_label(p->local.md, p->local.secret[!phase], p->local.secret_len, "quic ku", p->local.secret[phase], p->local.secret_len) < 0) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "imquic_hkdf_expand_label error: %s\n", ERR_reason_error_string(ERR_get_error()));
		return -1;
	}
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- Previous local secret\n");
	imquic_print_hex(IMQUIC_LOG_HUGE, p->local.secret[!phase], p->local.secret_len);
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- New local secret\n");
	imquic_print_hex(IMQUIC_LOG_HUGE, p->local.secret[phase], p->local.secret_len);
	if(imquic_hkdf_expand_label(p->remote.md, p->remote.secret[!phase], p->remote.secret_len, "quic ku", p->remote.secret[phase], p->remote.secret_len) < 0) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "imquic_hkdf_expand_label error: %s\n", ERR_reason_error_string(ERR_get_error()));
		return -1;
	}
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- Previous remote secret\n");
	imquic_print_hex(IMQUIC_LOG_HUGE, p->remote.secret[!phase], p->remote.secret_len);
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- New remote secret\n");
	imquic_print_hex(IMQUIC_LOG_HUGE, p->remote.secret[phase], p->remote.secret_len);
	/* Now expand the key and iv */
	int ret = imquic_expand_secret("Client", &p->remote, FALSE, phase);
	if(ret < 0)
		return ret;
	return imquic_expand_secret("Server", &p->local, FALSE, phase);
}

/* Unprotect and protect headers */
int imquic_unprotect_header(uint8_t *bytes, size_t blen, size_t pn_offset, uint8_t *hp, size_t hp_len) {
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "Unprotecting header\n");
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- HP\n");
	imquic_print_hex(IMQUIC_LOG_HUGE, hp, hp_len);
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- PN Offset:   %zu\n", pn_offset);
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- Sample\n");
	imquic_print_hex(IMQUIC_LOG_HUGE, bytes + pn_offset + 4, 16);
	/* Use AES-ECB to generate the mask from the header protection key and the sample */
	EVP_CIPHER_CTX *hp_ctx = EVP_CIPHER_CTX_new();
	if(EVP_EncryptInit_ex(hp_ctx, (hp_len == 16 ? EVP_aes_128_ecb() : EVP_aes_256_ecb()), NULL, hp, NULL) == 0) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "EVP_EncryptInit_ex error: %s\n", ERR_reason_error_string(ERR_get_error()));
		return -1;
	}
	uint8_t mask[100];
	int mask_len = sizeof(mask);
	if(EVP_EncryptUpdate(hp_ctx, mask, &mask_len, bytes + pn_offset + 4, 16) == 0) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "EVP_EncryptUpdate error: %s\n", ERR_reason_error_string(ERR_get_error()));
		return -1;
	}
	EVP_CIPHER_CTX_free(hp_ctx);
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "Mask (first byte)\n");
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- " BYTE_TO_BINARY_PATTERN "\n", BYTE_TO_BINARY(mask[0]));
	/* Use the mask to remove the protection from the first byte and the packet number */
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "%02x (pre-mask)\n", bytes[0]);
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- " BYTE_TO_BINARY_PATTERN "\n", BYTE_TO_BINARY(bytes[0]));
	if(bytes[0] & 0x80) {
		/* Long header */
		bytes[0] ^= mask[0] & 0x0F;
	} else {
		/* Short header */
		bytes[0] ^= mask[0] & 0x1F;
	}
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "%02x (post-mask)\n", bytes[0]);
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- " BYTE_TO_BINARY_PATTERN "\n", BYTE_TO_BINARY(bytes[0]));
	/* Read the unprotected packet number length */
	uint8_t pn_length = (bytes[0] & 0x03) + 1;
	/* Apply the mask to the packet number too */
	imquic_print_hex(IMQUIC_LOG_HUGE, &bytes[pn_offset], pn_length);
	for(uint8_t i=0; i<pn_length; i++)
		bytes[pn_offset+i] ^= mask[i+1];
	imquic_print_hex(IMQUIC_LOG_HUGE, &bytes[pn_offset], pn_length);

	return 0;
}

/* Decrypt and encrypt payloads */
int imquic_protect_header(uint8_t *bytes, size_t blen, size_t pn_offset, uint8_t *hp, size_t hp_len) {
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "Protecting header\n");
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- HP\n");
	imquic_print_hex(IMQUIC_LOG_HUGE, hp, hp_len);
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- PN Offset:   %zu\n", pn_offset);
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- Sample\n");
	imquic_print_hex(IMQUIC_LOG_HUGE, bytes + pn_offset + 4, 16);
	uint8_t pn_length = (bytes[0] & 0x03) + 1;
	/* Use AES-ECB to generate the mask from the header protection key and the sample */
	EVP_CIPHER_CTX *hp_ctx = EVP_CIPHER_CTX_new();
	if(EVP_EncryptInit_ex(hp_ctx, (hp_len == 16 ? EVP_aes_128_ecb() : EVP_aes_256_ecb()), NULL, hp, NULL) == 0) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "EVP_EncryptInit_ex error: %s\n", ERR_reason_error_string(ERR_get_error()));
		return -1;
	}
	uint8_t mask[100];
	int mask_len = sizeof(mask);
	if(EVP_EncryptUpdate(hp_ctx, mask, &mask_len, bytes + pn_offset + 4, 16) == 0) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "EVP_EncryptUpdate error: %s\n", ERR_reason_error_string(ERR_get_error()));
		return -1;
	}
	EVP_CIPHER_CTX_free(hp_ctx);
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "Mask (first byte)\n");
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- " BYTE_TO_BINARY_PATTERN "\n", BYTE_TO_BINARY(mask[0]));
	/* Use the mask to remove the protection from the first byte and the packet number */
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "%02x (pre-mask)\n", bytes[0]);
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- " BYTE_TO_BINARY_PATTERN "\n", BYTE_TO_BINARY(bytes[0]));
	if(bytes[0] & 0x80) {
		/* Long header */
		bytes[0] ^= mask[0] & 0x0F;
	} else {
		/* Short header */
		bytes[0] ^= mask[0] & 0x1F;
	}
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "%02x (post-mask)\n", bytes[0]);
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- " BYTE_TO_BINARY_PATTERN "\n", BYTE_TO_BINARY(bytes[0]));
	/* Apply the mask to the packet number too */
	imquic_print_hex(IMQUIC_LOG_HUGE, &bytes[pn_offset], pn_length);
	for(uint8_t i=0; i<pn_length; i++)
		bytes[pn_offset+i] ^= mask[i+1];
	imquic_print_hex(IMQUIC_LOG_HUGE, &bytes[pn_offset], pn_length);

	return 0;
}

int imquic_decrypt_payload(uint8_t *bytes, size_t blen, uint8_t *to, size_t tlen, uint8_t *header, size_t hlen, uint64_t pn, uint8_t *key, size_t key_len, uint8_t *iv, size_t iv_len) {
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "Decrypting payload (%zu bytes)\n", blen);
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- Header length (for tag): %zu\n", hlen);
	/* Prepare the nonce */
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- Key\n");
	imquic_print_hex(IMQUIC_LOG_HUGE, key, key_len);
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- IV\n");
	imquic_print_hex(IMQUIC_LOG_HUGE, iv, iv_len);
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- PKN: %"SCNu64"\n", pn);
	uint8_t nonce[12];
	memcpy(nonce, iv, sizeof(nonce));
	//~ nonce[10] ^= (pn & 0xff) >> 8;
	//~ nonce[11] ^= (pn & 0xff);
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "%u, %u, %u, %u, %u, %u, %u, %u\n",
		(uint8_t)(pn >> 56), (uint8_t)(pn >> 48), (uint8_t)(pn >> 40), (uint8_t)(pn >> 32),
		(uint8_t)(pn >> 24), (uint8_t)(pn >> 16), (uint8_t)(pn >> 8), (uint8_t)(pn));
	nonce[4] ^= (uint8_t)(pn >> 56);
	nonce[5] ^= (uint8_t)(pn >> 48);
	nonce[6] ^= (uint8_t)(pn >> 40);
	nonce[7] ^= (uint8_t)(pn >> 32);
	nonce[8] ^= (uint8_t)(pn >> 24);
	nonce[9] ^= (uint8_t)(pn >> 16);
	nonce[10] ^= (uint8_t)(pn >> 8);
	nonce[11] ^= (uint8_t)(pn);
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- Nonce\n");
	imquic_print_hex(IMQUIC_LOG_HUGE, nonce, 12);
	/* Decrypt the payload using the client key and nonce (iv) */
	EVP_CIPHER_CTX *pl_ctx = EVP_CIPHER_CTX_new();
	if(EVP_DecryptInit_ex(pl_ctx, (key_len == 16 ? EVP_aes_128_gcm() : EVP_aes_256_gcm()), NULL, key, nonce) == 0) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "EVP_DecryptInit_ex error: %s\n", ERR_reason_error_string(ERR_get_error()));
		EVP_CIPHER_CTX_free(pl_ctx);
		return -1;
	}
	/* We pass the header as AAD for the authentication */
	int d_len = 0;
	if(EVP_DecryptUpdate(pl_ctx, NULL, &d_len, header, hlen) == 0) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[AAD] EVP_EncryptUpdate error: %s\n", ERR_reason_error_string(ERR_get_error()));
		EVP_CIPHER_CTX_free(pl_ctx);
		return -1;
	}
	/* Decrypt the payload first */
	if(EVP_DecryptUpdate(pl_ctx, to, &d_len, bytes, blen - 16) == 0) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "EVP_DecryptUpdate error: %s\n", ERR_reason_error_string(ERR_get_error()));
		EVP_CIPHER_CTX_free(pl_ctx);
		return -1;
	}
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- Decrypted to %d bytes, checking tag now\n", d_len);
	/* Check the tag */
	if(EVP_CIPHER_CTX_ctrl(pl_ctx, EVP_CTRL_GCM_SET_TAG, 16, bytes + d_len) == 0) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "EVP_CIPHER_CTX_ctrl error: %s\n", ERR_reason_error_string(ERR_get_error()));
		EVP_CIPHER_CTX_free(pl_ctx);
		return -1;
	}
	int t_len = 0;
	int ret = EVP_DecryptFinal_ex(pl_ctx, to + d_len, &t_len);
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- -- Tag check return value: %d\n", ret);
	if(ret == 0) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "EVP_DecryptFinal_ex error: %s\n", ERR_reason_error_string(ERR_get_error()));
		imquic_print_hex(IMQUIC_LOG_INFO, to, d_len);
		EVP_CIPHER_CTX_free(pl_ctx);
		return -1;
	}
	EVP_CIPHER_CTX_free(pl_ctx);
	return d_len;
}

int imquic_encrypt_payload(uint8_t *bytes, size_t blen, uint8_t *to, size_t tlen, uint8_t *header, size_t hlen, uint64_t pn, uint8_t *key, size_t key_len, uint8_t *iv, size_t iv_len) {
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "Encrypting payload (%zu bytes)\n", blen);
	/* Prepare the nonce */
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- Key\n");
	imquic_print_hex(IMQUIC_LOG_HUGE, key, key_len);
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- IV\n");
	imquic_print_hex(IMQUIC_LOG_HUGE, iv, iv_len);
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- PKN: %"SCNu64"\n", pn);
	uint8_t nonce[12];
	memcpy(nonce, iv, sizeof(nonce));
	//~ nonce[10] ^= (pn & 0xff) >> 8;
	//~ nonce[11] ^= (pn & 0xff);
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "%u, %u, %u, %u, %u, %u, %u, %u\n",
		(uint8_t)(pn >> 56), (uint8_t)(pn >> 48), (uint8_t)(pn >> 40), (uint8_t)(pn >> 32),
		(uint8_t)(pn >> 24), (uint8_t)(pn >> 16), (uint8_t)(pn >> 8), (uint8_t)(pn));
	nonce[4] ^= (uint8_t)(pn >> 56);
	nonce[5] ^= (uint8_t)(pn >> 48);
	nonce[6] ^= (uint8_t)(pn >> 40);
	nonce[7] ^= (uint8_t)(pn >> 32);
	nonce[8] ^= (uint8_t)(pn >> 24);
	nonce[9] ^= (uint8_t)(pn >> 16);
	nonce[10] ^= (uint8_t)(pn >> 8);
	nonce[11] ^= (uint8_t)(pn);
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- Nonce\n");
	imquic_print_hex(IMQUIC_LOG_HUGE, nonce, 12);
	/* Encrypt the payload using the client key and nonce (iv) */
	EVP_CIPHER_CTX *pl_ctx = EVP_CIPHER_CTX_new();
	if(EVP_EncryptInit_ex(pl_ctx, (key_len == 16 ? EVP_aes_128_gcm() : EVP_aes_256_gcm()), NULL, key, nonce) == 0) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "EVP_EncryptInit_ex error: %s\n", ERR_reason_error_string(ERR_get_error()));
		EVP_CIPHER_CTX_free(pl_ctx);
		return -1;
	}
	/* We pass the header as AAD for the authentication */
	int d_len = 0;
	if(EVP_EncryptUpdate(pl_ctx, NULL, &d_len, header, hlen) == 0) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[AAD] EVP_EncryptUpdate error: %s\n", ERR_reason_error_string(ERR_get_error()));
		EVP_CIPHER_CTX_free(pl_ctx);
		return -1;
	}
	/* Encrypt the payload */
	if(EVP_EncryptUpdate(pl_ctx, to, &d_len, bytes, blen) == 0) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "EVP_EncryptUpdate error: %s\n", ERR_reason_error_string(ERR_get_error()));
		EVP_CIPHER_CTX_free(pl_ctx);
		return -1;
	}
	/* Now let's authenticate with a tag */
	int t_len = 0;
	int ret = EVP_EncryptFinal_ex(pl_ctx, to + d_len, &t_len);
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- Tag set return value: %d\n", ret);
	if(ret == 0) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "EVP_EncryptFinal_ex error: %s\n", ERR_reason_error_string(ERR_get_error()));
		EVP_CIPHER_CTX_free(pl_ctx);
		return -1;
	}
	uint8_t tag[16];
	if(EVP_CIPHER_CTX_ctrl(pl_ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) == 0) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "EVP_CIPHER_CTX_ctrl error: %s\n", ERR_reason_error_string(ERR_get_error()));
		EVP_CIPHER_CTX_free(pl_ctx);
		return -1;
	}
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- -- Tag (%d)\n", t_len);
	imquic_print_hex(IMQUIC_LOG_HUGE, tag, sizeof(tag));
	memcpy(to + d_len, tag, sizeof(tag));
	/* Done */
	EVP_CIPHER_CTX_free(pl_ctx);
	return d_len + 16;
}

int imquic_verify_retry(uint8_t *bytes, size_t blen, uint8_t *dcid, size_t dcid_len) {
	if(bytes == NULL || blen < 16 || dcid == NULL || dcid_len > 20)
		return -1;
	/* Obtain the Retry Pseudo-Packet */
	size_t rpp_len = 0;
	uint8_t rpp[1500];
	rpp[0] = dcid_len;
	rpp_len++;
	if(dcid_len > 0) {
		memcpy(&rpp[rpp_len], dcid, dcid_len);
		rpp_len += dcid_len;
	}
	memcpy(&rpp[rpp_len], bytes, blen-16);
	rpp_len += (blen-16);
	/* Encrypt the payload using the client key and nonce (iv) */
	EVP_CIPHER_CTX *pl_ctx = EVP_CIPHER_CTX_new();
	if(EVP_EncryptInit_ex(pl_ctx, EVP_aes_128_gcm(), NULL, imquicv1_retry_key, imquicv1_retry_nonce) == 0) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "EVP_EncryptInit_ex error: %s\n", ERR_reason_error_string(ERR_get_error()));
		EVP_CIPHER_CTX_free(pl_ctx);
		return -1;
	}
	/* We pass the pseudo packet as AAD for the authentication */
	int d_len = 0;
	if(EVP_EncryptUpdate(pl_ctx, NULL, &d_len, rpp, rpp_len) == 0) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[AAD] EVP_EncryptUpdate error: %s\n", ERR_reason_error_string(ERR_get_error()));
		EVP_CIPHER_CTX_free(pl_ctx);
		return -1;
	}
	/* Now let's authenticate with a tag */
	int t_len = 0;
	int ret = EVP_EncryptFinal_ex(pl_ctx, &rpp[rpp_len], &t_len);
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- Tag set return value: %d\n", ret);
	if(ret == 0) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "EVP_EncryptFinal_ex error: %s\n", ERR_reason_error_string(ERR_get_error()));
		EVP_CIPHER_CTX_free(pl_ctx);
		return -1;
	}
	uint8_t tag[16];
	if(EVP_CIPHER_CTX_ctrl(pl_ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) == 0) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "EVP_CIPHER_CTX_ctrl error: %s\n", ERR_reason_error_string(ERR_get_error()));
		EVP_CIPHER_CTX_free(pl_ctx);
		return -1;
	}
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- -- Tag (%d)\n", t_len);
	imquic_print_hex(IMQUIC_LOG_HUGE, tag, sizeof(tag));
	EVP_CIPHER_CTX_free(pl_ctx);
	/* Check if the tag is the same */
	uint8_t *o_tag = bytes + blen - 16;
	int i = 0;
	for(i=0; i<16; i++) {
		if(tag[i] != o_tag[i]) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "Failed to verify Retry integrity tag\n");
			return -1;
		}
	}
	/* Done */
	return 0;
}

/* BoringSSL QUIC callbacks */
static int imquic_tls_set_read_secret(SSL *ssl, enum ssl_encryption_level_t level,
		const SSL_CIPHER *cipher, const uint8_t *read_secret, size_t secret_len) {
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "[imquic_tls_set_read_secret] %s (%s, %zu)\n",
		imquic_encryption_level_str(level), SSL_CIPHER_get_name(cipher), secret_len);
	imquic_print_hex(IMQUIC_LOG_HUGE, (uint8_t *)read_secret, secret_len);
	/* Set the read (remote) secret, and expand it */
	imquic_connection *conn = SSL_get_app_data(ssl);
	conn->keys[level].remote.md = SSL_CIPHER_get_handshake_digest(cipher);
	memcpy(conn->keys[level].remote.secret, read_secret, secret_len);
	conn->keys[level].remote.secret_len = secret_len;
	conn->keys[level].remote.key_len = (secret_len == 48 ? 32 : 16);	/* FIXME */
	conn->keys[level].remote.iv_len = 12;
	conn->keys[level].remote.hp_len = (secret_len == 48 ? 32 : 16);	/* FIXME */
	imquic_expand_secret((conn->is_server ? "Client" : "Server"), &conn->keys[level].remote, TRUE, 0);
#ifdef HAVE_QLOG
	if(conn->qlog != NULL && conn->qlog->quic) {
		/* TODO The key phase should be the full thing, not the bit */
		imquic_qlog_key_updated(conn->qlog, imquic_encryption_key_type_str(level, !conn->is_server),
			conn->keys[level].remote.key[0], conn->keys[level].remote.key_len, 0);
	}
#endif
	return 1;
}
static int imquic_tls_set_write_secret(SSL *ssl, enum ssl_encryption_level_t level,
		const SSL_CIPHER *cipher, const uint8_t *write_secret, size_t secret_len) {
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "[imquic_tls_set_write_secret] %s (%s, %zu)\n",
		imquic_encryption_level_str(level), SSL_CIPHER_get_name(cipher), secret_len);
	imquic_print_hex(IMQUIC_LOG_HUGE, (uint8_t *)write_secret, secret_len);
	/* Set the write (local) secret, and expand it */
	imquic_connection *conn = SSL_get_app_data(ssl);
	conn->keys[level].local.md = SSL_CIPHER_get_handshake_digest(cipher);
	memcpy(conn->keys[level].local.secret, write_secret, secret_len);
	conn->keys[level].local.secret_len = secret_len;
	conn->keys[level].local.key_len = (secret_len == 48 ? 32 : 16);	/* FIXME */
	conn->keys[level].local.iv_len = 12;
	conn->keys[level].local.hp_len = (secret_len == 48 ? 32 : 16);	/* FIXME */
	imquic_expand_secret((conn->is_server ? "Server" : "Client"), &conn->keys[level].local, TRUE, 0);
#ifdef HAVE_QLOG
	if(conn->qlog != NULL && conn->qlog->quic) {
		/* TODO The key phase should be the full thing, not the bit */
		imquic_qlog_key_updated(conn->qlog, imquic_encryption_key_type_str(level, conn->is_server),
			conn->keys[level].local.key[0], conn->keys[level].local.key_len, 0);
	}
#endif
	return 1;
}
#ifndef IMQUIC_BORINGSSL
static int imquic_tls_set_encryption_secrets(SSL *ssl, enum ssl_encryption_level_t level,
		const uint8_t *read_secret, const uint8_t *write_secret, size_t secret_len) {
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "[imquic_tls_set_encryption_secrets] %s (%zu)\n",
		imquic_encryption_level_str(level), secret_len);
	const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);
	if(read_secret)
		imquic_tls_set_read_secret(ssl, level, cipher, read_secret, secret_len);
	if(write_secret)
		imquic_tls_set_write_secret(ssl, level, cipher, write_secret, secret_len);
	return 1;
}
#endif
static int imquic_tls_add_handshake_data(SSL *ssl, enum ssl_encryption_level_t level,
		const uint8_t *data, size_t len) {
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "[imquic_tls_add_handshake_data] %s (%zu)\n",
		imquic_encryption_level_str(level), len);

	/* Queue in the outgoing buffer: flush_flight will determine when we'll send this */
	imquic_connection *conn = SSL_get_app_data(ssl);
	if(level > conn->level)
		imquic_connection_change_level(conn, level);
	if(conn->crypto_out[level] == NULL)
		conn->crypto_out[level] = imquic_buffer_create(0);
	imquic_buffer_append(conn->crypto_out[level], (uint8_t *)data, len);
	conn->send_crypto = TRUE;
	/* Done */
	return 1;
}
static int imquic_tls_flush_flight(SSL *ssl) {
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "[imquic_tls_flush_flight]\n");
	imquic_connection *conn = SSL_get_app_data(ssl);
	conn->send_crypto = TRUE;
	return 1;
}
static int imquic_tls_send_alert(SSL *ssl, enum ssl_encryption_level_t level, uint8_t alert) {
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "[imquic_tls_send_alert] %s: %u (%s, %s)\n",
		imquic_encryption_level_str(level), alert,
		SSL_alert_type_string_long(alert), SSL_alert_desc_string_long(alert));
	/* FIXME Close connection with a failure */
	imquic_connection *conn = SSL_get_app_data(ssl);
	imquic_send_close_connection(conn, IMQUIC_INTERNAL_ERROR, IMQUIC_CRYPTO, SSL_alert_desc_string_long(alert));
	return 1;
}
