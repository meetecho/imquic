/*! \file   crypto.h
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright MIT License
 * \brief  QUIC cryptographic utilities (headers)
 * \details Cryptographic utilities for QUIC. This is where contexts for
 * taking care of header protection and encryption at different levels
 * are provided, with helper functions exposed to the internal QUIC stack.
 *
 * \ingroup Core
 */

#ifndef IMQUIC_CRYPTO_H
#define IMQUIC_CRYPTO_H

#include <stdint.h>

#include <glib.h>

#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#ifdef IMQUIC_BORINGSSL
#include <openssl/hkdf.h>
#else
#include <openssl/kdf.h>
#endif
#include <openssl/err.h>

/*! \brief Helper function to serialize to string the name of an SSL encryption level.
 * @param level The SSL encryption level
 * @returns The encryption level name as a string, if valid, or NULL otherwise */
const char *imquic_encryption_level_str(enum ssl_encryption_level_t level);
/*! \brief Helper function to serialize to string the key type of an SSL encryption level.
 * @param level The SSL encryption level
 * @param server Server or client
 * @returns The key type as a string, if valid, or NULL otherwise */
const char *imquic_encryption_key_type_str(enum ssl_encryption_level_t level, gboolean server);

/*! \brief Initialize the TLS stack at startup
 * @param secrets_log File to use to store QUIC secret, e.g., for Wireshark debugging (see SSLKEYLOGFILE)
 * @returns 0 in case of success, a negative integer otherwise */
int imquic_tls_init(const char *secrets_log);
/*! \brief Uninitialize the TLS stack */
void imquic_tls_deinit(void);

/*! \brief TLS context */
typedef struct imquic_tls {
	/*! \brief Whether this is for a server or a client */
	gboolean is_server;
	/*! \brief TLS context */
	SSL_CTX *ssl_ctx;
	/*! \brief Certificate */
	X509 *ssl_cert;
	/*! \brief Key */
	EVP_PKEY *ssl_key;
	/*! \brief Whether early data should be supported */
	gboolean early_data;
	/*! \brief File to use for session tickets, when doing early data */
	char *ticket_file;
} imquic_tls;
/*! \brief Helper to create a new TLS context
 * @param is_server Whether this is for a server or a client
 * @param server_pem Path to the certificate file
 * @param server_key Path to the certificate key
 * @param password Certificate password, if any
 * @returns A pointer to a new imquic_tls instance, if successful, or NULL otherwise */
imquic_tls *imquic_tls_create(gboolean is_server, const char *server_pem, const char *server_key, const char *password);
/*! \brief Enable early data on an existing TLS context
 * @param tls The imquic_tls context to enable early data on
 * @param ticket_file The file to write/read the ticket to/from
 * @returns 0 in case of success, a negative integer otherwise */
int imquic_tls_enable_early_data(imquic_tls *tls, const char *ticket_file);
/*! \brief Get a new SSL instance from an existing TLS context
 * @param tls The imquic_tls context to create the new SSL instance from
 * @returns A pointer to a new SSL instance, if successful, or NULL otherwise */
SSL *imquic_tls_new_ssl(imquic_tls *tls);
/*! \brief Destroy an existing imquic_tls context
 * @param tls The imquic_tls context to destroy */
void imquic_tls_destroy(imquic_tls *tls);

/*! \brief Encryption context for a specific direction and encryption level in a QUIC connection */
typedef struct imquic_encryption {
	/*! \brief Hashing algorithm */
	const EVP_MD *md;
	/*! \brief Secret (key phased) */
	uint8_t secret[2][48];
	/*! \brief Length of the secret */
	size_t secret_len;
	/*! \brief Key (key phased) */
	uint8_t key[2][32];
	/*! \brief Length of the key */
	size_t key_len;
	/*! \brief IV (key phased) */
	uint8_t iv[2][12];
	/*! \brief Length of the IV */
	size_t iv_len;
	/*! \brief Header protection */
	uint8_t hp[32];
	/*! \brief Length of the header protection */
	size_t hp_len;
} imquic_encryption;
/*! \brief Protection context in both directions for a specific encryption level in a QUIC connection */
typedef struct imquic_protection {
	/*! \brief Local encryption context */
	imquic_encryption local;
	/*! \brief Remote encryption context */
	imquic_encryption remote;
} imquic_protection;

/** @name HKDF utilities
 */
///@{
/*! \brief Helper to build an HKDF label, to use with HKDF_expand
 * @note This automatically prefixes the provided label with "tls13 "
 * @param[in] label The label to build (without the "tls13 " prefix)
 * @param[out] hkdf_label The buffer where to store the HKDF label
 * @param buflen Size of the buffer where to store the HKDF label
 * @param outlen To how many bytes we want to expand
 * @returns the size of the label in case of success, a negative integer otherwise */
int imquic_build_hkdf_label(const char *label, uint8_t *hkdf_label, size_t buflen, size_t outlen);
/*! \brief Helper to perform an HKDF extract
 * @param[in] digest The digest to use for the extraction
 * @param[in] key The key to use for the extraction
 * @param[in] keylen Size of the key
 * @param[out] out The output buffer where to store the result of the operation
 * @param[out] outlen Size of the output buffer
 * @returns 0 in case of success, a negative integer otherwise */
int imquic_hkdf_extract(const EVP_MD *digest, uint8_t *key, size_t keylen, uint8_t *out, size_t *outlen);
/*! \brief Helper to expand an HKDF label
 * @param[in] digest The digest to use for the expansion
 * @param[in] key The key to use for the expansion
 * @param[in] keylen Size of the key
 * @param[in] label The label to use for the expansion (without the "tls13 " prefix)
 * @param[out] out The output buffer where to store the result of the operation
 * @param[out] outlen Size of the output buffer
 * @returns 0 in case of success, a negative integer otherwise */
int imquic_hkdf_expand_label(const EVP_MD *digest, uint8_t *key, size_t keylen, const char *label, uint8_t *out, size_t outlen);
/*! \brief Helper to derive the initial secrets from a known connection ID
 * @note Depending on whether we're calling this from a server or a remote endpoint,
 * we update the local and remote properties of imquic_protection accordingly.
 * @param p The imquic_protection instance to derive the initial secret for
 * @param dcid Buffer containing the connection ID to derive the initial secret from
 * @param dcid_len Size of the connection ID buffer
 * @param is_server Whether the endpoint is a server or a client
 * @returns 0 in case of success, a negative integer otherwise */
int imquic_derive_initial_secret(imquic_protection *p, uint8_t *dcid, size_t dcid_len, gboolean is_server);
/*! \brief Helper to expand a secret, taking into account the key phase
 * @param name Short string description of what we're updating
 * @param e The imquic_encryption we're updating
 * @param expand_hp Whether we should expand the header protection info as well
 * (will be FALSE when just updating keys because of the key phase)
 * @param phase The value of the key phase bit
 * @returns 0 in case of success, a negative integer otherwise */
int imquic_expand_secret(const char *name, imquic_encryption *e, gboolean expand_hp, gboolean phase);
///@}

/*! \brief Update the key phase for an existing context
 * @param p The imquic_protection instance to update
 * @param phase The new key phase bit value
 * @returns 0 in case of success, a negative integer otherwise */
int imquic_update_keys(imquic_protection *p, gboolean phase);

/** @name Header protection
 */
///@{
/*! \brief Unprotect a received QUIC message (and unobfuscate the header)
 * @note The buffer is updated inline
 * @param[in] bytes The buffer containing the protected message
 * @param[in] blen The size of the buffer containing the protected message
 * @param[in] pn_offset Offset in the buffer where the packet number can be found
 * @param[in] hp The remote header protection key
 * @param[in] hp_len Size of the remote header protection key
 * @returns 0 in case of success, a negative integer otherwise */
int imquic_unprotect_header(uint8_t *bytes, size_t blen, size_t pn_offset, uint8_t *hp, size_t hp_len);
/*! \brief Protect a QUIC message to send (and obfuscate the header)
 * @note The buffer is updated inline
 * @param[in] bytes The buffer containing the unprotected message
 * @param[in] blen The size of the buffer containing the unprotected message
 * @param[in] pn_offset Offset in the buffer where the packet number can be found
 * @param[in] hp The local header protection key
 * @param[in] hp_len Size of the local header protection key
 * @returns 0 in case of success, a negative integer otherwise */
int imquic_protect_header(uint8_t *bytes, size_t blen, size_t pn_offset, uint8_t *hp, size_t hp_len);
///@}

/** @name Payload encryption and decryption
 */
///@{
/*! \brief Decrypt a received QUIC payload
 * @param[in] bytes The buffer containing the encrypted payload
 * @param[in] blen The size of the buffer containing the encrypted payload
 * @param[out] to The buffer where to copy the decrypted payload
 * @param[in] tlen The size of the buffer for the decrypted payload
 * @param[in] header The buffer containing the QUIC message header (as AAD for authentication)
 * @param[in] hlen The size of the header
 * @param[in] pn The packet number (to use for the nonce)
 * @param[in] key The remote key
 * @param[in] key_len Size of the remote key
 * @param[in] iv The remote IV (to use for the nonce)
 * @param[in] iv_len Size of the remote IV
 * @returns The size of the decrypted payload, if successful, or a negative integer otherwise */
int imquic_decrypt_payload(uint8_t *bytes, size_t blen, uint8_t *to, size_t tlen, uint8_t *header, size_t hlen, uint64_t pn, uint8_t *key, size_t key_len, uint8_t *iv, size_t iv_len);
/*! \brief Encrypt a QUIC payload to send
 * @param[in] bytes The buffer containing the unencrypted payload
 * @param[in] blen The size of the buffer containing the unencrypted payload
 * @param[out] to The buffer where to copy the encrypted payload
 * @param[in] tlen The size of the buffer for the encrypted payload
 * @param[in] header The buffer containing the QUIC message header (as AAD for authentication)
 * @param[in] hlen The size of the header
 * @param[in] pn The packet number (to use for the nonce)
 * @param[in] key The local key
 * @param[in] key_len Size of the local key
 * @param[in] iv The local IV (to use for the nonce)
 * @param[in] iv_len Size of the local IV
 * @returns The size of the encrypted payload, if successful, or a negative integer otherwise */
int imquic_encrypt_payload(uint8_t *bytes, size_t blen, uint8_t *to, size_t tlen, uint8_t *header, size_t hlen, uint64_t pn, uint8_t *key, size_t key_len, uint8_t *iv, size_t iv_len);
///@}

/*! \brief Verify the integrity of a Retry packet
 * @param[in] bytes The buffer containing the payload of the Retry message
 * @param[in] blen The size of the buffer containing the payload
 * @param[in] dcid Original Destination Connection ID
 * @param[in] dcid_len The size of the original Destination Connection ID
 * @returns 0 if the packet is verified, or a negative integer otherwise */
int imquic_verify_retry(uint8_t *bytes, size_t blen, uint8_t *dcid, size_t dcid_len);

#endif
