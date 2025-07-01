/*! \file   imquic.h
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright MIT License
 * \brief  imquic public interface (headers)
 * \details Public interface to the imquic library. This is where public
 * functions are callbacks to interact with the library are defined.
 *
 * \ingroup API Core
 *
 * \page publicapi imquic public API
 *
 * The first thing you must do (and only once) to use the library is
 * initializing it, which you can do with a call to \ref imquic_init. A
 * successful initialization will return \c 0 , so a negative value being
 * return will indicate something went wrong and the library won't be
 * usable. The only argument it expects is an optional path to a file
 * to use for storing the exchanged crypto secret: this is only needed
 * in case you want to, e.g., use tools like Wireshark to debug the QUIC
 * message exchanges even when encrypted, pretty much as other applications
 * do when using the \c SSLKEYLOGFILE format. For instance, initializing
 * the stack like this:
 *
\verbatim
	if(imquic_init("/home/lminiero/mykeys.log") < 0) {
		// Oh no!
		exit(1);
	}
\endverbatim
 *
 * will store all crypto secrets for all QUIC sessions in the provided
 * file. Using that file in the "Master-Secret" section of the
 * "Protocols/TLS" section of Wireshark will allow you to see the QUIC
 * exchanges as unencrypted, for debugging purposes.
 *
 * When you're done with
 * the application, a call to \ref imquic_deinit will take care of the cleanup.
 *
 * You can configure the logging level of the library with a call to
 * \ref imquic_set_log_level. The logging level can be tweaked dynamically,
 * which means you can make that part configurable in your application,
 * if you so prefer. The library comes with a few macros to allow you
 * to log messages at different debugging levels: \c IMQUIC_PRINT will
 * always print the message, while \c IMQUIC_LOG will only show the message
 * if the log level associated to the message is lower or equal to the
 * configured log level. Check debug.h for details.
 *
 * Versioning information can be obtained with different methods:
 * \ref imquic_get_version returns a synthetic numeric version, that's
 * computed from major, minor and patch version, and ensures that any
 * bump results in a higher number; \ref imquic_get_version_major,
 * \ref imquic_get_version_minor and \ref imquic_get_version_patch,
 * instead, return the individual major, minor and patch version numbers.
 * The version is also available as a string in \ref imquic_get_version_string,
 * which serializes major, minor and patch numbers separating them with a dot
 * (e.g., <code>0.0.1</code>). A release type of the current version (e.g.,
 * "alpha", "dev" or "stable") is provided in \ref imquic_get_version_release.
 * A complete representation of the current version as a string, which serialized
 * version and release separated by a backslash, is instead available in
 * \ref imquic_get_version_string_full (e.g., <code>0.0.1/alpha</code>).
 * To conclude, the \ref imquic_get_build_time and \ref imquic_get_build_sha
 * functions provide info on the code itself, namely when this specific build
 * of the library was compiled, and which git hash it refers to (which
 * is useful when needing to figure out debugging information).
 *
 * As far as using the library is concerned, it usually involves going
 * through the following steps:
 *
 * -# creating a QUIC server or client;
 * -# configuring the callback functions for relevant events;
 * -# starting the endpoint (waiting for connections, or initiating one);
 * -# when a connection is available, add a reference the connection
 * object, and performing the application logic (e.g., exchanging messages);
 * -# programmatically send data, if needed, and/or reacting to incoming one;
 * -# when a connection is notified as being closed, remove the previously
 * obtained reference to the connection and, if needed, perform any
 * application level cleanup (taking into account that, for server endpoints,
 * more connections may arrive in the future).
 *
 * In a nutshell, this summarizes a typical usage of the library, and
 * specifically the one we've used in all of our demo examples. Of course,
 * multiple client and server can be created at the same time, each with
 * their own callback functions if required.
 *
 * Creating a new QUIC endpoint means either creating a new QUIC server,
 * or a new QUIC client. You can create a new QUIC server using
 * \ref imquic_create_server, while on the other end \ref imquic_create_client
 * will create a client endpoint instead. Both use a variable argument
 * approach to dictate what these endpoints should be like, specifically
 * using a sequence of \ref imquic_config key/value properties started with
 * a \c IMQUIC_CONFIG_INIT and ended by a \c IMQUIC_CONFIG_DONE .
 *
 * <div class="alert alert-warning">
 * <b>Note Well:</b> no matter what ALPN is negotiated, these functions
 * will create a generic QUIC endpoint, where the application level
 * protocol is entirely up to you and to the callbacks/methods that follow.
 * If you want imquic to handle a specific protocol natively for you, it
 * will need to be implemented within the library itself, with different
 * methods to create endpoints and custom callbacks tailored to the
 * functionality of the protocol itself. For an example, check the native
 * support imquic offers for RTP Over QUIC (RoQ) in the \ref roqapi
 * documentation, and Media Over QUIC (MoQ) in the \ref moqapi documentation.
 * </div>
 *
 * Whether you created a client or a server, you'll need to configure
 * some callbacks to receive events (e.g., connections coming and going,
 * or incoming data) before actually starting the endpoint with a call
 * to \ref imquic_start_endpoint.
 *
 * Once an endpoint is live, the configured callbacks will be triggered
 * on relevant events. A new client connecting to your server, or your
 * client connecting to the server, will trigger a call to the callback
 * function configured in \ref imquic_set_new_connection_cb, with a pointer
 * to the new \ref imquic_connection instance associated to that specific
 * connection. Further events associated to that connection will refer
 * to the same instance, and using that pointer in active calls will
 * allow you to interact with a connection (e.g., to send data, or close
 * a connection). Considering the potentially multithread nature of the
 * library and its use in your application, it's a good idea to increase
 * a reference to the connection with \ref imquic_connection_ref when you're
 * first notified about it.
 *
 * The \ref imquic_set_stream_incoming_cb and \ref imquic_set_datagram_incoming_cb
 * functions allow you to configure callback functions to be notified about
 * incoming data, on \c STREAM and \c DATAGRAM respectively. To send data,
 * you can use \ref imquic_send_on_stream and \ref imquic_send_on_datagram
 * instead. Notice that sending data on a \c STREAM will only possible if
 * the stack knows about it, which means that either it's a stream your
 * peer created, or one you created yourself with \ref imquic_new_stream_id.
 *
 * The \ref imquic_set_connection_gone_cb connection notifies you when a
 * connection failed or is not available anymore: this can happens when the
 * the server is unreachable, the peer closed it remotely, an error occurred
 * within the library (e.g., a protocol violation in the communication), or
 * you programmatically closed the connection with a call to
 * \ref imquic_close_connection. If you increased the reference to the
 * connection when first notified about it, you should decrease it when
 * you don't need it anymore, and the connection gone callback function is
 * a good place to do that, since the library won't notify you about that
 * connection anymore after that. Of course you must not remove the reference
 * if you didn't increase it in the first place, e.g., if the connection
 * was never established and so this callback was invoked to notify you
 * that the connection failed.
 */

#ifndef IMQUIC_IMQUIC_H
#define IMQUIC_IMQUIC_H

#include "debug.h"

/* Opaque structures */
typedef struct imquic_connection imquic_connection;
typedef struct imquic_network_endpoint imquic_server;
typedef struct imquic_network_endpoint imquic_client;
typedef struct imquic_network_endpoint imquic_endpoint;

/** @name Library initialization
 */
///@{
/*! \brief Initialize the imquic library
 * @note Must only be called once
 * @param secrets_log File to use to store QUIC secret, e.g., for Wireshark debugging (see SSLKEYLOGFILE)
 * @returns 0 in case of success, a negative integer otherwise */
int imquic_init(const char *secrets_log);
/*! \brief Check if the imquic library has already been initialized */
gboolean imquic_is_inited(void);
/*! \brief Uninitialize the imquic library */
void imquic_deinit(void);
///@}

/** @name Versioning
 */
///@{
/*! \brief Get the current version of the library as a number
 * @note This is computed by shifting major and minor version numbers
 * by 24 and 16 bits respectively, while the patch is left as is
 * @returns A numeric version of the library */
uint32_t imquic_get_version(void);
/*! \brief Get the current major version of the library as a number
 * @returns The major version number of the library */
int imquic_get_version_major(void);
/*! \brief Get the current minor version of the library as a number
 * @returns The minor version number of the library */
int imquic_get_version_minor(void);
/*! \brief Get the current patch version of the library as a number
 * @returns The patch version number of the library */
int imquic_get_version_patch(void);
/*! \brief Get the current release type of the library as a string
 * @note We use this to mark versions as, e.g., alpha, dev or stable
 * @returns A string release type of the library */
const char *imquic_get_version_release(void);
/*! \brief Get the current version of the library as a string
 * @returns A string version of the library */
const char *imquic_get_version_string(void);
/*! \brief Get the current version of the library, including release type, as a string
 * @returns A string full version of the library */
const char *imquic_get_version_string_full(void);
/*! \brief Get info on when this shared object was built
 * @returns A string description of the build time */
const char *imquic_get_build_time(void);
/*! \brief Get info on the git commit was compiled in this build
 * @returns A string description of the git commit */
const char *imquic_get_build_sha(void);
///@}

/** @name Logging
 */
///@{
/*! \brief Set the log level for the library
 * @note See debug.h for valid levels. The default is IMQUIC_LOG_VERB (5)
 * @param level Debugging level to use */
void imquic_set_log_level(int level);
///@}

/** @name QLOG
 */
///@{
/*! \brief Check if QLOG is supported at runtime
 * @returns TRUE if supported, FALSE otherwise */
gboolean imquic_is_qlog_supported(void);
///@}

/** @name Debugging
 */
///@{
/*! \brief Enable or disable lock/mutex debugging
 * @param enabled Whether debugging should now be enabled */
void imquic_set_lock_debugging(gboolean enabled);
/*! \brief Enable or disable debugging of reference counters
 * @param enabled Whether debugging should now be enabled */
void imquic_set_refcount_debugging(gboolean enabled);
///@}

/*! \brief Configuration properties when creating servers/clients */
typedef enum imquic_config {
	/*! \brief Must be the first property (no arguments) */
	IMQUIC_CONFIG_INIT = 0,
	/*! \brief Local IP address to bind to (default=all interfaces) */
	IMQUIC_CONFIG_LOCAL_BIND,
	/*! \brief Local port to bind to (0=random) */
	IMQUIC_CONFIG_LOCAL_PORT,
	/*! \brief Remote host to connect to (string, clients only) */
	IMQUIC_CONFIG_REMOTE_HOST,
	/*! \brief Remote host to connect to (clients only) */
	IMQUIC_CONFIG_REMOTE_PORT,
	/*! \brief TLS certificate to use, if any (file path) */
	IMQUIC_CONFIG_TLS_CERT,
	/*! \brief TLS certificate key to use, if any (file path) */
	IMQUIC_CONFIG_TLS_KEY,
	/*! \brief TLS certificate password to use, if any (string) */
	IMQUIC_CONFIG_TLS_PASSWORD,
	/*! \brief Whether early data should be supported (boolean) */
	IMQUIC_CONFIG_EARLY_DATA,
	/*! \brief If early data is supported, path to file to write/read the session ticket to/from (client only) */
	IMQUIC_CONFIG_TICKET_FILE,
	/*! \brief SNI to use, for clients (string) */
	IMQUIC_CONFIG_SNI,
	/*! \brief ALPN to negotiate (string, raw QUIC only) */
	IMQUIC_CONFIG_ALPN,
	/*! \brief Whether raw QUIC should be offered (boolean) */
	IMQUIC_CONFIG_RAW_QUIC,
	/*! \brief Whether WebTransport should be offered (boolean) */
	IMQUIC_CONFIG_WEBTRANSPORT,
	/*! \brief For WebTransport, path to respond to (defaults to "/") */
	IMQUIC_CONFIG_HTTP3_PATH,
	/*! \brief Subprotocol to negotiate on the main ALPN, if any (string) */
	IMQUIC_CONFIG_SUBPROTOCOL,
	/*! \brief Save a QLOG file to this path
	 * \note For servers, this will need to be a folder, and not a specific
	 * filename, as servers will handle multiple connections. This property
	 * is ignored (apart from a warning) if QLOG support was not compiled */
	IMQUIC_CONFIG_QLOG_PATH,
	/*! \brief Whether to save QUIC events to QLOG
	 * \note This property is ignored if QLOG support was not compiled */
	IMQUIC_CONFIG_QLOG_QUIC,
	/*! \brief Whether to save HTTP/3 events to QLOG (ignored if not offering WebTransport)
	 * \note This property is ignored if QLOG support was not compiled */
	IMQUIC_CONFIG_QLOG_HTTP3,
	/*! \brief Whether to save RoQ events to QLOG
	 * \note This property is ignored if QLOG support was not compiled */
	IMQUIC_CONFIG_QLOG_ROQ,
	/*! \brief Whether to save MoQ events to QLOG
	 * \note This property is ignored if QLOG support was not compiled */
	IMQUIC_CONFIG_QLOG_MOQ,
	/*! \brief Whether sequential JSON should be used, instead of regular JSON
	 * \note This property is ignored if QLOG support was not compiled */
	IMQUIC_CONFIG_QLOG_SEQUENTIAL,
	/*! \brief Generic user data, if any (void pointer) */
	IMQUIC_CONFIG_USER_DATA,
	/*! \brief Must be the last property, followed by NULL */
	IMQUIC_CONFIG_DONE,
} imquic_config;
/*! \brief Helper function to serialize to string the name of a imquic_config property.
 * @param type The imquic_config property
 * @returns The type name as a string, if valid, or NULL otherwise */
const char *imquic_config_str(imquic_config type);

/** @name QUIC endpoints management
 */
///@{
/*! \brief Method to create a new QUIC server, using variable arguments to dictate
 * what the server should do (e.g., port to bind to, ALPN, etc.). Variable
 * arguments are in the form of a sequence of name-value started with
 * a \c IMQUIC_CONFIG_INIT and ended by a \c IMQUIC_CONFIG_DONE , e.g.:
 \verbatim
	imquic_server *server = imquic_create_server("echo-server",
		IMQUIC_CONFIG_INIT,
		IMQUIC_CONFIG_TLS_CERT, cert_pem,
		IMQUIC_CONFIG_TLS_KEY, cert_key,
		IMQUIC_CONFIG_TLS_PASSWORD, cert_pwd,
		IMQUIC_CONFIG_LOCAL_PORT, 9000,
		IMQUIC_CONFIG_ALPN, "doq",
		IMQUIC_CONFIG_DONE, NULL);
 \endverbatim
 * to create a QUIC server advertising the "doq" (DNS Over QUIC) ALPN.
 * Notice that this will only create the resource, but not actually start
 * it: before doing that, you'll need to configure the callbacks for the
 * events you're interested in, and then use imquic_start_endpoint to
 * start the QUIC server (which will wait for incoming connections).
 * @note This creates just the QUIC (or WebTransport) stack, to negotiate
 * the provided ALPN, but all application details are up to you. If you
 * want imquic to handle a protocol natively for you, you'll need to use
 * a different creator, like imquic_create_moq_server for MoQ or
 * imquic_create_roq_server for RoQ.
 * @param[in] name The endpoint name (if NULL, a default value will be set)
 * @returns A pointer to a imquic_server object, if successful, NULL otherwise */
imquic_server *imquic_create_server(const char *name, ...);
/*! \brief Method to create a new QUIC client, using variable arguments to dictate
 * what the client should do (e.g., address to connect to, ALPN, etc.). Variable
 * arguments are in the form of a sequence of name-value started with
 * a \c IMQUIC_CONFIG_INIT and ended by a \c IMQUIC_CONFIG_DONE , e.g.:
 \verbatim
	imquic_client *client = imquic_create_client("echo-client",
		IMQUIC_CONFIG_INIT,
		IMQUIC_CONFIG_TLS_CERT, cert_pem,
		IMQUIC_CONFIG_TLS_KEY, cert_key,
		IMQUIC_CONFIG_TLS_PASSWORD, cert_pwd,
		IMQUIC_CONFIG_REMOTE_HOST, "127.0.0.1",
		IMQUIC_CONFIG_REMOTE_PORT, 9000,
		IMQUIC_CONFIG_ALPN, "doq",
		IMQUIC_CONFIG_DONE, NULL);
 \endverbatim
 * to create a QUIC client advertising the "doq" (DNS Over QUIC) ALPN.
 * Notice that this will only create the resource, but not actually start
 * it: before doing that, you'll need to configure the callbacks for the
 * events you're interested in, and then use imquic_start_endpoint to
 * start the QUIC client (which will attempt a connection).
 * @note This creates just the QUIC (or WebTransport) stack, to negotiate
 * the provided ALPN, but all application details are up to you. If you
 * want imquic to handle a protocol natively for you, you'll need to use
 * a different creator, like imquic_create_moq_server for MoQ or
 * imquic_create_roq_server for RoQ.
 * @param[in] name The endpoint name (if NULL, a default value will be set)
 * @returns A pointer to a imquic_server object, if successful, NULL otherwise */
imquic_client *imquic_create_client(const char *name, ...);

/*! \brief Helper function to get the endpoint name of a local client or server
 * @param endpoint The imquic_endpoint (imquic_server or imquic_client) to query
 * @returns The endpoint name, if successful, or NULL otherwise */
const char *imquic_get_endpoint_name(imquic_endpoint *endpoint);
/*! \brief Helper function to check whether a local endpoint is a server
 * @param endpoint The imquic_endpoint (imquic_server or imquic_client) to query
 * @returns TRUE if the endpoint is a server, or FALSE otherwise */
gboolean imquic_is_endpoint_server(imquic_endpoint *endpoint);
/*! \brief Helper function to get the ALPN a local client or server is configured to negotiate
 * @param endpoint The imquic_endpoint (imquic_server or imquic_client) to query
 * @returns The ALPN, if successful, or NULL otherwise */
const char *imquic_get_endpoint_alpn(imquic_endpoint *endpoint);
/*! \brief Helper function to get the WebTransport protocol a local client or server is configured to negotiate
 * @param endpoint The imquic_endpoint (imquic_server or imquic_client) to query
 * @returns The subprotocol, if successful, or NULL otherwise */
const char *imquic_get_endpoint_subprotocol(imquic_endpoint *endpoint);
/*! \brief Helper function to get the local port a client or server is bound to
 * @param endpoint The imquic_endpoint (imquic_server or imquic_client) to query
 * @returns The local port number */
uint16_t imquic_get_endpoint_port(imquic_endpoint *endpoint);

/*! \brief Start a QUIC stack previously created with imquic_create_server
 * or imquic_create_client. In case of a server, it will start listening
 * for incoming connections; in case of a client, it will attempt to
 * connect to the provided remote address.
 * @param endpoint The imquic_endpoint (imquic_server or imquic_client) to start */
void imquic_start_endpoint(imquic_endpoint *endpoint);
/*! \brief Shutdown a previously started QUIC endpoint (client or server)
 * In case of a server, it will terminate all client connections it's
 * handling, and stop accepting new ones; in case of a client, it will
 * terminate the active connection, if any.
 * @param endpoint The imquic_endpoint (imquic_server or imquic_client) to shutdown */
void imquic_shutdown_endpoint(imquic_endpoint *endpoint);

/*! \brief Configure the callback function to be notified about new connections
 * on the configured endpoint. For a server, it will be triggered any time
 * a client successfully connects to the server; for a client, it will
 * be triggered when the client successfully connects to the server.
 * @note This is a good place to obtain the first reference to a connection
 * @param endpoint The imquic_endpoint (imquic_server or imquic_client) to configure
 * @param new_connection Pointer to the function that will be invoked on the new connection */
void imquic_set_new_connection_cb(imquic_endpoint *endpoint,
	void (* new_connection)(imquic_connection *conn, void *user_data));
/*! \brief Configure the callback function to be notified about incoming STREAM
 * data on an existing connection handled by this endpoint.
 * @param endpoint The imquic_endpoint (imquic_server or imquic_client) to configure
 * @param stream_incoming Pointer to the function that will be invoked on the new STREAM data */
void imquic_set_stream_incoming_cb(imquic_endpoint *endpoint,
	void (* stream_incoming)(imquic_connection *conn, uint64_t stream_id,
		uint8_t *bytes, uint64_t offset, uint64_t length, gboolean complete));
/*! \brief Configure the callback function to be notified about incoming DATAGRAM
 * data on an existing connection handled by this endpoint.
 * @param endpoint The imquic_endpoint (imquic_server or imquic_client) to configure
 * @param datagram_incoming Pointer to the function that will be invoked on the new DATAGRAM data */
void imquic_set_datagram_incoming_cb(imquic_endpoint *endpoint,
	void (* datagram_incoming)(imquic_connection *conn, uint8_t *bytes, uint64_t length));
/*! \brief Configure the callback function to be notified when an existing connection
 * handled by this endpoint has been closed/shut down.
 * @note This is a good place to release the last reference to the connection
 * @param endpoint The imquic_endpoint (imquic_server or imquic_client) to configure
 * @param connection_gone Pointer to the function that will be invoked when a connection is gone */
void imquic_set_connection_gone_cb(imquic_endpoint *endpoint,
	void (* connection_gone)(imquic_connection *conn));
///@}

/** @name Interacting with connections
 */
///@{
/*! \brief Helper function to get the ALPN of a connection
 * @param conn The imquic_connection to query
 * @returns The ALPN, if successful, or NULL otherwise */
const char *imquic_get_connection_alpn(imquic_connection *conn);
/*! \brief Helper function to get the display name of a connection
 * @note The display name is the concatenation of the the endpoint name,
 * a slash character, and a monotonically increasing identifier.
 * @param conn The imquic_connection to query
 * @returns The display name, if successful, or NULL otherwise */
const char *imquic_get_connection_name(imquic_connection *conn);
/*! \brief Helper method to ask for the next usable locally originated stream ID on this connection
 * @param[in] conn The imquic_connection to query
 * @param[in] bidirectional Whether the new stream should be bidirectional
 * @param[out] stream_id Pointer where the new stream ID will be provided
 * @returns 0 if successful, a negative integer otherwise */
int imquic_new_stream_id(imquic_connection *conn, gboolean bidirectional, uint64_t *stream_id);
/*! \brief Helper method to send data on a QUIC STREAM
 * @note The stream ID must already be known by the stack, either because
 * created by the peer, or previously created via imquic_new_stream_id.
 * Notice that this method will queue the data for delivery, but not send
 * it right away. The event loop will take care of that internally.
 * @param[in] conn The imquic_connection to send data on
 * @param[in] stream_id The QUIC stream to use for sending data
 * @param[in] bytes Buffer containing the data to send
 * @param[in] offset Offset value to put in the outgoing STREAM fragment
 * @param[in] length Size of the buffer of data
 * @param[in] complete Whether this (offset+length) is the end of the STREAM data
 * @returns 0 if successful, a negative integer otherwise */
int imquic_send_on_stream(imquic_connection *conn, uint64_t stream_id,
	uint8_t *bytes, uint64_t offset, uint64_t length, gboolean complete);
/*! \brief Helper method to send data on a QUIC DATAGRAM
 * @note Datagrams support must have been negotiated on the connection.
 * Notice that this method will queue the data for delivery, but not send
 * it right away. The event loop will take care of that internally.
 * @param[in] conn The imquic_connection to send data on
 * @param[in] bytes Buffer containing the data to send
 * @param[in] length Size of the buffer of data
 * @returns 0 if successful, a negative integer otherwise */
int imquic_send_on_datagram(imquic_connection *conn, uint8_t *bytes, uint64_t length);
/*! \brief Helper method to close a QUIC connection
 * @note Closing a server connection will keep the server alive, without
 * impacting other connections to the same server and waiting for more
 * connections. Closing a client connection will make that client instance
 * unusable from that point forward.
 * @param[in] conn The imquic_connection to close
 * @param[in] error The application error code to send, if any
 * @param[in] reason A string description of why the connection was closed, if any */
void imquic_close_connection(imquic_connection *conn, uint64_t error, const char *reason);
///@}

/** @name Public imquic utilities
 */
///@{
/*! \brief Increase a reference to a imquic_connection instance
 * @note This should be used at least once, the first time the library
 * notifies you about a new connection, so that the library knows you'll
 * be managing it. Other references can be added/removed contextually.
 * @param conn The imquic_connection instance to increase a reference for */
void imquic_connection_ref(imquic_connection *conn);
/*! \brief Decrease a reference to a imquic_connection instance
 * @note As an application, you should decrease all references you previously
 * increased. The last reference should be decreased only when you know
 * you won't need the connection anymore (e.g., in the callback the library
 * invokes to notify you the connection is over).
 * @param conn The imquic_connection instance to decrease a reference for */
void imquic_connection_unref(imquic_connection *conn);

/*! \brief Parse a QUIC stream ID to its actual ID and its other properties
 * @param[in] stream_id The QUIC stream ID to parse
 * @param[out] id The actual client/server uni/bidirectional ID
 * @param[out] client_initiated Whether this stream is client initiated
 * @param[out] bidirectional Whether this stream is bidirectional */
void imquic_stream_id_parse(uint64_t stream_id, uint64_t *id, gboolean *client_initiated, gboolean *bidirectional);
/*! \brief Build a QUIC stream ID out of its actual ID and its other properties
 * @param[in] id The actual client/server uni/bidirectional ID
 * @param[in] client_initiated Whether this stream is client initiated
 * @param[in] bidirectional Whether this stream is bidirectional
 * @returns The QUIC stream ID */
uint64_t imquic_stream_id_build(uint64_t id, gboolean client_initiated, gboolean bidirectional);

/*! \brief Read a variable size integer from a buffer
 * @note You can use the return value to know how many bytes to skip in
 * the buffer to read the next value. In case of issues in the parsing,
 * length will have value 0.
 * @param[in] bytes The buffer to read
 * @param[in] blen The size of the buffer
 * @param[out] length How many bytes the variable size integer used
 * @returns The variable size integer, if length is higher than 0 */
uint64_t imquic_varint_read(uint8_t *bytes, size_t blen, uint8_t *length);
/*! \brief Write a variable size integer to a buffer
 * @note You can use the return value to know how many bytes to skip in
 * the buffer to write the next value. In case of issues in the writing,
 * length will have value 0.
 * @param[in] number The number to write as a variable size integer
 * @param[in] bytes The buffer to write to
 * @param[in] blen The size of the buffer
 * @returns How many bytes the variable size integer used, if successful, 0 otherwise */
uint8_t imquic_varint_write(uint64_t number, uint8_t *bytes, size_t blen);

/*! \brief Helper to generate random 64 bit unsigned integers
 * @note This will fall back to a non-cryptographically safe PRNG in case
 * the crypto library RAND_bytes() call fails.
 * @returns A (mostly crypto-safe) random 64-bit unsigned integer */
uint64_t imquic_uint64_random(void);
/*! \brief Helper to generate an allocated copy of a uint64_t number
 * @note While apparently silly, this is needed in order to make sure uint64_t values
 * used as keys in GHashTable operations are not lost: using temporary uint64_t numbers
 * in a g_hash_table_insert, for instance, will cause the key to contain garbage as
 * soon as the temporary variable is lost, and all opererations on the key to fail
 * @param num The uint64_t number to duplicate
 * @returns A pointer to a uint64_t number, if successful, NULL otherwise */
uint64_t *imquic_uint64_dup(uint64_t num);
///@}
#endif
