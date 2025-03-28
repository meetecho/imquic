/*! \file   http3.h
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright MIT License
 * \brief  HTTP/3 stack (WebTransport only) (headers)
 * \details Implementation of the required set of features need to
 * establish a WebTransport connection, when needed. It explicitly only
 * deals with WebTransport, meaning it will fail with anything else that
 * is not a \c CONNECT request.
 *
 * \ingroup Core
 */

#ifndef IMQUIC_HTTP3_H
#define IMQUIC_HTTP3_H

#include <glib.h>

#include "../imquic/imquic.h"
#include "qpack.h"
#include "buffer.h"
#include "stream.h"
#include "qlog.h"
#include "refcount.h"

/*! \brief HTTP/3 stream type */
typedef enum imquic_http3_stream_type {
	/*! \brief Control stream */
	IMQUIC_HTTP3_CONTROL_STREAM = 0x00,
	/*! \brief Push stream */
	IMQUIC_HTTP3_PUSH_STREAM = 0x01,
	/*! \brief QPACK encoder stream */
	IMQUIC_HTTP3_QPACK_ENCODER_STREAM = 0x02,
	/*! \brief QPACK decoder stream */
	IMQUIC_HTTP3_QPACK_DECODER_STREAM = 0x03
} imquic_http3_stream_type;
/*! \brief Helper function to serialize to string the name of a imquic_http3_stream_type value.
 * @param type The imquic_http3_stream_type value
 * @returns The type name as a string, if valid, or NULL otherwise */
const char *imquic_http3_stream_type_str(imquic_http3_stream_type type);

/*! \brief HTTP/3 frame type */
typedef enum imquic_http3_frame_type {
	/*! \brief DATA */
	IMQUIC_HTTP3_DATA = 0x00,
	/*! \brief HEADERS */
	IMQUIC_HTTP3_HEADERS = 0x01,
	/*! \brief CANCEL_PUSH */
	IMQUIC_HTTP3_CANCEL_PUSH = 0x03,
	/*! \brief SETTINGS */
	IMQUIC_HTTP3_SETTINGS = 0x04,
	/*! \brief PUSH_PROMISE */
	IMQUIC_HTTP3_PUSH_PROMISE = 0x05,
	/*! \brief GOAWAY */
	IMQUIC_HTTP3_GOAWAY = 0x07,
	/*! \brief MAX_PUSH_ID */
	IMQUIC_HTTP3_MAX_PUSH_ID = 0x0d,
	/*! \brief WebTransport unidirectional stream */
	IMQUIC_HTTP3_WEBTRANSPORT_UNI_STREAM = 0x54,
	/*! \brief WebTransport bidirectional stream */
	IMQUIC_HTTP3_WEBTRANSPORT_STREAM = 0x41
} imquic_http3_frame_type;
/*! \brief Helper function to serialize to string the name of a imquic_http3_frame_type value.
 * @param type The imquic_http3_frame_type value
 * @returns The type name as a string, if valid, or NULL otherwise */
const char *imquic_http3_frame_type_str(imquic_http3_frame_type type);

/*! \brief HTTP/3 SETTINGS type */
typedef enum imquic_http3_settings_type {
	/*! \brief QPACK_MAX_TABLE_CAPACITY */
	IMQUIC_HTTP3_SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0x01,
	/*! \brief MAX_FIELD_SECTION_SIZE */
	IMQUIC_HTTP3_SETTINGS_MAX_FIELD_SECTION_SIZE = 0x06,
	/*! \brief QPACK_BLOCKED_STREAMS */
	IMQUIC_HTTP3_SETTINGS_QPACK_BLOCKED_STREAMS = 0x07,
	/*! \brief ENABLE_CONNECT_PROTOCOL */
	IMQUIC_HTTP3_SETTINGS_ENABLE_CONNECT_PROTOCOL = 0x08,
	/*! \brief H3_DATAGRAM */
	IMQUIC_HTTP3_SETTINGS_H3_DATAGRAM = 0x33,
	/*! \brief ENABLE_WEBTRANSPORT */
	IMQUIC_HTTP3_SETTINGS_ENABLE_WEBTRANSPORT = 0x2b603742,		/* FIXME Deprecated? */
	/*! \brief WEBTRANSPORT_MAX_SESSIONS */
	IMQUIC_HTTP3_SETTINGS_WEBTRANSPORT_MAX_SESSIONS = 0xc671706a,
} imquic_http3_settings_type;
/*! \brief Helper function to serialize to string the name of a imquic_http3_settings_type value.
 * @param type The imquic_http3_settings_type value
 * @returns The type name as a string, if valid, or NULL otherwise */
const char *imquic_http3_settings_type_str(imquic_http3_settings_type type);

/*! \brief HTTP/3 error codes */
typedef enum imquic_http3_error_code {
	/*! \brief DATAGRAM_ERROR */
	IMQUIC_HTTP3_H3_DATAGRAM_ERROR = 0x33,
	/*! \brief NO_ERROR */
	IMQUIC_HTTP3_H3_NO_ERROR = 0x0100,
	/*! \brief GENERAL_PROTOCOL_ERROR */
	IMQUIC_HTTP3_H3_GENERAL_PROTOCOL_ERROR = 0x0101,
	/*! \brief IMQUIC_HTTP3_H3_INTERNAL_ERROR */
	IMQUIC_HTTP3_H3_INTERNAL_ERROR = 0x0102,
	/*! \brief H3_STREAM_CREATION_ERROR */
	IMQUIC_HTTP3_H3_STREAM_CREATION_ERROR = 0x0103,
	/*! \brief H3_CLOSED_CRITICAL_STREAM */
	IMQUIC_HTTP3_H3_CLOSED_CRITICAL_STREAM = 0x0104,
	/*! \brief H3_FRAME_UNEXPECTED */
	IMQUIC_HTTP3_H3_FRAME_UNEXPECTED = 0x0105,
	/*! \brief H3_FRAME_ERROR */
	IMQUIC_HTTP3_H3_FRAME_ERROR = 0x0106,
	/*! \brief H3_EXCESSIVE_LOAD */
	IMQUIC_HTTP3_H3_EXCESSIVE_LOAD = 0x0107,
	/*! \brief H3_ID_ERROR */
	IMQUIC_HTTP3_H3_ID_ERROR = 0x0108,
	/*! \brief H3_SETTINGS_ERROR */
	IMQUIC_HTTP3_H3_SETTINGS_ERROR = 0x0109,
	/*! \brief H3_MISSING_SETTINGS */
	IMQUIC_HTTP3_H3_MISSING_SETTINGS = 0x010a,
	/*! \brief H3_REQUEST_REJECTED */
	IMQUIC_HTTP3_H3_REQUEST_REJECTED = 0x010b,
	/*! \brief H3_REQUEST_CANCELLED */
	IMQUIC_HTTP3_H3_REQUEST_CANCELLED = 0x010c,
	/*! \brief H3_REQUEST_INCOMPLETE */
	IMQUIC_HTTP3_H3_REQUEST_INCOMPLETE = 0x010d,
	/*! \brief H3_MESSAGE_ERROR */
	IMQUIC_HTTP3_H3_MESSAGE_ERROR = 0x010e,
	/*! \brief H3_CONNECT_ERROR */
	IMQUIC_HTTP3_H3_CONNECT_ERROR = 0x010f,
	/*! \brief H3_VERSION_FALLBACK */
	IMQUIC_HTTP3_H3_VERSION_FALLBACK = 0x0110,
	/*! \brief QPACK_DECOMPRESSION_FAILED */
	IMQUIC_HTTP3_QPACK_DECOMPRESSION_FAILED = 0x0200,
	/*! \brief QPACK_ENCODER_STREAM_ERROR */
	IMQUIC_HTTP3_QPACK_ENCODER_STREAM_ERROR = 0x0201,
	/*! \brief QPACK_DECODER_STREAM_ERROR */
	IMQUIC_HTTP3_QPACK_DECODER_STREAM_ERROR = 0x0202
} imquic_http3_error_code;
/*! \brief Helper function to serialize to string the name of a imquic_http3_error_code value.
 * @param type The imquic_http3_error_code value
 * @returns The type name as a string, if valid, or NULL otherwise */
const char *imquic_http3_error_code_str(imquic_http3_error_code type);

/*! \brief HTTP/3 connection abstraction */
typedef struct imquic_http3_connection {
	/*! \brief Associated QUIC core connection */
	imquic_connection *conn;
	/*! \brief Whether this is a server or a client */
	gboolean is_server;
	/*! \brief Current SETTINGS state */
	gboolean settings_sent, settings_received;
	/*! \brief Streams */
	uint64_t local_control_stream, remote_control_stream,
		local_qpack_encoder_stream, remote_qpack_encoder_stream,
		local_qpack_decoder_stream, remote_qpack_decoder_stream,
		request_stream;
	/*! \brief Whether the request stream has been set */
	gboolean request_stream_set;
	/*! \brief Whether there (already) are bidirectional streams in this connection */
	gboolean has_bidi_streams;
	/*! \brief QPACK context */
	imquic_qpack_context *qpack;
	/*! \brief Whether a WebTransport connection has been established */
	gboolean webtransport;
	/*! \brief Subprotocol to negotiate on WebTransport, if any (currently unused) */
	char *subprotocol;
	/*! \brief Buffers for incoming data, indexed by stream ID */
	GHashTable *buffers;
	/*! \brief Whether this instance has been destroyed (reference counting) */
	volatile gint destroyed;
	/*! \brief Reference counter */
	imquic_refcount ref;
} imquic_http3_connection;
/*! \brief Helper method to create a new HTTP/3 connection associated with a new QUIC core connection
 * @param conn The QUIC core connection to associate this HTTP/3 instance to
 * @param subprotocol The subprotocol to negotiate on WebTransport, if any (currently unused)
 * @returns A pointer to a new imquic_http3_connection instance, if successful, or NULL otherwise */
imquic_http3_connection *imquic_http3_connection_create(imquic_connection *conn, char *subprotocol);
/*! \brief Helper method to destroy an existing HTTP/3 connection associated with a QUIC core connection
 * @param h3c The imquic_http3_connection to destroy */
void imquic_http3_connection_destroy(imquic_http3_connection *h3c);

/*! \brief Callback invoked by the core when there's incoming \c STREAM data to process on an existing connection
 * @param conn The imquic_connection instance the data has been received on
 * @param stream The imquic_stream instance in the connection the data has been received on
 * @param chunk The imquic_buffer_chunk instance containing the new data
 * @param new_stream Whether this data opened a new stream  */
void imquic_http3_process_stream_data(imquic_connection *conn, imquic_stream *stream, imquic_buffer_chunk *chunk, gboolean new_stream);

/** @name Parsing HTTP/3 messages
 */
///@{
/*! brief Helper method to parse an incoming HTTP/3 request
 * @param h3c The imquic_http3_connection instance to parse the request for
 * @param stream The imquic_stream instance in the connection the data has been received on
 * @param bytes Data to process
 * @param blen Size of the data to process
 * @returns 0 in case of success, a negative integer otherwise */
int imquic_http3_parse_request(imquic_http3_connection *h3c, imquic_stream *stream, uint8_t *bytes, size_t blen);
/*! brief Helper method to parse a \c HEADERS frame in an HTTP/3 message
 * @param h3c The imquic_http3_connection instance to parse the \c HEADERS for
 * @param stream The imquic_stream instance in the connection the data has been received on
 * @param bytes Data to process
 * @param blen Size of the data to process
 * @returns The number of processed bytes, if successful, or 0 otherwise */
size_t imquic_http3_parse_request_headers(imquic_http3_connection *h3c, imquic_stream *stream, uint8_t *bytes, size_t blen);
/*! brief Helper method to parse a \c DATA frame in an HTTP/3 message
 * @param h3c The imquic_http3_connection instance to parse the \c DATA for
 * @param stream The imquic_stream instance in the connection the data has been received on
 * @param bytes Data to process
 * @param blen Size of the data to process
 * @returns The number of processed bytes, if successful, or 0 otherwise */
size_t imquic_http3_parse_request_data(imquic_http3_connection *h3c, imquic_stream *stream, uint8_t *bytes, size_t blen);
/*! brief Helper method to parse an incoming \c SETTINGS frame
 * @param h3c The imquic_http3_connection instance to parse the \c SETTINGS for
 * @param stream The imquic_stream instance in the connection the data has been received on
 * @param bytes Data to process
 * @param blen Size of the data to process
 * @returns 0 in case of success, a negative integer otherwise */
int imquic_http3_parse_settings(imquic_http3_connection *h3c, imquic_stream *stream, uint8_t *bytes, size_t blen);
///@}

/** @name Creating and sending HTTP/3 messages
 */
///@{
/*! \brief Helper to prepare a new HTTP/3 request
 * @param h3c The imquic_http3_connection instance to prepare the request for
 * @param es Buffer to use for the QPACK encoder stream, if needed
 * @param es_len Size of the encoder stream buffer
 * @param rs Buffer to use for the HTTP/3 request
 * @param rs_len Size of the request buffer
 * @returns 0 in case of success, a negative integer otherwise */
int imquic_http3_prepare_headers_request(imquic_http3_connection *h3c, uint8_t *es, size_t *es_len, uint8_t *rs, size_t *rs_len);
/*! \brief Helper to prepare a new HTTP/3 response
 * @param h3c The imquic_http3_connection instance to prepare the response for
 * @param es Buffer to use for the QPACK encoder stream, if needed
 * @param es_len Size of the encoder stream buffer
 * @param rs Buffer to use for the HTTP/3 request
 * @param rs_len Size of the request buffer
 * @returns 0 in case of success, a negative integer otherwise */
int imquic_http3_prepare_headers_response(imquic_http3_connection *h3c, uint8_t *es, size_t *es_len, uint8_t *rs, size_t *rs_len);
/*! \brief Helper to prepare a new \c SETTINGS frame
 * @param h3c The imquic_http3_connection instance to prepare the \c SETTINGS frame for
 * @returns 0 in case of success, a negative integer otherwise */
int imquic_http3_prepare_settings(imquic_http3_connection *h3c);
/*! \brief Helper to add a new \c SETTINGS property to a buffer
 * @param bytes Buffer to add the property to
 * @param blen Size of the buffer
 * @param type The imquic_http3_settings_type type to add to the frame
 * @param number The numeric value of the property to add
 * @returns 0 in case of success, a negative integer otherwise */
size_t imquic_http3_settings_add_int(uint8_t *bytes, size_t blen, imquic_http3_settings_type type, uint64_t number);
/*! \brief Helper to send a new HTTP/3 \c CONNECT request to establish a WebTransport session
 * @param h3c The imquic_http3_connection instance to send the \c CONNECT on */
void imquic_http3_check_send_connect(imquic_http3_connection *h3c);
///@}

#ifdef HAVE_QLOG
/** @name QLOG events tracing for HTTP/3
 */
///@{
/*! \brief Add a \c parameters_set event
 * @param qlog The imquic_qlog instance to add the event to
 * @param local Whether this is a local or remote parameters set
 * @param extended_connect Whether SETTINGS_ENABLE_CONNECT_PROTOCOL is set
 * @param h3_datagram Whether SETTINGS_H3_DATAGRAM is set */
void imquic_http3_qlog_parameters_set(imquic_qlog *qlog, gboolean local, gboolean extended_connect, gboolean h3_datagram);
/*! \brief Add a \c stream_type_set
 * @param qlog The imquic_qlog instance to add the event to
 * @param local Whether this is a local or remote stream
 * @param stream_id The Stream ID used for this message
 * @param type The stream type */
void imquic_http3_qlog_stream_type_set(imquic_qlog *qlog, gboolean local, uint64_t stream_id, const char *type);
/*! \brief Helper to prepare a frame or an object/array, and add it to a parent if it's specified
 * @note If no parent is specified, a \c frame_type property is set in the new object automatically;
 * if it is, the object/array will be empty and added to the parent with the provided name
 * @param parent The object/array to add the object to, if any
 * @param name The object/array name, or the \c frame_type property in the object
 * @param array Whether to create an array or an object (ignored if \c parent is NULL)
 * @returns A pointer to the new object, if successful, or NULL otherwise */
json_t *imquic_qlog_http3_prepare_content(json_t *parent, const char *name, gboolean array);
/*! \brief Helper to append a name/value object to an array
 * @param parent The array to append the new name/value obect to
 * @param name The object name
 * @param value The object value */
void imquic_qlog_http3_append_object(json_t *parent, const char *name, const char *value);
/*! \brief Add a \c frame_created
 * @param qlog The imquic_qlog instance to add the event to
 * @param stream_id The Stream ID used for this message
 * @param length The size of the frame
 * @param frame The frame that was created */
void imquic_http3_qlog_frame_created(imquic_qlog *qlog, uint64_t stream_id, uint64_t length, json_t *frame);
/*! \brief Add a \c frame_parsed
 * @param qlog The imquic_qlog instance to add the event to
 * @param stream_id The Stream ID used for this message
 * @param length The size of the frame
 * @param frame The frame that was parsed */
void imquic_http3_qlog_frame_parsed(imquic_qlog *qlog, uint64_t stream_id, uint64_t length, json_t *frame);
///@}
#endif

#endif
