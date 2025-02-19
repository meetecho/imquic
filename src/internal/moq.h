/*! \file   moq.h
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright MIT License
 * \brief  Media Over QUIC (MoQ) stack (headers)
 * \details Implementation of the Media Over QUIC (MoQ) stack as part
 * of the library itself. At the time of writing, this implements (most
 * of) versions -03 and -04 of the protocol.
 *
 * \note This is the internal implementation of MoQ in the library. You're
 * still free to only use imquic as the underlying QUIC/WebTransport library,
 * and take care of the MoQ implementation on your own instead: in order
 * to do that, use the generic imquic client/server creation utilities,
 * rather than the MoQ specific ones.
 *
 * \ingroup MoQ Core
 */

#ifndef IMQUIC_MOQ_INTERNAL_H
#define IMQUIC_MOQ_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#include <glib.h>

#include "../imquic/imquic.h"
#include "../imquic/moq.h"
#include "utils.h"
#include "refcount.h"

#define IMQUIC_MOQ		7171953

/*! \brief Initialize the native MoQ stack at startup */
void imquic_moq_init(void);
/*! \brief Uninitialize the native MoQ stack */
void imquic_moq_deinit(void);

/*! \brief Generic error codes */
typedef enum imquic_moq_error_code {
	IMQUIC_MOQ_NO_ERROR = 0x0,
	IMQUIC_MOQ_INTERNAL_ERROR = 0x1,
	IMQUIC_MOQ_UNAUTHORIZED = 0x2,
	IMQUIC_MOQ_PROTOCOL_VIOLATION = 0x3,
	IMQUIC_MOQ_DUPLICATE_TRACK_ALIAS = 0x4,
	IMQUIC_MOQ_PARAMETER_LENGTH_MISMATCH = 0x5,
	IMQUIC_MOQ_TOO_MANY_SUBSCRIBES = 0x6,
	IMQUIC_MOQ_GOAWAY_TIMEOUT = 0x10,
	IMQUIC_MOQ_CONTROL_MESSAGE_TIMEOUT = 0x11,
	IMQUIC_MOQ_DATA_STREAM_TIMEOUT = 0x12
} imquic_moq_error_code;
/*! \brief Helper function to serialize to string the name of a imquic_moq_error_code value.
 * @param code The imquic_moq_error_code value
 * @returns The type name as a string, if valid, or NULL otherwise */
const char *imquic_moq_error_code_str(imquic_moq_error_code code);

/*! \brief Announce error codes */
typedef enum imquic_moq_announce_error_code {
	IMQUIC_MOQ_ANNCERR_INTERNAL_ERROR = 0x0,
	IMQUIC_MOQ_ANNCERR_UNAUTHORIZED = 0x1,
	IMQUIC_MOQ_ANNCERR_TIMEOUT = 0x2,
	IMQUIC_MOQ_ANNCERR_NOT_SUPPORTED = 0x3,
	IMQUIC_MOQ_ANNCERR_UNINTERESTED = 0x4
} imquic_moq_announce_error_code;
/*! \brief Helper function to serialize to string the name of a imquic_moq_announce_error_code value.
 * @param code The imquic_moq_announce_error_code value
 * @returns The type name as a string, if valid, or NULL otherwise */
const char *imquic_moq_announce_error_code_str(imquic_moq_announce_error_code code);

/*! \brief Subscribe error codes */
typedef enum imquic_moq_sub_error_code {
	IMQUIC_MOQ_SUBERR_INTERNAL_ERROR = 0x0,
	IMQUIC_MOQ_SUBERR_UNAUTHORIZED = 0x1,
	IMQUIC_MOQ_SUBERR_TIMEOUT = 0x2,
	IMQUIC_MOQ_SUBERR_NOT_SUPPORTED = 0x3,
	IMQUIC_MOQ_SUBERR_TRACK_DOES_NOT_EXIST = 0x4,
	IMQUIC_MOQ_SUBERR_INVALID_RANGE = 0x5,
	IMQUIC_MOQ_SUBERR_RETRY_TRACK_ALIAS = 0x6
} imquic_moq_sub_error_code;
/*! \brief Helper function to serialize to string the name of a imquic_moq_sub_error_code value.
 * @param code The imquic_moq_sub_error_code value
 * @returns The type name as a string, if valid, or NULL otherwise */
const char *imquic_moq_sub_error_code_str(imquic_moq_sub_error_code code);

/*! \brief Subscribe announces error codes */
typedef enum imquic_moq_subannc_error_code {
	IMQUIC_MOQ_SUBANNCERR_INTERNAL_ERROR = 0x0,
	IMQUIC_MOQ_SUBANNCERR_UNAUTHORIZED = 0x1,
	IMQUIC_MOQ_SUBANNCERR_TIMEOUT = 0x2,
	IMQUIC_MOQ_SUBANNCERR_NOT_SUPPORTED = 0x3,
	IMQUIC_MOQ_SUBANNCERR_NAMESPACE_PREFIX_UNKNOWN = 0x4
} imquic_moq_subannc_error_code;
/*! \brief Helper function to serialize to string the name of a imquic_moq_subannc_error_code value.
 * @param code The imquic_moq_subannc_error_code value
 * @returns The type name as a string, if valid, or NULL otherwise */
const char *imquic_moq_subannc_error_code_str(imquic_moq_subannc_error_code code);

/*! \brief Fetch error codes */
typedef enum imquic_moq_fetch_error_code {
	IMQUIC_MOQ_FETCHERR_INTERNAL_ERROR = 0x0,
	IMQUIC_MOQ_FETCHERR_UNAUTHORIZED = 0x1,
	IMQUIC_MOQ_FETCHERR_TIMEOUT = 0x2,
	IMQUIC_MOQ_FETCHERR_NOT_SUPPORTED = 0x3,
	IMQUIC_MOQ_FETCHERR_TRACK_DOES_NOT_EXIST = 0x4,
	IMQUIC_MOQ_FETCHERR_INVALID_RANGE = 0x5
} imquic_moq_fetch_error_code;
/*! \brief Helper function to serialize to string the name of a imquic_moq_fetch_error_code value.
 * @param code The imquic_moq_fetch_error_code value
 * @returns The type name as a string, if valid, or NULL otherwise */
const char *imquic_moq_fetch_error_code_str(imquic_moq_fetch_error_code code);

/*! \brief Subscribe done codes */
typedef enum imquic_moq_sub_done_code {
	IMQUIC_MOQ_SUBDONE_INTERNAL_ERROR = 0x0,
	IMQUIC_MOQ_SUBDONE_UNAUTHORIZED = 0x1,
	IMQUIC_MOQ_SUBDONE_TRACK_ENDED = 0x2,
	IMQUIC_MOQ_SUBDONE_SUBSCRIPTION_ENDED = 0x3,
	IMQUIC_MOQ_SUBDONE_GOING_AWAY = 0x4,
	IMQUIC_MOQ_SUBDONE_EXPIRED = 0x5,
	IMQUIC_MOQ_SUBDONE_TOO_FAR_BEHIND = 0x6
} imquic_moq_sub_done_code;
/*! \brief Helper function to serialize to string the name of a imquic_moq_sub_done_code value.
 * @param code The imquic_moq_sub_done_code value
 * @returns The type name as a string, if valid, or NULL otherwise */
const char *imquic_moq_sub_done_code_str(imquic_moq_sub_done_code code);

/*! \brief MoQ messages */
typedef enum imquic_moq_message_type {
	IMQUIC_MOQ_SUBSCRIBE_UPDATE = 0x2,
	IMQUIC_MOQ_SUBSCRIBE = 0x3,
	IMQUIC_MOQ_SUBSCRIBE_OK = 0x4,
	IMQUIC_MOQ_SUBSCRIBE_ERROR = 0x5,
	IMQUIC_MOQ_ANNOUNCE = 0x6,
	IMQUIC_MOQ_ANNOUNCE_OK = 0x7,
	IMQUIC_MOQ_ANNOUNCE_ERROR = 0x8,
	IMQUIC_MOQ_UNANNOUNCE = 0x9,
	IMQUIC_MOQ_UNSUBSCRIBE = 0xa,
	IMQUIC_MOQ_SUBSCRIBE_DONE = 0xb,
	IMQUIC_MOQ_ANNOUNCE_CANCEL = 0xc,
	IMQUIC_MOQ_TRACK_STATUS_REQUEST = 0xd,
	IMQUIC_MOQ_TRACK_STATUS = 0xe,
	IMQUIC_MOQ_GOAWAY = 0x10,
	IMQUIC_MOQ_SUBSCRIBE_ANNOUNCES = 0x11,
	IMQUIC_MOQ_SUBSCRIBE_ANNOUNCES_OK = 0x12,
	IMQUIC_MOQ_SUBSCRIBE_ANNOUNCES_ERROR = 0x13,
	IMQUIC_MOQ_UNSUBSCRIBE_ANNOUNCES = 0x14,
	IMQUIC_MOQ_MAX_SUBSCRIBE_ID = 0x15,
	IMQUIC_MOQ_SUBSCRIBES_BLOCKED = 0x1A,
	IMQUIC_MOQ_FETCH = 0x16,
	IMQUIC_MOQ_FETCH_CANCEL = 0x17,
	IMQUIC_MOQ_FETCH_OK = 0x18,
	IMQUIC_MOQ_FETCH_ERROR = 0x19,
	IMQUIC_MOQ_CLIENT_SETUP = 0x40,
	IMQUIC_MOQ_SERVER_SETUP = 0x41,
} imquic_moq_message_type;
/*! \brief Helper function to serialize to string the name of a imquic_moq_message_type value.
 * @param type The imquic_moq_message_type value
 * @returns The type name as a string, if valid, or NULL otherwise */
const char *imquic_moq_message_type_str(imquic_moq_message_type type);

/*! \brief MoQ data messages */
typedef enum imquic_moq_data_message_type {
	IMQUIC_MOQ_OBJECT_STREAM = 0x0,
	IMQUIC_MOQ_OBJECT_DATAGRAM = 0x1,
	IMQUIC_MOQ_OBJECT_DATAGRAM_STATUS = 0x2,
	IMQUIC_MOQ_STREAM_HEADER_TRACK = 0x50,
		IMQUIC_MOQ_STREAM_HEADER_TRACK_V06 = 0x2,
	IMQUIC_MOQ_STREAM_HEADER_GROUP = 0x51,
	IMQUIC_MOQ_SUBGROUP_HEADER = 0x4,
	IMQUIC_MOQ_FETCH_HEADER = 0x5,
} imquic_moq_data_message_type;
/*! \brief Helper function to serialize to string the name of a imquic_moq_data_message_type value.
 * @param type The imquic_data_moq_message_type value
 * @param version The version of the connection
 * @returns The type name as a string, if valid, or NULL otherwise */
const char *imquic_moq_data_message_type_str(imquic_moq_data_message_type type, imquic_moq_version version);
/*! \brief Helper function to return the imquic_moq_delivery mode associated
 * to a imquic_moq_data_message_type type
 * @param type The imquic_data_moq_message_type value
 * @param version The version of the connection
 * @returns The associated imquic_moq_delivery mode, if successful, or -1 otherwise */
imquic_moq_delivery imquic_moq_data_message_type_to_delivery(imquic_moq_data_message_type type, imquic_moq_version version);

/*! \brief MoQ setup parameters */
typedef enum imquic_moq_setup_parameter_type {
	IMQUIC_MOQ_PARAM_ROLE = 0x00,	/* Deprecated since v08 */
	IMQUIC_MOQ_PARAM_PATH = 0x01,
	IMQUIC_MOQ_PARAM_MAX_SUBSCRIBE_ID = 0x02,
} imquic_moq_setup_parameter_type;
/*! \brief Helper function to serialize to string the name of a imquic_moq_setup_parameter_type value.
 * @param type The imquic_moq_setup_parameter_type value
 * @returns The type name as a string, if valid, or NULL otherwise */
const char *imquic_moq_setup_parameter_type_str(imquic_moq_setup_parameter_type type);

/*! \brief MoQ subscribe parameters */
typedef enum imquic_moq_subscribe_parameter_type {
	IMQUIC_MOQ_PARAM_AUTHORIZATION_INFO = 0x02,
	IMQUIC_MOQ_PARAM_DELIVERY_TIMEOUT = 0x03,
	IMQUIC_MOQ_PARAM_MAX_CACHE_DURATION = 0x04,
} imquic_moq_subscribe_parameter_type;
/*! \brief Helper function to serialize to string the name of a imquic_moq_subscribe_parameter_type value.
 * @param type The imquic_moq_subscribe_parameter_type value
 * @returns The type name as a string, if valid, or NULL otherwise */
const char *imquic_moq_subscribe_parameter_type_str(imquic_moq_subscribe_parameter_type type);

/*! \brief MoQ roles */
typedef enum imquic_moq_role_type {
	IMQUIC_MOQ_ROLE_ENDPOINT = 0x00,	/* Not a real role: since -08, there are no more roles */
	IMQUIC_MOQ_ROLE_PUBLISHER = 0x01,
	IMQUIC_MOQ_ROLE_SUBSCRIBER = 0x02,
	IMQUIC_MOQ_ROLE_PUBSUB = 0x03
} imquic_moq_role_type;
/*! \brief Helper function to serialize to string the name of a imquic_moq_role_type value.
 * @param type The imquic_moq_role_type value
 * @returns The type name as a string, if valid, or NULL otherwise */
const char *imquic_moq_role_type_str(imquic_moq_role_type type);

/*! \brief Parsed MoQ setup parameter */
typedef struct imquic_moq_parsed_setup_parameter {
	/*! \brief The setup parameter ID */
	imquic_moq_setup_parameter_type type;
	union {
		/*! \brief ROLE */
		imquic_moq_role_type role;
		/*! \brief PATH */
		char *path;
		/*! \brief MAX_SUBSCRIBE_ID */
		uint64_t max_subscribe_id;
	} value;
} imquic_moq_parsed_setup_parameter;

/*! \brief Parsed MoQ subscribe parameter */
typedef struct imquic_moq_parsed_subscribe_parameter {
	/*! \brief The subscribe parameter ID */
	imquic_moq_subscribe_parameter_type type;
	union {
		/*! \brief AUTHORIZATION_INFO */
		imquic_moq_auth_info auth_info;
		/*! \brief DELIVERY_TIMEOUT */
		uint64_t delivery_timeout;
		/*! \brief MAX_CACHE_DURATION */
		uint64_t max_cache_duration;
	} value;
} imquic_moq_parsed_subscribe_parameter;


/*! \brief MoQ location modes */
typedef enum imquic_moq_location_mode {
	IMQUIC_MOQ_LOCATION_NONE = 0x0,
	IMQUIC_MOQ_LOCATION_ABSOLUTE = 0x1,
	IMQUIC_MOQ_LOCATION_RELATIVEPREVIOUS = 0x2,
	IMQUIC_MOQ_LOCATION_RELATIVENEXT = 0x3
} imquic_moq_location_mode;
/*! \brief Helper function to serialize to string the name of a imquic_moq_location_mode value.
 * @param mode The imquic_moq_location_mode value
 * @returns The type name as a string, if valid, or NULL otherwise */
const char *imquic_moq_location_mode_str(imquic_moq_location_mode mode);

/*! \brief MoQ location */
typedef struct imquic_moq_location {
	/*! \brief Location mode */
	imquic_moq_location_mode mode;
	/*! \brief Value */
	uint64_t value;
} imquic_moq_location;

/*! \brief MoQ filter type
 * \note Only supported in version -04 of the protocol */
typedef enum imquic_moq_filter_type {
	IMQUIC_MOQ_FILTER_LATEST_GROUP = 0x1,
	IMQUIC_MOQ_FILTER_LATEST_OBJECT = 0x2,
	IMQUIC_MOQ_FILTER_ABSOLUTE_START = 0x3,
	IMQUIC_MOQ_FILTER_ABSOLUTE_RANGE = 0x4,
} imquic_moq_filter_type;
/*! \brief Helper function to serialize to string the name of a imquic_moq_filter_type value.
 * @param type The imquic_moq_filter_type value
 * @returns The type name as a string, if valid, or NULL otherwise */
const char *imquic_moq_filter_type_str(imquic_moq_filter_type type);

/*! \brief Group ordering for FETCH
 * \note Only supported since version -07 of the protocol */
typedef enum imquic_moq_group_order {
	IMQUIC_MOQ_ORDERING_ORIGINAL = 0x0,
	IMQUIC_MOQ_ORDERING_ASCENDING = 0x1,
	IMQUIC_MOQ_ORDERING_DESCENDING = 0x2,
} imquic_moq_group_order;
/*! \brief Helper function to serialize to string the name of a imquic_moq_group_order value.
 * @param type The imquic_moq_group_order value
 * @returns The type name as a string, if valid, or NULL otherwise */
const char *imquic_moq_group_order_str(imquic_moq_group_order type);

/*! \brief MoQ FETCH types */
typedef enum imquic_moq_fetch_type {
	IMQUIC_MOQ_FETCH_STANDALONE = 0x01,
	IMQUIC_MOQ_FETCH_JOINING = 0x02
} imquic_moq_fetch_type;
/*! \brief Helper function to serialize to string the name of a imquic_moq_fetch_type value.
 * @param type The imquic_moq_fetch_type value
 * @returns The type name as a string, if valid, or NULL otherwise */
const char *imquic_moq_fetch_type_str(imquic_moq_fetch_type type);

/*! \brief MoQ context */
typedef struct imquic_moq_context {
	/*! \brief Associated QUIC connection */
	imquic_connection *conn;
	/*! \brief Negotiated version */
	imquic_moq_version version;
	/*! \brief Whether a version has been set */
	gboolean version_set;
	/*! \brief Role of this endpoint */
	imquic_moq_role_type type;
	/*! \brief Whether a role has been set */
	gboolean role_set;
	/*! \brief Whether this is a QUIC server or client */
	gboolean is_server;
	/*! \brief Whether a MoQ control stream has been established */
	gboolean has_control_stream;
	/*! \brief ID of the control stream */
	uint64_t control_stream_id;
	/*! \brief Current offset of the control stream on the way out */
	uint64_t control_stream_offset;
	/*! \brief QUIC streams handled by the stack */
	GHashTable *streams;
	/*! \brief Subscriptions this connection will send objects to, indexed by track_alias */
	GHashTable *subscriptions;
	/*! \brief Subscriptions this connection will send objects to, indexed by subscribe_id */
	GHashTable *subscriptions_by_id;
	/*! \brief Current Subscribe IDs we expect and we can send */
	uint64_t expected_subscribe_id, next_subscribe_id;
	/*! \brief Maximum Subscribe IDs we can send and the one we accept */
	uint64_t max_subscribe_id, local_max_subscribe_id;
	/*! \brief Mutex */
	imquic_mutex mutex;
	/*! \brief Whether we have established a connection */
	volatile gint connected;
	/*! \brief Whether this instance has been destroyed (reference counting) */
	volatile gint destroyed;
	/*! \brief Reference counter */
	imquic_refcount ref;
} imquic_moq_context;

/*! \brief MoQ buffer */
typedef struct imquic_moq_buffer {
	/*! \brief Buffer containing the data */
	uint8_t *bytes;
	/*! \brief Size of the data currently in the buffer */
	uint64_t length;
	/*! \brief Overall size of the buffer */
	uint64_t size;
} imquic_moq_buffer;
/*! \brief Resize an existing buffer
 * @note We can only increase the size of the buffer, not reduce it.
 * @param buffer Buffer to resize
 * @param new_size New size of the buffer
 * @returns TRUE if successful, a negative integer otherwise */
gboolean imquic_moq_buffer_resize(imquic_moq_buffer *buffer, uint64_t new_size);
/*! \brief Append data at the end of the buffer
 * @note This automatically resizes the buffer with imquic_moq_buffer_resize,
 * if appending the new data would exceeds the buffer size.
 * @param buffer Buffer to append the new data to
 * @param bytes Data to append
 * @param length Size of the data to append */
void imquic_moq_buffer_append(imquic_moq_buffer *buffer, uint8_t *bytes, uint64_t length);
/*! \brief Move the data in the buffer back of a specific number of bytes
 * @note This automatically updates the buffer length accordingly.
 * @param buffer Buffer to update
 * @param length How many bytes back the buffer should be moved */
void imquic_moq_buffer_shift(imquic_moq_buffer *buffer, uint64_t length);
/*! \brief Destroy an existing buffer
 * @param buffer Buffer to destroy */
void imquic_moq_buffer_destroy(imquic_moq_buffer *buffer);

/*! \brief MoQ stream */
typedef struct imquic_moq_stream {
	/*! \brief Delivery mode for this stream */
	imquic_moq_data_message_type type;
	/*! \brief QUIC stream ID */
	uint64_t stream_id;
	/*! \brief ID of the subscription */
	uint64_t subscribe_id;
	/*! \brief Track alias */
	uint64_t track_alias;
	/*! \brief Group ID */
	uint64_t group_id;
	/*! \brief Subgroup ID (only after v06) */
	uint64_t subgroup_id;
	/*! \brief Object ID */
	uint64_t object_id;
	/*! \brief Object status */
	imquic_moq_object_status object_status;
	/*! \brief Object send order (v03 and v04 only) */
	uint64_t object_send_order;
	/*! \brief Publisher priority (only after v05) */
	uint8_t priority;
	/*! \brief Current stream offset */
	uint64_t stream_offset;
	/*! \brief Buffer to process incoming messages/objects */
	imquic_moq_buffer *buffer;
	/*! \brief Whether we closed this stream */
	gboolean closed;
} imquic_moq_stream;
/*! \brief Destroy an existing MoQ stream
 * @param moq_stream MoQ stream to destroy */
void imquic_moq_stream_destroy(imquic_moq_stream *moq_stream);

/*! \brief MoQ subscription, whether this is a publisher or a subscriber */
typedef struct imquic_moq_subscription {
	/*! \brief ID of the subscription */
	uint64_t subscribe_id;
	/*! \brief Track alias */
	uint64_t track_alias;
	/*! \brief Whether this is a FETCH */
	gboolean fetch;
	/*! \brief Stream for this subscription, in case it's a single one */
	imquic_moq_stream *stream;
	/*! \brief Streams for this subscription, indexed by group */
	GHashTable *streams_by_group;
	/*! \brief Streams for this subscription, indexed by subgroup */
	GHashTable *streams_by_subgroup;
} imquic_moq_subscription;
/*! \brief Helper to create a new subscription instance
 * @param subscribe_id The subscription ID
 * @param track_alias The track alias
 * @returns A pointer to a imquic_moq_subscription, if successful, or NULL otherwise */
imquic_moq_subscription *imquic_moq_subscription_create(uint64_t subscribe_id, uint64_t track_alias);
/*! \brief Destroy an existing MoQ subscription
 * @param moq_sub MoQ subscription to destroy */
void imquic_moq_subscription_destroy(imquic_moq_subscription *moq_sub);

/** @name Parsing MoQ messages
 */
///@{
/*! \brief Parse an incoming MoQ message
 * @note This will iterate on a buffer, trying to parse as many messages
 * as possible in a sequential way. In case a message is incomplete (e.g.,
 * because we're still waiting on \c STREAM data), we move back to the
 * beginning of the buffer and return, waiting for more data to arrive.
 * @param moq The imquic_moq_context instance the message is for
 * @param stream_id The QUIC stream ID the message came from
 * @param bytes The buffer containing the message to parse
 * @param blen Size of the buffer to parse
 * @param complete Whether this data marks the completion of the QUIC stream it came from
 * @param datagram Whether this is not coming from a \c STREAM but a \c DATAGRAM
 * @returns 0 in case of success, or a negative integer otherwise */
int imquic_moq_parse_message(imquic_moq_context *moq, uint64_t stream_id, uint8_t *bytes, size_t blen, gboolean complete, gboolean datagram);
/*! \brief Helper to parse a \c CLIENT_SETUP message
 * @param[in] moq The imquic_moq_context instance the message is for
 * @param[in] bytes The buffer containing the message to parse
 * @param[in] blen Size of the buffer to parse
 * @param[out] error In/out property, initialized to 0 and set to 1 in case of parsing errors
 * @returns The size of the parsed message, if successful, or 0 otherwise */
size_t imquic_moq_parse_client_setup(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error);
/*! \brief Helper to parse a \c SERVER_SETUP message
 * @param[in] moq The imquic_moq_context instance the message is for
 * @param[in] bytes The buffer containing the message to parse
 * @param[in] blen Size of the buffer to parse
 * @param[out] error In/out property, initialized to 0 and set to 1 in case of parsing errors
 * @returns The size of the parsed message, if successful, or 0 otherwise */
size_t imquic_moq_parse_server_setup(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error);
/*! \brief Helper to parse a \c MAX_SUBSCRIBE_ID message
 * @param[in] moq The imquic_moq_context instance the message is for
 * @param[in] bytes The buffer containing the message to parse
 * @param[in] blen Size of the buffer to parse
 * @param[out] error In/out property, initialized to 0 and set to 1 in case of parsing errors
 * @returns The size of the parsed message, if successful, or 0 otherwise */
size_t imquic_moq_parse_max_subscribe_id(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error);
/*! \brief Helper to parse a \c SUBSCRIBES_BLOCKED message
 * @param[in] moq The imquic_moq_context instance the message is for
 * @param[in] bytes The buffer containing the message to parse
 * @param[in] blen Size of the buffer to parse
 * @param[out] error In/out property, initialized to 0 and set to 1 in case of parsing errors
 * @returns The size of the parsed message, if successful, or 0 otherwise */
size_t imquic_moq_parse_subscribes_blocked(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error);
/*! \brief Helper to parse an \c ANNOUNCE message
 * @param[in] moq The imquic_moq_context instance the message is for
 * @param[in] bytes The buffer containing the message to parse
 * @param[in] blen Size of the buffer to parse
 * @param[out] error In/out property, initialized to 0 and set to 1 in case of parsing errors
 * @returns The size of the parsed message, if successful, or 0 otherwise */
size_t imquic_moq_parse_announce(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error);
/*! \brief Helper to parse an \c ANNOUNCE_OK message
 * @param[in] moq The imquic_moq_context instance the message is for
 * @param[in] bytes The buffer containing the message to parse
 * @param[in] blen Size of the buffer to parse
 * @param[out] error In/out property, initialized to 0 and set to 1 in case of parsing errors
 * @returns The size of the parsed message, if successful, or 0 otherwise */
size_t imquic_moq_parse_announce_ok(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error);
/*! \brief Helper to parse an \c ANNOUNCE_ERROR message
 * @param[in] moq The imquic_moq_context instance the message is for
 * @param[in] bytes The buffer containing the message to parse
 * @param[in] blen Size of the buffer to parse
 * @param[out] error In/out property, initialized to 0 and set to 1 in case of parsing errors
 * @returns The size of the parsed message, if successful, or 0 otherwise */
size_t imquic_moq_parse_announce_error(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error);
/*! \brief Helper to parse an \c UNANNOUNCE message
 * @param[in] moq The imquic_moq_context instance the message is for
 * @param[in] bytes The buffer containing the message to parse
 * @param[in] blen Size of the buffer to parse
 * @param[out] error In/out property, initialized to 0 and set to 1 in case of parsing errors
 * @returns The size of the parsed message, if successful, or 0 otherwise */
size_t imquic_moq_parse_unannounce(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error);
/*! \brief Helper to parse an \c ANNOUNCE_CANCEL message
 * @param[in] moq The imquic_moq_context instance the message is for
 * @param[in] bytes The buffer containing the message to parse
 * @param[in] blen Size of the buffer to parse
 * @param[out] error In/out property, initialized to 0 and set to 1 in case of parsing errors
 * @returns The size of the parsed message, if successful, or 0 otherwise */
size_t imquic_moq_parse_announce_cancel(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error);
/*! \brief Helper to parse a \c SUBSCRIBE message
 * @param[in] moq The imquic_moq_context instance the message is for
 * @param[in] bytes The buffer containing the message to parse
 * @param[in] blen Size of the buffer to parse
 * @param[out] error In/out property, initialized to 0 and set to 1 in case of parsing errors
 * @returns The size of the parsed message, if successful, or 0 otherwise */
size_t imquic_moq_parse_subscribe(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error);
/*! \brief Helper to parse a \c SUBSCRIBE_UPDATE message
 * @param[in] moq The imquic_moq_context instance the message is for
 * @param[in] bytes The buffer containing the message to parse
 * @param[in] blen Size of the buffer to parse
 * @param[out] error In/out property, initialized to 0 and set to 1 in case of parsing errors
 * @returns The size of the parsed message, if successful, or 0 otherwise */
size_t imquic_moq_parse_subscribe_update(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error);
/*! \brief Helper to parse a \c SUBSCRIBE_OK message
 * @param[in] moq The imquic_moq_context instance the message is for
 * @param[in] bytes The buffer containing the message to parse
 * @param[in] blen Size of the buffer to parse
 * @param[out] error In/out property, initialized to 0 and set to 1 in case of parsing errors
 * @returns The size of the parsed message, if successful, or 0 otherwise */
size_t imquic_moq_parse_subscribe_ok(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error);
/*! \brief Helper to parse a \c SUBSCRIBE_ERROR message
 * @param[in] moq The imquic_moq_context instance the message is for
 * @param[in] bytes The buffer containing the message to parse
 * @param[in] blen Size of the buffer to parse
 * @param[out] error In/out property, initialized to 0 and set to 1 in case of parsing errors
 * @returns The size of the parsed message, if successful, or 0 otherwise */
size_t imquic_moq_parse_subscribe_error(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error);
/*! \brief Helper to parse an \c UNSUBSCRIBE message
 * @param[in] moq The imquic_moq_context instance the message is for
 * @param[in] bytes The buffer containing the message to parse
 * @param[in] blen Size of the buffer to parse
 * @param[out] error In/out property, initialized to 0 and set to 1 in case of parsing errors
 * @returns The size of the parsed message, if successful, or 0 otherwise */
size_t imquic_moq_parse_unsubscribe(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error);
/*! \brief Helper to parse a \c SUBSCRIBE_DONE message
 * @param[in] moq The imquic_moq_context instance the message is for
 * @param[in] bytes The buffer containing the message to parse
 * @param[in] blen Size of the buffer to parse
 * @param[out] error In/out property, initialized to 0 and set to 1 in case of parsing errors
 * @returns The size of the parsed message, if successful, or 0 otherwise */
size_t imquic_moq_parse_subscribe_done(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error);
/*! \brief Helper to parse a \c SUBSCRIBE_ANNOUNCES message
 * @param[in] moq The imquic_moq_context instance the message is for
 * @param[in] bytes The buffer containing the message to parse
 * @param[in] blen Size of the buffer to parse
 * @param[out] error In/out property, initialized to 0 and set to 1 in case of parsing errors
 * @returns The size of the parsed message, if successful, or 0 otherwise */
size_t imquic_moq_parse_subscribe_announces(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error);
/*! \brief Helper to parse a \c SUBSCRIBE_ANNOUNCES_OK message
 * @param[in] moq The imquic_moq_context instance the message is for
 * @param[in] bytes The buffer containing the message to parse
 * @param[in] blen Size of the buffer to parse
 * @param[out] error In/out property, initialized to 0 and set to 1 in case of parsing errors
 * @returns The size of the parsed message, if successful, or 0 otherwise */
size_t imquic_moq_parse_subscribe_announces_ok(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error);
/*! \brief Helper to parse a \c SUBSCRIBE_ANNOUNCES_ERROR message
 * @param[in] moq The imquic_moq_context instance the message is for
 * @param[in] bytes The buffer containing the message to parse
 * @param[in] blen Size of the buffer to parse
 * @param[out] error In/out property, initialized to 0 and set to 1 in case of parsing errors
 * @returns The size of the parsed message, if successful, or 0 otherwise */
size_t imquic_moq_parse_subscribe_announces_error(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error);
/*! \brief Helper to parse an \c UNSUBSCRIBE_ANNOUNCES message
 * @param[in] moq The imquic_moq_context instance the message is for
 * @param[in] bytes The buffer containing the message to parse
 * @param[in] blen Size of the buffer to parse
 * @param[out] error In/out property, initialized to 0 and set to 1 in case of parsing errors
 * @returns The size of the parsed message, if successful, or 0 otherwise */
size_t imquic_moq_parse_unsubscribe_announces(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error);
/*! \brief Helper to parse a \c FETCH message
 * @param[in] moq The imquic_moq_context instance the message is for
 * @param[in] bytes The buffer containing the message to parse
 * @param[in] blen Size of the buffer to parse
 * @param[out] error In/out property, initialized to 0 and set to 1 in case of parsing errors
 * @returns The size of the parsed message, if successful, or 0 otherwise */
size_t imquic_moq_parse_fetch(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error);
/*! \brief Helper to parse a \c FETCH_CANCEL message
 * @param[in] moq The imquic_moq_context instance the message is for
 * @param[in] bytes The buffer containing the message to parse
 * @param[in] blen Size of the buffer to parse
 * @param[out] error In/out property, initialized to 0 and set to 1 in case of parsing errors
 * @returns The size of the parsed message, if successful, or 0 otherwise */
size_t imquic_moq_parse_fetch_cancel(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error);
/*! \brief Helper to parse a \c FETCH_OK message
 * @param[in] moq The imquic_moq_context instance the message is for
 * @param[in] bytes The buffer containing the message to parse
 * @param[in] blen Size of the buffer to parse
 * @param[out] error In/out property, initialized to 0 and set to 1 in case of parsing errors
 * @returns The size of the parsed message, if successful, or 0 otherwise */
size_t imquic_moq_parse_fetch_ok(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error);
/*! \brief Helper to parse a \c FETCH_ERROR message
 * @param[in] moq The imquic_moq_context instance the message is for
 * @param[in] bytes The buffer containing the message to parse
 * @param[in] blen Size of the buffer to parse
 * @param[out] error In/out property, initialized to 0 and set to 1 in case of parsing errors
 * @returns The size of the parsed message, if successful, or 0 otherwise */
size_t imquic_moq_parse_fetch_error(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error);
/*! \brief Helper to parse a \c TRACK_STATUS_REQUEST message
 * @param[in] moq The imquic_moq_context instance the message is for
 * @param[in] bytes The buffer containing the message to parse
 * @param[in] blen Size of the buffer to parse
 * @param[out] error In/out property, initialized to 0 and set to 1 in case of parsing errors
 * @returns The size of the parsed message, if successful, or 0 otherwise */
size_t imquic_moq_parse_track_status_request(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error);
/*! \brief Helper to parse a \c TRACK_STATUS message
 * @param[in] moq The imquic_moq_context instance the message is for
 * @param[in] bytes The buffer containing the message to parse
 * @param[in] blen Size of the buffer to parse
 * @param[out] error In/out property, initialized to 0 and set to 1 in case of parsing errors
 * @returns The size of the parsed message, if successful, or 0 otherwise */
size_t imquic_moq_parse_track_status(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error);
/*! \brief Helper to parse an \c OBJECT_STREAM message
 * @param[in] moq The imquic_moq_context instance the message is for
 * @param[in] moq_stream The imquic_moq_context instance the message came from
 * @param[in] bytes The buffer containing the message to parse
 * @param[in] blen Size of the buffer to parse
 * @param[out] error In/out property, initialized to 0 and set to 1 in case of parsing errors
 * @returns The size of the parsed message, if successful, or 0 otherwise */
size_t imquic_moq_parse_object_stream(imquic_moq_context *moq, imquic_moq_stream *moq_stream, uint8_t *bytes, size_t blen, uint8_t *error);
/*! \brief Helper to parse an \c OBJECT_DATAGRAM message
 * @param[in] moq The imquic_moq_context instance the message is for
 * @param[in] bytes The buffer containing the message to parse
 * @param[in] blen Size of the buffer to parse
 * @param[out] error In/out property, initialized to 0 and set to 1 in case of parsing errors
 * @returns The size of the parsed message, if successful, or 0 otherwise */
size_t imquic_moq_parse_object_datagram(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error);
/*! \brief Helper to parse an \c OBJECT_DATAGRAM_STATUS message
 * @param[in] moq The imquic_moq_context instance the message is for
 * @param[in] bytes The buffer containing the message to parse
 * @param[in] blen Size of the buffer to parse
 * @param[out] error In/out property, initialized to 0 and set to 1 in case of parsing errors
 * @returns The size of the parsed message, if successful, or 0 otherwise */
size_t imquic_moq_parse_object_datagram_status(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error);
/*! \brief Helper to parse a \c STREAM_HEADER_TRACK message
 * @param[in] moq The imquic_moq_context instance the message is for
 * @param[in] moq_stream The imquic_moq_context instance the object is from
 * @param[in] bytes The buffer containing the message to parse
 * @param[in] blen Size of the buffer to parse
 * @param[out] error In/out property, initialized to 0 and set to 1 in case of parsing errors
 * @returns The size of the parsed message, if successful, or 0 otherwise */
size_t imquic_moq_parse_stream_header_track(imquic_moq_context *moq, imquic_moq_stream *moq_stream, uint8_t *bytes, size_t blen, uint8_t *error);
/*! \brief Helper to parse a \c STREAM_HEADER_TRACK object
 * @note A negative response doesn't mean there's an error, but just that
 * the object isn't complete yet and we need to wait for more data.
 * @param[in] moq The imquic_moq_context instance the object is for
 * @param[in] moq_stream The imquic_moq_context instance the object is from
 * @param[in] complete Whether this data marks the completion of the QUIC stream it came from
 * @returns 0 in case of success, or a negative integer otherwise */
int imquic_moq_parse_stream_header_track_object(imquic_moq_context *moq, imquic_moq_stream *moq_stream, gboolean complete);
/*! \brief Helper to parse a \c STREAM_HEADER_GROUP message
 * @param[in] moq The imquic_moq_context instance the message is for
 * @param[in] moq_stream The imquic_moq_context instance the message came from
 * @param[in] bytes The buffer containing the message to parse
 * @param[in] blen Size of the buffer to parse
 * @param[out] error In/out property, initialized to 0 and set to 1 in case of parsing errors
 * @returns The size of the parsed message, if successful, or 0 otherwise */
size_t imquic_moq_parse_stream_header_group(imquic_moq_context *moq, imquic_moq_stream *moq_stream, uint8_t *bytes, size_t blen, uint8_t *error);
/*! \brief Helper to parse a \c STREAM_HEADER_GROUP object
 * @note A negative response doesn't mean there's an error, but just that
 * the object isn't complete yet and we need to wait for more data.
 * @param[in] moq The imquic_moq_context instance the object is for
 * @param[in] moq_stream The imquic_moq_context instance the object is from
 * @param[in] complete Whether this data marks the completion of the QUIC stream it came from
 * @returns 0 in case of success, or a negative integer otherwise */
int imquic_moq_parse_stream_header_group_object(imquic_moq_context *moq, imquic_moq_stream *moq_stream, gboolean complete);
/*! \brief Helper to parse a \c SUBGROUP_HEADER message
 * @param[in] moq The imquic_moq_context instance the message is for
 * @param[in] moq_stream The imquic_moq_context instance the message came from
 * @param[in] bytes The buffer containing the message to parse
 * @param[in] blen Size of the buffer to parse
 * @param[out] error In/out property, initialized to 0 and set to 1 in case of parsing errors
 * @returns The size of the parsed message, if successful, or 0 otherwise */
size_t imquic_moq_parse_subgroup_header(imquic_moq_context *moq, imquic_moq_stream *moq_stream, uint8_t *bytes, size_t blen, uint8_t *error);
/*! \brief Helper to parse a \c SUBGROUP_HEADER object
 * @note A negative response doesn't mean there's an error, but just that
 * the object isn't complete yet and we need to wait for more data.
 * @param[in] moq The imquic_moq_context instance the object is for
 * @param[in] moq_stream The imquic_moq_context instance the object is from
 * @param[in] complete Whether this data marks the completion of the QUIC stream it came from
 * @returns 0 in case of success, or a negative integer otherwise */
int imquic_moq_parse_subgroup_header_object(imquic_moq_context *moq, imquic_moq_stream *moq_stream, gboolean complete);
/*! \brief Helper to parse a \c FETCH_HEADER message
 * @param[in] moq The imquic_moq_context instance the message is for
 * @param[in] moq_stream The imquic_moq_context instance the object is from
 * @param[in] bytes The buffer containing the message to parse
 * @param[in] blen Size of the buffer to parse
 * @param[out] error In/out property, initialized to 0 and set to 1 in case of parsing errors
 * @returns The size of the parsed message, if successful, or 0 otherwise */
size_t imquic_moq_parse_fetch_header(imquic_moq_context *moq, imquic_moq_stream *moq_stream, uint8_t *bytes, size_t blen, uint8_t *error);
/*! \brief Helper to parse a \c FETCH_HEADER object
 * @note A negative response doesn't mean there's an error, but just that
 * the object isn't complete yet and we need to wait for more data.
 * @param[in] moq The imquic_moq_context instance the object is for
 * @param[in] moq_stream The imquic_moq_context instance the object is from
 * @param[in] complete Whether this data marks the completion of the QUIC stream it came from
 * @returns 0 in case of success, or a negative integer otherwise */
int imquic_moq_parse_fetch_header_object(imquic_moq_context *moq, imquic_moq_stream *moq_stream, gboolean complete);
/*! \brief Helper to parse a \c GOAWAY message
 * @param[in] moq The imquic_moq_context instance the message is for
 * @param[in] bytes The buffer containing the message to parse
 * @param[in] blen Size of the buffer to parse
 * @param[out] error In/out property, initialized to 0 and set to 1 in case of parsing errors
 * @returns The size of the parsed message, if successful, or 0 otherwise */
size_t imquic_moq_parse_goaway(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error);
///@}

/** @name Building MoQ messages
 */
///@{
/*! \brief Helper method to put a message header and a payload together
 * @note All the "add" functions for control messages don't set the type
 * in the buffer, since versions of MoQ later than v06 also envision a
 * payload length varint: as such, we prepare the payload first, and
 * prefix the message type (and optionally the payload length) later.
 * @param[in] moq The imquic_moq_context generating the message
 * @param[in] type The ID of the control message to send
 * @param[in] bytes The buffer to add the control message to
 * @param[in] blen The size of the buffer
 * @param[in] poffset Where in the provided buffer we already have the payload
 * @param[in] plen Size of the payload in the buffer
 * @param[out] start Where the final control message starts, in the buffer
 * @returns The size of the generated message, if successful, or 0 otherwise */
size_t imquic_moq_add_control_message(imquic_moq_context *moq, imquic_moq_message_type type,
	uint8_t *bytes, size_t blen, size_t poffset, size_t plen, size_t *start);
/*! \brief Helper method to add a \c CLIENT_SETUP message to a buffer
 * @param moq The imquic_moq_context generating the message
 * @param bytes The buffer to add the message to
 * @param blen The size of the buffer
 * @param supported_versions List of supported versions
 * @param params_num Number of parameters to add to the message, if any
 * @param parameters A buffer containing an already serialized list of parameters
 * @returns The size of the generated message, if successful, or 0 otherwise */
size_t imquic_moq_add_client_setup(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
	GList *supported_versions, size_t params_num, imquic_data *parameters);
/*! \brief Helper method to add a \c SERVER_SETUP message to a buffer
 * @param moq The imquic_moq_context generating the message
 * @param bytes The buffer to add the message to
 * @param blen The size of the buffer
 * @param version Negotiated version
 * @param params_num Number of parameters to add to the message, if any
 * @param parameters A buffer containing an already serialized list of parameters
 * @returns The size of the generated message, if successful, or 0 otherwise */
size_t imquic_moq_add_server_setup(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
	uint32_t version, size_t params_num, imquic_data *parameters);
/*! \brief Helper method to add a \c MAX_SUBSCRIBE_ID message to a buffer
 * @param moq The imquic_moq_context generating the message
 * @param bytes The buffer to add the message to
 * @param blen The size of the buffer
 * @param max_subscribe_id Maximum subscribe ID to put in the message
 * @returns The size of the generated message, if successful, or 0 otherwise */
size_t imquic_moq_add_max_subscribe_id(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint64_t max_subscribe_id);
/*! \brief Helper method to add a \c SUBSCRIBES_BLOCKED message to a buffer
 * @param moq The imquic_moq_context generating the message
 * @param bytes The buffer to add the message to
 * @param blen The size of the buffer
 * @param max_subscribe_id Maximum subscribe ID to put in the message
 * @returns The size of the generated message, if successful, or 0 otherwise */
size_t imquic_moq_add_subscribes_blocked(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint64_t max_subscribe_id);
/*! \brief Helper method to add an \c ANNOUNCE message to a buffer
 * @param moq The imquic_moq_context generating the message
 * @param bytes The buffer to add the message to
 * @param blen The size of the buffer
 * @param track_namespace Namespace to announce
 * @param params_num Number of parameters to add to the message, if any
 * @param parameters A buffer containing an already serialized list of parameters
 * @returns The size of the generated message, if successful, or 0 otherwise */
size_t imquic_moq_add_announce(imquic_moq_context *moq, uint8_t *bytes, size_t blen, imquic_moq_namespace *track_namespace,
	size_t params_num, imquic_data *parameters);
/*! \brief Helper method to add an \c ANNOUNCE_OK message to a buffer
 * @param moq The imquic_moq_context generating the message
 * @param bytes The buffer to add the message to
 * @param blen The size of the buffer
 * @param track_namespace Namespace for which the announcement succeeded
 * @returns The size of the generated message, if successful, or 0 otherwise */
size_t imquic_moq_add_announce_ok(imquic_moq_context *moq, uint8_t *bytes, size_t blen, imquic_moq_namespace *track_namespace);
/*! \brief Helper method to add an \c ANNOUNCE_ERROR message to a buffer
 * @param moq The imquic_moq_context generating the message
 * @param bytes The buffer to add the message to
 * @param blen The size of the buffer
 * @param track_namespace Namespace for which the announcement caused an error
 * @param error Error code associated to the message
 * @param reason Verbose description of the error, if any
 * @returns The size of the generated message, if successful, or 0 otherwise */
size_t imquic_moq_add_announce_error(imquic_moq_context *moq, uint8_t *bytes, size_t blen, imquic_moq_namespace *track_namespace,
	imquic_moq_announce_error_code error, const char *reason);
/*! \brief Helper method to add an \c UNANNOUNCE message to a buffer
 * @param moq The imquic_moq_context generating the message
 * @param bytes The buffer to add the message to
 * @param blen The size of the buffer
 * @param track_namespace Namespace to unannounce
 * @returns The size of the generated message, if successful, or 0 otherwise */
size_t imquic_moq_add_unannounce(imquic_moq_context *moq, uint8_t *bytes, size_t blen, imquic_moq_namespace *track_namespace);
/*! \brief Helper method to add aN \c ANNOUNCE_CANCEL message to a buffer
 * @param moq The imquic_moq_context generating the message
 * @param bytes The buffer to add the message to
 * @param blen The size of the buffer
 * @param track_namespace Namespace for which to cancel the announcement
 * @returns The size of the generated message, if successful, or 0 otherwise */
size_t imquic_moq_add_announce_cancel(imquic_moq_context *moq, uint8_t *bytes, size_t blen, imquic_moq_namespace *track_namespace);
/*! \brief Helper to add a \c SUBSCRIBE message (version -03 of the draft) to a buffer
 * @note This sends the \c -03 variant of the message
 * @param moq The imquic_moq_context generating the message
 * @param bytes The buffer to add the message to
 * @param blen The size of the buffer
 * @param subscribe_id The subscription ID to put in the message
 * @param track_alias The track alias to put in the message
 * @param track_namespace The namespace to put in the message
 * @param track_name The track name to put in the message
 * @param start_group The start group as a imquic_moq_location instance, if any
 * @param start_object The start object as a imquic_moq_location instance, if any
 * @param end_group The end group as a imquic_moq_location instance, if any
 * @param end_object The end object as a imquic_moq_location instance, if any
 * @param params_num Number of parameters to add to the message, if any
 * @param parameters A buffer containing an already serialized list of parameters
 * @returns The size of the generated message, if successful, or 0 otherwise */
size_t imquic_moq_add_subscribe_v03(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint64_t subscribe_id, uint64_t track_alias,
	imquic_moq_namespace *track_namespace, imquic_moq_name *track_name, imquic_moq_location *start_group, imquic_moq_location *start_object,
	imquic_moq_location *end_group, imquic_moq_location *end_object, size_t params_num, imquic_data *parameters);
/*! \brief Helper to add a \c SUBSCRIBE message (any version of the draft except v03) to a buffer
 * @note This sends the \c -04 or \c -05 variant of the message
 * @param moq The imquic_moq_context generating the message
 * @param bytes The buffer to add the message to
 * @param blen The size of the buffer
 * @param subscribe_id The subscription ID to put in the message
 * @param track_alias The track alias to put in the message
 * @param track_namespace The namespace to put in the message
 * @param track_name The track name to put in the message
 * @param priority The subscriber priority to put in the message (only after v05)
 * @param group_order The group order to put in the message (only after v05)
 * @param filter The filter as a imquic_moq_filter_type value
 * @param start_group The start group ID to put in the message
 * @param start_object The start object ID to put in the message
 * @param end_group The end group ID to put in the message
 * @param end_object The end object ID to put in the message
 * @param params_num Number of parameters to add to the message, if any
 * @param parameters A buffer containing an already serialized list of parameters
 * @returns The size of the generated message, if successful, or 0 otherwise */
size_t imquic_moq_add_subscribe(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint64_t subscribe_id, uint64_t track_alias,
	imquic_moq_namespace *track_namespace, imquic_moq_name *track_name, uint8_t priority, uint8_t group_order, imquic_moq_filter_type filter,
	uint64_t start_group, uint64_t start_object, uint64_t end_group, uint64_t end_object, size_t params_num, imquic_data *parameters);
/*! \brief Helper method to add a \c SUBSCRIBE_UPDATE message to a buffer
 * @param moq The imquic_moq_context generating the message
 * @param bytes The buffer to add the message to
 * @param blen The size of the buffer
 * @param subscribe_id The subscription ID to put in the message
 * @param start_group The start group ID to put in the message
 * @param start_object The start object ID to put in the message
 * @param end_group The end group ID to put in the message
 * @param end_object The end object ID to put in the message
 * @param priority The subscriber priority to put in the message (only after v05)
 * @param params_num Number of parameters to add to the message, if any
 * @param parameters A buffer containing an already serialized list of parameters
 * @returns The size of the generated message, if successful, or 0 otherwise */
size_t imquic_moq_add_subscribe_update(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint64_t subscribe_id,
	uint64_t start_group, uint64_t start_object, uint64_t end_group, uint64_t end_object, uint8_t priority,
	size_t params_num, imquic_data *parameters);
/*! \brief Helper method to add a \c SUBSCRIBE_OK message to a buffer
 * @param moq The imquic_moq_context generating the message
 * @param bytes The buffer to add the message to
 * @param blen The size of the buffer
 * @param subscribe_id The subscription ID to put in the message
 * @param expires The expires value to put in the message
 * @param group_order The group order to put in the message (only after v05)
 * @param content_exists Whether the following two properties should be added to the message
 * @param largest_group_id Largest group ID to add to the message, if needed
 * @param largest_object_id Largest object ID to add to the message, if needed
 * @param params_num Number of parameters to add to the message, if any (only after v06)
 * @param parameters A buffer containing an already serialized list of parameters (only after v06)
 * @returns The size of the generated message, if successful, or 0 otherwise */
size_t imquic_moq_add_subscribe_ok(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint64_t subscribe_id,
	uint64_t expires, imquic_moq_group_order group_order, gboolean content_exists, uint64_t largest_group_id, uint64_t largest_object_id,
	size_t params_num, imquic_data *parameters);
/*! \brief Helper method to add a \c SUBSCRIBE_ERRROR message to a buffer
 * @param moq The imquic_moq_context generating the message
 * @param bytes The buffer to add the message to
 * @param blen The size of the buffer
 * @param subscribe_id The subscription ID to put in the message
 * @param error Error code associated to the message
 * @param reason Verbose description of the error, if any
 * @param track_alias The track alias to put in the message
 * @returns The size of the generated message, if successful, or 0 otherwise */
size_t imquic_moq_add_subscribe_error(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint64_t subscribe_id,
	imquic_moq_sub_error_code error, const char *reason, uint64_t track_alias);
/*! \brief Helper method to add an \c UNSUBSCRIBE message to a buffer
 * @param moq The imquic_moq_context generating the message
 * @param bytes The buffer to add the message to
 * @param blen The size of the buffer
 * @param subscribe_id The subscription ID to put in the message
 * @returns The size of the generated message, if successful, or 0 otherwise */
size_t imquic_moq_add_unsubscribe(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint64_t subscribe_id);
/*! \brief Helper method to add a \c SUBSCRIBE_DONE message to a buffer
 * @param moq The imquic_moq_context generating the message
 * @param bytes The buffer to add the message to
 * @param blen The size of the buffer
 * @param subscribe_id The subscription ID to put in the message
 * @param status The status of the subscrption
 * @param streams_count The streams count (only after v07)
 * @param reason Verbose description of the status
 * @param content_exists Whether the following two properties should be added to the message (only before v08)
 * @param final_group Final group ID to add to the message, if needed (only before v08)
 * @param final_object Final object ID to add to the message, if needed (only before v08)
 * @returns The size of the generated message, if successful, or 0 otherwise (only before v08) */
size_t imquic_moq_add_subscribe_done(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint64_t subscribe_id,
	imquic_moq_sub_done_code status, uint64_t streams_count, const char *reason, gboolean content_exists, uint64_t final_group, uint64_t final_object);
/*! \brief Helper to add a \c SUBSCRIBE_ANNOUNCES message (version -04 of the draft) to a buffer
 * @note This sends the \c -04 or \c -05 variant of the message
 * @param moq The imquic_moq_context generating the message
 * @param bytes The buffer to add the message to
 * @param blen The size of the buffer
 * @param track_namespace The namespace to put in the message
 * @param params_num Number of parameters to add to the message, if any
 * @param parameters A buffer containing an already serialized list of parameters
 * @returns The size of the generated message, if successful, or 0 otherwise */
size_t imquic_moq_add_subscribe_announces(imquic_moq_context *moq, uint8_t *bytes, size_t blen, imquic_moq_namespace *track_namespace,
	size_t params_num, imquic_data *parameters);
/*! \brief Helper method to add a \c SUBSCRIBE_ANNOUNCES_OK message to a buffer
 * @param moq The imquic_moq_context generating the message
 * @param bytes The buffer to add the message to
 * @param blen The size of the buffer
 * @param track_namespace The namespace to put in the message
 * @returns The size of the generated message, if successful, or 0 otherwise */
size_t imquic_moq_add_subscribe_announces_ok(imquic_moq_context *moq, uint8_t *bytes, size_t blen, imquic_moq_namespace *track_namespace);
/*! \brief Helper method to add a \c SUBSCRIBE_ANNOUNCES_ERRROR message to a buffer
 * @param moq The imquic_moq_context generating the message
 * @param bytes The buffer to add the message to
 * @param blen The size of the buffer
 * @param track_namespace The namespace to put in the message
 * @param error Error code associated to the message
 * @param reason Verbose description of the error, if any
 * @returns The size of the generated message, if successful, or 0 otherwise */
size_t imquic_moq_add_subscribe_announces_error(imquic_moq_context *moq, uint8_t *bytes, size_t blen, imquic_moq_namespace *track_namespace,
	imquic_moq_subannc_error_code error, const char *reason);
/*! \brief Helper method to add an \c UNSUBSCRIBE_ANNOUNCES message to a buffer
 * @param moq The imquic_moq_context generating the message
 * @param bytes The buffer to add the message to
 * @param blen The size of the buffer
 * @param track_namespace The namespace to put in the message
 * @returns The size of the generated message, if successful, or 0 otherwise */
size_t imquic_moq_add_unsubscribe_announces(imquic_moq_context *moq, uint8_t *bytes, size_t blen, imquic_moq_namespace *track_namespace);
/*! \brief Helper to add a \c FETCH message (any version of the draft except v03) to a buffer
 * @note This sends the \c -04 or \c -05 variant of the message
 * @param moq The imquic_moq_context generating the message
 * @param bytes The buffer to add the message to
 * @param blen The size of the buffer
 * @param type The FETCH type
 * @param subscribe_id The subscription ID to put in the message
 * @param joining_subscribe_id The joining subscription ID to put in the message, if any
 * @param preceding_group_offset The preceding group offset for joining fetches, if any
 * @param track_namespace The namespace to put in the message
 * @param track_name The track name to put in the message
 * @param priority The fetchr priority to put in the message
 * @param group_order The group order to put in the message
 * @param start_group The start group ID to put in the message
 * @param start_object The start object ID to put in the message
 * @param end_group The end group ID to put in the message
 * @param end_object The end object ID to put in the message
 * @param params_num Number of parameters to add to the message, if any
 * @param parameters A buffer containing an already serialized list of parameters
 * @returns The size of the generated message, if successful, or 0 otherwise */
size_t imquic_moq_add_fetch(imquic_moq_context *moq, uint8_t *bytes, size_t blen, imquic_moq_fetch_type type,
	uint64_t subscribe_id, uint64_t joining_subscribe_id, uint64_t preceding_group_offset,
	imquic_moq_namespace *track_namespace, imquic_moq_name *track_name, uint8_t priority, imquic_moq_group_order group_order,
	uint64_t start_group, uint64_t start_object, uint64_t end_group, uint64_t end_object, size_t params_num, imquic_data *parameters);
/*! \brief Helper method to add an \c FETCH_CANCEL message to a buffer
 * @param moq The imquic_moq_context generating the message
 * @param bytes The buffer to add the message to
 * @param blen The size of the buffer
 * @param subscribe_id The subscription ID to put in the message
 * @returns The size of the generated message, if successful, or 0 otherwise */
size_t imquic_moq_add_fetch_cancel(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint64_t subscribe_id);
/*! \brief Helper method to add a \c FETCH_OK message to a buffer
 * @param moq The imquic_moq_context generating the message
 * @param bytes The buffer to add the message to
 * @param blen The size of the buffer
 * @param subscribe_id The subscription ID to put in the message
 * @param group_order The group order to put in the message
 * @param end_of_track Whether all objects have been published
 * @param largest_group_id Largest group ID to add to the message, if needed
 * @param largest_object_id Largest object ID to add to the message, if needed
 * @param params_num Number of parameters to add to the message, if any
 * @param parameters A buffer containing an already serialized list of parameters
 * @returns The size of the generated message, if successful, or 0 otherwise */
size_t imquic_moq_add_fetch_ok(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint64_t subscribe_id,
	uint8_t group_order, uint8_t end_of_track, uint64_t largest_group_id, uint64_t largest_object_id,
	size_t params_num, imquic_data *parameters);
/*! \brief Helper method to add a \c FETCH_ERRROR message to a buffer
 * @param moq The imquic_moq_context generating the message
 * @param bytes The buffer to add the message to
 * @param blen The size of the buffer
 * @param subscribe_id The subscription ID to put in the message
 * @param error Error code associated to the message
 * @param reason Verbose description of the error, if any
 * @returns The size of the generated message, if successful, or 0 otherwise */
size_t imquic_moq_add_fetch_error(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint64_t subscribe_id,
	imquic_moq_fetch_error_code error, const char *reason);
/*! \brief Helper to add a \c TRACK_STATUS_REQUEST message to a buffer
 * @param moq The imquic_moq_context generating the message
 * @param bytes The buffer to add the message to
 * @param blen The size of the buffer
 * @param track_namespace The namespace to put in the message
 * @param track_name The track name to put in the message
 * @returns The size of the generated message, if successful, or 0 otherwise */
size_t imquic_moq_add_track_status_request(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
	imquic_moq_namespace *track_namespace, imquic_moq_name *track_name);
/*! \brief Helper to add a \c TRACK_STATUS message to a buffer
 * @param moq The imquic_moq_context generating the message
 * @param bytes The buffer to add the message to
 * @param blen The size of the buffer
 * @param track_namespace The namespace to put in the message
 * @param track_name The track name to put in the message
 * @param status_code The status code to put in the message
 * @param last_group_id The last group ID to put in the message
 * @param last_object_id The last object ID to put in the message
 * @returns The size of the generated message, if successful, or 0 otherwise */
size_t imquic_moq_add_track_status(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
	imquic_moq_namespace *track_namespace, imquic_moq_name *track_name, uint64_t status_code, uint64_t last_group_id, uint64_t last_object_id);
/*! \brief Helper to add an \c OBJECT_STREAM message to a buffer (only before v06)
 * @note This will create a throaway \c STREAM just to send this object
 * @param moq The imquic_moq_context generating the message
 * @param bytes The buffer to add the message to
 * @param blen The size of the buffer
 * @param subscribe_id The subscription ID to put in the message
 * @param track_alias The track alias to put in the message
 * @param group_id The group ID to put in the message
 * @param object_id The object ID to put in the message
 * @param object_status The object status (only added if the payload length is 0)
 * @param object_send_order The object send order to put in the message (v03 and v04 only)
 * @param priority The publisher priority to put in the message (only after v05)
 * @param payload The buffer containing the payload of the object
 * @param plen The size of the payload buffer
 * @returns The size of the generated message, if successful, or 0 otherwise */
size_t imquic_moq_add_object_stream(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint64_t subscribe_id, uint64_t track_alias,
	uint64_t group_id, uint64_t object_id, uint64_t object_status, uint64_t object_send_order, uint8_t priority, uint8_t *payload, size_t plen);
/*! \brief Helper to add an \c OBJECT_DATAGRAM message to a buffer
 * @note This assumes the connection negotiated \c DATAGRAM support
 * @param moq The imquic_moq_context generating the message
 * @param bytes The buffer to add the message to
 * @param blen The size of the buffer
 * @param subscribe_id The subscription ID to put in the message
 * @param track_alias The track alias to put in the message
 * @param group_id The group ID to put in the message
 * @param object_id The object ID to put in the message
 * @param object_status The object status (only added if the payload length is 0)
 * @param object_send_order The object send order to put in the message (v03 and v04 only)
 * @param priority The publisher priority to put in the message (only after v05)
 * @param payload The buffer containing the payload of the object
 * @param plen The size of the payload buffer
 * @param extensions List of extensions to add (only after v08)
 * @returns The size of the generated message, if successful, or 0 otherwise */
size_t imquic_moq_add_object_datagram(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint64_t subscribe_id, uint64_t track_alias,
	uint64_t group_id, uint64_t object_id, uint64_t object_status, uint64_t object_send_order, uint8_t priority,
	uint8_t *payload, size_t plen, GList *extensions);
/*! \brief Helper to add an \c OBJECT_DATAGRAM_STATUS message to a buffer
 * @note This assumes the connection negotiated \c DATAGRAM support
 * @param moq The imquic_moq_context generating the message
 * @param bytes The buffer to add the message to
 * @param blen The size of the buffer
 * @param track_alias The track alias to put in the message
 * @param group_id The group ID to put in the message
 * @param object_id The object ID to put in the message
 * @param priority The publisher priority to put in the message (only after v05)
 * @param object_status The object status (only added if the payload length is 0)
 * @returns The size of the generated message, if successful, or 0 otherwise */
size_t imquic_moq_add_object_datagram_status(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
	uint64_t track_alias, uint64_t group_id, uint64_t object_id, uint8_t priority, uint64_t object_status);
/*! \brief Helper to add a \c STREAM_HEADER_TRACK message to a buffer (only before v06)
 * @note This will create a new \c STREAM and send the header: after
 * that, imquic_moq_add_stream_header_track_object is used to send
 * all objects that belong to this track.
 * @param moq The imquic_moq_context generating the message
 * @param bytes The buffer to add the message to
 * @param blen The size of the buffer
 * @param subscribe_id The subscription ID to put in the message
 * @param track_alias The track alias to put in the message
 * @param object_send_order The object send order to put in the message (v03 and v04 only)
 * @param priority The publisher priority to put in the message (only after v05)
 * @returns The size of the generated message, if successful, or 0 otherwise */
size_t imquic_moq_add_stream_header_track(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
	uint64_t subscribe_id, uint64_t track_alias, uint64_t object_send_order, uint8_t priority);
/*! \brief Helper to add an object to a buffer, formatted as expected
 * for \c STREAM_HEADER_TRACK objects (so not all IDs) (only before v06)
 * @param moq The imquic_moq_context generating the object
 * @param bytes The buffer to add the object to
 * @param blen The size of the buffer
 * @param group_id The group ID
 * @param object_id The object ID
 * @param object_status The object status (only added if the payload length is 0)
 * @param payload The buffer containing the payload of the object
 * @param plen The size of the payload buffer
 * @returns The size of the generated object, if successful, or 0 otherwise */
size_t imquic_moq_add_stream_header_track_object(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
	uint64_t group_id, uint64_t object_id, uint64_t object_status, uint8_t *payload, size_t plen);
/*! \brief Helper to add a \c STREAM_HEADER_GROUP message to a buffer (only before v06)
 * @note This will create a new \c STREAM and send the header: after
 * that, imquic_moq_add_stream_header_group_object is used to send
 * all objects that belong to this group.
 * @param moq The imquic_moq_context generating the message
 * @param bytes The buffer to add the message to
 * @param blen The size of the buffer
 * @param subscribe_id The subscription ID to put in the message
 * @param track_alias The track alias to put in the message
 * @param group_id The group ID to put in the message
 * @param object_send_order The object send order to put in the message (v03 and v04 only)
 * @param priority The publisher priority to put in the message (only after v05)
 * @returns The size of the generated message, if successful, or 0 otherwise */
size_t imquic_moq_add_stream_header_group(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint64_t subscribe_id,
	uint64_t track_alias, uint64_t group_id, uint64_t object_send_order, uint8_t priority);
/*! \brief Helper to add an object to a buffer, formatted as expected
 * for \c STREAM_HEADER_GROUP objects (so not all IDs) (only before v06)
 * @param moq The imquic_moq_context generating the object
 * @param bytes The buffer to add the object to
 * @param blen The size of the buffer
 * @param object_id The object ID
 * @param object_status The object status (only added if the payload length is 0)
 * @param payload The buffer containing the payload of the object
 * @param plen The size of the payload buffer
 * @returns The size of the generated object, if successful, or 0 otherwise */
size_t imquic_moq_add_stream_header_group_object(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
	uint64_t object_id, uint64_t object_status, uint8_t *payload, size_t plen);
/*! \brief Helper to add a \c SUBGROUP_HEADER message to a buffer (only after v06)
 * @note This will create a new \c STREAM and send the header: after
 * that, imquic_moq_add_stream_header_subgroup_object is used to send
 * all objects that belong to this subgroup.
 * @param moq The imquic_moq_context generating the message
 * @param bytes The buffer to add the message to
 * @param blen The size of the buffer
 * @param subscribe_id The subscription ID to put in the message
 * @param track_alias The track alias to put in the message
 * @param group_id The group ID to put in the message
 * @param subgroup_id The subgroup ID to put in the message
 * @param priority The publisher priority to put in the message
 * @returns The size of the generated message, if successful, or 0 otherwise */
size_t imquic_moq_add_subgroup_header(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint64_t subscribe_id,
	uint64_t track_alias, uint64_t group_id, uint64_t subgroup_id, uint8_t priority);
/*! \brief Helper to add an object to a buffer, formatted as expected
 * for \c SUBGROUP_HEADER objects (so not all IDs) (only after v06)
 * @param moq The imquic_moq_context generating the object
 * @param bytes The buffer to add the object to
 * @param blen The size of the buffer
 * @param object_id The object ID
 * @param object_status The object status (only added if the payload length is 0)
 * @param payload The buffer containing the payload of the object
 * @param plen The size of the payload buffer
 * @param extensions List of extensions to add (only after v08)
 * @returns The size of the generated object, if successful, or 0 otherwise */
size_t imquic_moq_add_subgroup_header_object(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
	uint64_t object_id, uint64_t object_status, uint8_t *payload, size_t plen, GList *extensions);
/*! \brief Helper to add a \c FETCH_HEADER message to a buffer (only after v07)
 * @note This will create a new \c STREAM and send the header: after
 * that, imquic_moq_add_fetch_header_object is used to send
 * all objects that belong to this track.
 * @param moq The imquic_moq_context generating the message
 * @param bytes The buffer to add the message to
 * @param blen The size of the buffer
 * @param subscribe_id The subscription ID to put in the message
 * @returns The size of the generated message, if successful, or 0 otherwise */
size_t imquic_moq_add_fetch_header(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint64_t subscribe_id);
/*! \brief Helper to add an object to a buffer, formatted as expected
 * for \c FETCH_HEADER objects (so not all IDs) (only before v06)
 * @param moq The imquic_moq_context generating the object
 * @param bytes The buffer to add the object to
 * @param blen The size of the buffer
 * @param group_id The group ID
 * @param subgroup_id The subgroup ID
 * @param object_id The object ID
 * @param priority The publisher priority to put in the message
 * @param object_status The object status (only added if the payload length is 0)
 * @param payload The buffer containing the payload of the object
 * @param plen The size of the payload buffer
 * @param extensions List of extensions to add (only after v08)
 * @returns The size of the generated object, if successful, or 0 otherwise */
size_t imquic_moq_add_fetch_header_object(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
	uint64_t group_id, uint64_t subgroup_id, uint64_t object_id, uint8_t priority,
	uint64_t object_status, uint8_t *payload, size_t plen, GList *extensions);
/*! \brief Helper method to add a \c GOAWAY message to a buffer
 * @param moq The imquic_moq_context generating the message
 * @param bytes The buffer to add the message to
 * @param blen The size of the buffer
 * @param new_session_uri Buffer containint the new uri value to put in the message, if any
 * @returns The size of the generated message, if successful, or 0 otherwise */
size_t imquic_moq_add_goaway(imquic_moq_context *moq, uint8_t *bytes, size_t blen, imquic_data *new_session_uri);
/*! \brief Helper method to add object extensions to a buffer
 * \note Object extensions were only added in v08, so this method does
 * nothing when used on a connection that negotiated an older version
 * @param moq The imquic_moq_context generating the message
 * @param bytes The buffer to add the message to
 * @param blen The size of the buffer
 * @param extensions List of extensions to add
 * @returns The size of the generated extensions block, if successful, or 0 otherwise */
size_t imquic_moq_add_object_extensions(imquic_moq_context *moq, uint8_t *bytes, size_t blen, GList *extensions);
///@}

/** @name Parsing and building MoQ parameters
 */
///@{
/*! \brief Helper method to parse a MoQ setup parameter
 * @note This method does nothing at the moment
 * @param[in] moq The imquic_moq_context instance to update with the new parameter
 * @param[in] bytes Buffer containing the parameter to parse
 * @param[in] blen Size of the buffer to parse
 * @param[out] param imquic_moq_parsed_setup_parameter instance to put the parsed parameter in
 * @param[out] error In/out property, initialized to 0 and set to 1 in case of parsing errors
 * @returns The size of the parameter, if successful, or 0 otherwise */
size_t imquic_moq_parse_setup_parameter(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
	imquic_moq_parsed_setup_parameter *param, uint8_t *error);
/*! \brief Helper method to parse a MoQ subscribe parameter
 * @note This method does nothing at the moment
 * @param[in] moq The imquic_moq_context instance to update with the new parameter
 * @param[in] bytes Buffer containing the parameter to parse
 * @param[in] blen Size of the buffer to parse
 * @param[out] param imquic_moq_parsed_subscribe_parameter instance to put the parsed parameter in
 * @param[out] error In/out property, initialized to 0 and set to 1 in case of parsing errors
 * @returns The size of the parameter, if successful, or 0 otherwise */
size_t imquic_moq_parse_subscribe_parameter(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
	imquic_moq_parsed_subscribe_parameter *param, uint8_t *error);
/*! \brief Helper to add a MoQ (setup or subscribe) parameter with a numeric value to a buffer
 * @param moq The imquic_moq_context instance the parameter is for
 * @param bytes Buffer to add the parameter to
 * @param blen Size of the buffer
 * @param param ID of the parameter to add
 * @param number The numeric value of the parameter to add
 * @returns The size of the parameter, if successful, or 0 otherwise */
size_t imquic_moq_parameter_add_int(imquic_moq_context *moq, uint8_t *bytes, size_t blen, int param, uint64_t number);
/*! \brief Helper to add a MoQ (setup or subscribe) parameter with generic data to a buffer
 * @param moq The imquic_moq_context instance the parameter is for
 * @param bytes Buffer to add the parameter to
 * @param blen Size of the buffer
 * @param param ID of the parameter to add
 * @param buf The data acting as a value for the parameter to add
 * @param buflen The size of the data value
 * @returns The size of the parameter, if successful, or 0 otherwise */
size_t imquic_moq_parameter_add_data(imquic_moq_context *moq, uint8_t *bytes, size_t blen, int param, uint8_t *buf, size_t buflen);
///@}

/*! \brief RoQ public callbacks */
typedef struct imquic_moq_callbacks {
	/*! \brief Callback function to be notified about new moQ connections */
	void (* new_connection)(imquic_connection *conn, void *user_data);
	/*! \brief Callback function to be notified when a MoQ connection is ready (setup performed on both ends) */
	void (* moq_ready)(imquic_connection *conn);
	/*! \brief Callback function to be notified about incoming \c ANNOUNCE messages */
	void (* incoming_announce)(imquic_connection *conn, imquic_moq_namespace *tns);
	/*! \brief Callback function to be notified about incoming \c ANNOUNCE_CANCEL messages */
	void (* incoming_announce_cancel)(imquic_connection *conn, imquic_moq_namespace *tns);
	/*! \brief Callback function to be notified about incoming \c ANNOUNCE_ACCEPTED messages */
	void (* announce_accepted)(imquic_connection *conn, imquic_moq_namespace *tns);
	/*! \brief Callback function to be notified about incoming \c ANNOUNCE_ERROR messages */
	void (* announce_error)(imquic_connection *conn, imquic_moq_namespace *tns, int error_code, const char *reason);
	/*! \brief Callback function to be notified about incoming \c UNANNOUNCE messages */
	void (* incoming_unannounce)(imquic_connection *conn, imquic_moq_namespace *tns);
	/*! \brief Callback function to be notified about incoming \c SUBSCRIBE messages */
	void (* incoming_subscribe)(imquic_connection *conn, uint64_t subscribe_id, uint64_t track_alias, imquic_moq_namespace *tns, imquic_moq_name *tn, imquic_moq_auth_info *auth);
	/*! \brief Callback function to be notified about incoming \c SUBSCRIBE_ACCEPTED messages */
	void (* subscribe_accepted)(imquic_connection *conn, uint64_t subscribe_id, uint64_t expires, gboolean descending);
	/*! \brief Callback function to be notified about incoming \c SUBSCRIBE_ERROR messages */
	void (* subscribe_error)(imquic_connection *conn, uint64_t subscribe_id, int error_code, const char *reason, uint64_t track_alias);
	/*! \brief Callback function to be notified about incoming \c SUBSCRIBE_DONE messages */
	void (* subscribe_done)(imquic_connection *conn, uint64_t subscribe_id, int status_code, uint64_t streams_count, const char *reason);
	/*! \brief Callback function to be notified about incoming \c UNBSUBSCRIBE messages */
	void (* incoming_unsubscribe)(imquic_connection *conn, uint64_t subscribe_id);
	/*! \brief Callback function to be notified about incoming \c SUBSCRIBES_BLOCKED messages */
	void (* subscribes_blocked)(imquic_connection *conn, uint64_t max_subscribe_id);
	/*! \brief Callback function to be notified about incoming \c SUBSCRIBE_ANNOUNCES messages */
	void (* incoming_subscribe_announces)(imquic_connection *conn, imquic_moq_namespace *tns, imquic_moq_auth_info *auth);
	/*! \brief Callback function to be notified about incoming \c SUBSCRIBE_ANNOUNCES_ACCEPTED messages */
	void (* subscribe_announces_accepted)(imquic_connection *conn, imquic_moq_namespace *tns);
	/*! \brief Callback function to be notified about incoming \c SUBSCRIBE_ANNOUNCES_ERROR messages */
	void (* subscribe_announces_error)(imquic_connection *conn, imquic_moq_namespace *tns, int error_code, const char *reason);
	/*! \brief Callback function to be notified about incoming \c UNSUBSCRIBE_ANNOUNCES messages */
	void (* incoming_unsubscribe_announces)(imquic_connection *conn, imquic_moq_namespace *tns);
	/*! \brief Callback function to be notified about incoming \c FETCH messages */
	void (* incoming_standalone_fetch)(imquic_connection *conn, uint64_t subscribe_id,
		imquic_moq_namespace *tns, imquic_moq_name *tn, gboolean descending, imquic_moq_fetch_range *range, imquic_moq_auth_info *auth);
	void (* incoming_joining_fetch)(imquic_connection *conn, uint64_t subscribe_id, uint64_t joining_subscribe_id,
		uint64_t preceding_group_offset, gboolean descending, imquic_moq_auth_info *auth);
	/*! \brief Callback function to be notified about incoming \c FETCH_CANCEL messages */
	void (* incoming_fetch_cancel)(imquic_connection *conn, uint64_t subscribe_id);
	/*! \brief Callback function to be notified about incoming \c FETCH_ACCEPTED messages */
	void (* fetch_accepted)(imquic_connection *conn, uint64_t subscribe_id, gboolean descending, imquic_moq_position *largest);
	/*! \brief Callback function to be notified about incoming \c FETCH_ERROR messages */
	void (* fetch_error)(imquic_connection *conn, uint64_t subscribe_id, int error_code, const char *reason);
	/*! \brief Callback function to be notified about incoming MoQ objects */
	void (* incoming_object)(imquic_connection *conn, imquic_moq_object *object);
	/*! \brief Callback function to be notified about incoming \c GOAWAY messages */
	void (* incoming_goaway)(imquic_connection *conn, const char *uri);
	/*! \brief Callback function to be notified about RoQ connections being closed */
	void (* connection_gone)(imquic_connection *conn);
} imquic_moq_callbacks;

/** @name Internal callbacks for MoQ endpoints
 */
///@{
/*! \brief Callback the core invokes when a new QUIC connection using MoQ is available
 * @param conn The imquic_connection instance that is now available
 * @param user_data Optional user data the user/application may have
 * associated to the endpoint this connection belongs to */
void imquic_moq_new_connection(imquic_connection *conn, void *user_data);
/*! \brief Callback the core invokes when there's new incoming data on a \c STREAM
 * @param conn The imquic_connection instance for which new \c STREAM data is available
 * @param stream_id The QUIC Stream ID for which new data is available
 * @param bytes The new data that is available
 * @param offset The offset in the stream this new data should be put in
 * @param length Size of the new data
 * @param complete Whether this data marks the end of this \c STREAM */
void imquic_moq_stream_incoming(imquic_connection *conn, uint64_t stream_id,
	uint8_t *bytes, uint64_t offset, uint64_t length, gboolean complete);
/*! \brief Callback the core invokes when there's new incoming data on a \c DATAGRAM
 * @param conn The imquic_connection instance for which new \c DATAGRAM data is available
 * @param bytes The new data that is available
 * @param length Size of the new data */
void imquic_moq_datagram_incoming(imquic_connection *conn, uint8_t *bytes, uint64_t length);
/*! \brief Callback the core invokes when an existing MoQ connection is not available anymore
 * @param conn The imquic_connection instance that is now gone */
void imquic_moq_connection_gone(imquic_connection *conn);
///@}

#endif
