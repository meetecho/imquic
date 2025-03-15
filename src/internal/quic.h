/*! \file   quic.h
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright MIT License
 * \brief  QUIC stack implementation (headers)
 * \details Implementation of the QUIC stack itself. This is where message
 * parsing and building is implemented, including connection establishment
 * and (mostly) state management.
 *
 * \ingroup Core
 *  */

#ifndef IMQUIC_QUIC_H
#define IMQUIC_QUIC_H

#include <sys/socket.h>

#include <glib.h>

#include "../imquic/imquic.h"
#include "connection.h"
#include "stream.h"
#include "utils.h"

/*! \brief Initialize the QUIC stack at startup */
void imquic_quic_init(void);
/*! \brief Uninitialize the QUIC stack */
void imquic_quic_deinit(void);

/*! \brief Track a Connection ID and map it to a connection
 * @note This will add a reference to the connections
 * @param conn The imquic_connection instance the ID is associated with
 * @param cid The imquic_connection_id Connection ID instance */
void imquic_quic_connection_add(imquic_connection *conn, imquic_connection_id *cid);
/*! \brief Stop tracking a Connection ID associated to a connection
 * @note This will unref the connection, if a mapping exists
 * @param cid The imquic_connection_id Connection ID instance */
void imquic_quic_connection_remove(imquic_connection_id *cid);

/*! \brief QUIC long packet types
 * \note We don't support 0-RTT and Retry tey, at the moment */
typedef enum imquic_long_packet_type {
	IMQUIC_INITIAL = 0x00,
	IMQUIC_0RTT = 0x01,
	IMQUIC_HANDSHAKE = 0x02,
	IMQUIC_RETRY = 0x03
} imquic_long_packet_type;
/*! \brief Helper function to serialize to string the name of a imquic_long_packet_type value.
 * @param type The imquic_long_packet_type value
 * @returns The type name as a string, if valid, or NULL otherwise */
const char *imquic_long_packet_type_str(imquic_long_packet_type type);

/*! \brief QUIC frame types */
typedef enum imquic_frame_type {
	IMQUIC_PADDING = 0x00,
	IMQUIC_PING = 0x01,
	IMQUIC_ACK = 0x02,	/* Also 0x03 */
		IMQUIC_ACK_WITH_ECN = 0x03,
	IMQUIC_RESET_STREAM = 0x04,
	IMQUIC_STOP_SENDING = 0x05,
	IMQUIC_CRYPTO = 0x06,
	IMQUIC_NEW_TOKEN = 0x07,
	IMQUIC_STREAM = 0x08,	/* Also 0x09-0x0F */
		IMQUIC_STREAM_F = 0x09,
		IMQUIC_STREAM_L = 0x0A,
		IMQUIC_STREAM_LF = 0x0B,
		IMQUIC_STREAM_O = 0x0C,
		IMQUIC_STREAM_OF = 0x0D,
		IMQUIC_STREAM_OL = 0x0E,
		IMQUIC_STREAM_OLF = 0x0F,
	IMQUIC_MAX_DATA = 0x10,
	IMQUIC_MAX_STREAM_DATA = 0x11,
	IMQUIC_MAX_STREAMS = 0x12,	/* Also 0x13 */
		IMQUIC_MAX_STREAMS_UNI = 0x13,
	IMQUIC_DATA_BLOCKED = 0x14,
	IMQUIC_STREAM_DATA_BLOCKED = 0x15,
	IMQUIC_STREAMS_BLOCKED = 0x16,	/* Also 0x17 */
		IMQUIC_STREAMS_BLOCKED_UNI = 0x17,
	IMQUIC_NEW_CONNECTION_ID = 0x18,
	IMQUIC_RETIRE_CONNECTION_ID = 0x19,
	IMQUIC_PATH_CHALLENGE = 0x1A,
	IMQUIC_PATH_RESPONSE = 0x1B,
	IMQUIC_CONNECTION_CLOSE = 0x1C,	/* Also 0x1D */
		IMQUIC_CONNECTION_CLOSE_APP = 0x1D,
	IMQUIC_HANDSHAKE_DONE = 0x1E,
	IMQUIC_DATAGRAM = 0x30,	/* Also 0x31 */
		IMQUIC_DATAGRAM_L = 0x31
} imquic_frame_type;
/*! \brief Helper function to serialize to string the name of a imquic_frame_type value.
 * @param type The imquic_frame_type value
 * @returns The type name as a string, if valid, or NULL otherwise */
const char *imquic_frame_type_str(imquic_frame_type type);

/*! \brief A serialized QUIC frame
 * \note This is only used as part of \ref imquic_packet instances to
 * reconstruct messages with important frames we need to retransmit */
typedef struct imquic_frame {
	/*! \brief Frame type */
	imquic_frame_type type;
	/*! \brief Content of the frame */
	uint8_t *buffer;
	/*! \brief Size of the frame */
	size_t size;
#ifdef HAVE_QLOG
	/*! \brief QLOG serialization of this frame */
	json_t *qlog_frame;
#endif
} imquic_frame;
/*! \brief Helper method to create a imquic_frame instance
 * @param type The type of frame
 * @param buffer The content of the frame
 * @param size The size of the frame
 * @returns A pointer to a imquic_frame instance, if successful, or NULL otherwise */
imquic_frame *imquic_frame_create(imquic_frame_type type, uint8_t *buffer, size_t size);
/*! \brief Helper method to destroy an existing imquic_frame instance
 * @param frame The imquic_frame instanceto destroy */
void imquic_frame_destroy(imquic_frame *frame);

/*! \brief QUIC transport parameters */
typedef enum imquic_transport_parameter {
	IMQUIC_ORIGINAL_DESTINATION_CONNECTION_ID = 0x00,
	IMQUIC_MAX_IDLE_TIMEOUT = 0x01,
	IMQUIC_STATELESS_RESET_TOKEN = 0x02,
	IMQUIC_MAX_UDP_PAYLOAD_SIZE = 0x03,
	IMQUIC_INITIAL_MAX_DATA = 0x04,
	IMQUIC_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL = 0x05,
	IMQUIC_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE = 0x06,
	IMQUIC_INITIAL_MAX_STREAM_DATA_UNI = 0x07,
	IMQUIC_INITIAL_MAX_STREAMS_BIDI = 0x08,
	IMQUIC_INITIAL_MAX_STREAMS_UNI = 0x09,
	IMQUIC_ACK_DELAY_EXPONENT = 0x0A,
	IMQUIC_MAX_ACK_DELAY = 0x0B,
	IMQUIC_DISABLE_ACTIVE_MIGRATION = 0x0C,
	IMQUIC_PREFERRED_ADDRESS = 0x0D,
	IMQUIC_ACTIVE_CONNECTION_ID_LIMIT = 0x0E,
	IMQUIC_INITIAL_SOURCE_CONNECTION_ID = 0x0F,
	IMQUIC_RETRY_SOURCE_CONNECTION_ID = 0x10,
	IMQUIC_MAX_DATAGRAM_FRAME_SIZE = 0x20
} imquic_transport_parameter;
/*! \brief Helper function to serialize to string the name of a imquic_transport_parameter value.
 * @param param The imquic_transport_parameter value
 * @returns The param name as a string, if valid, or NULL otherwise */
const char *imquic_transport_parameter_str(imquic_transport_parameter param);

/*! \brief Abstraction of a QUIC packet */
typedef struct imquic_packet {
	/*! \brief Whether the packet is valid, (still) protected, and (still) encrypted */
	gboolean is_valid, is_protected, is_encrypted;
	/*! \brief The encryption level of this packet */
	enum ssl_encryption_level_t level;
	/*! \brief Whether this packet uses a long or short header */
	gboolean longheader;
	/*! \brief Whether ths spin bit and/or the key phase bit are set in this packet (only in case longheader is FALSE) */
	gboolean spin_bit, key_phase;
	/*! \brief Type of long header packet (only in case longheader is TRUE) */
	imquic_long_packet_type type;
	/*! \brief QUIC version in the packet (only in case longheader is TRUE) */
	uint32_t version;
	/*! \brief Destination Connection ID */
	imquic_connection_id destination;
	/*! \brief Source Connection ID (only in case longheader is TRUE) */
	imquic_connection_id source;
	/*! \brief QUIC packet number */
	uint64_t packet_number;
	/*! \brief Offsets in the packet data to where the lenght, packet number and payload are */
	size_t length_offset, pkn_offset, payload_offset;
	/*! \brief List of serialized frames in this packet
	 * \note Only used for outgoing packets */
	GList *frames;
	/*! \brief Cumulative size of all the frames */
	size_t frames_size;
#ifdef HAVE_QLOG
	/*! \brief Frames serialized for QLOG purposes, if needed */
	json_t *qlog_frames;
	/*! \brief Last frame serialized for QLOG purposes, if needed */
	json_t *qlog_frame;
#endif
	/*! \brief Whether this packet contains ACK-eliciting frames */
	gboolean ack_eliciting;
	/*! \brief Whether this packet should be retransmitted if lost */
	gboolean retransmit_if_lost;
	/*! \brief Buffers */
	imquic_data_fixed payload, data;
} imquic_packet;
/*! \brief Helper method to create a imquic_packet instance
 * @returns A pointer to a imquic_packet instance, if successful, or NULL otherwise */
imquic_packet *imquic_packet_create(void);
/*! \brief Initialize a imquic_packet instance as a long header packet
 * @param pkt The imquic_packet instance to initialize
 * @param type The imquic_long_packet_type type of long header packet (e.g., Initial)
 * @param src The Source Connection ID to put in the packet, if any
 * @param dest The Destination Connection ID to put in the packet, if any
 * @returns 0 in case of success, or a negative integer otherwise */
int imquic_packet_long_init(imquic_packet *pkt, imquic_long_packet_type type, imquic_connection_id *src, imquic_connection_id *dest);
/*! \brief Initialize a imquic_packet instance as a short header packet
 * @param pkt The imquic_packet instance to initialize
 * @param dest The Destination Connection ID to put in the packet, if any
 * @returns 0 in case of success, or a negative integer otherwise */
int imquic_packet_short_init(imquic_packet *pkt, imquic_connection_id *dest);
/*! \brief Helper method to destroy an existing imquic_packet instance
 * @param pkt The imquic_packet instance to destroy */
void imquic_packet_destroy(imquic_packet *pkt);

/*! \brief Info on a sent packet
 * @note This is only used to retrieve info on a sent packet when parsing an ACK
*/
typedef struct imquic_sent_packet {
	/*! \brief Connection this packet was sent on */
	imquic_connection *conn;
	/*! \brief imquic_packet instance, in case we need it for retransmissions */
	imquic_packet *packet;
	/*! \brief The encryption level of this packet */
	enum ssl_encryption_level_t level;
	/*! \brief Packet number */
	uint64_t packet_number;
	/*! \brief Packet size in bytes */
	size_t packet_size;
	/*! \brief Monotonic time of when this packet was sent */
	int64_t sent_time;
	/*! \brief Whether this packet contained ACK-eliciting frames */
	gboolean ack_eliciting;
	/* TODO We should add info on whether this packet contained an ACK,
	 * so that we can decide when to move on with our own ACK ranges */
} imquic_sent_packet;
/*! \brief Helper method to destroy an existing imquic_sent_packet instance
 * @param sent_pkt The imquic_sent_packet instance to destroy */
void imquic_sent_packet_destroy(imquic_sent_packet *sent_pkt);

/** @name Parsing and processing QUIC messages
 */
///@{
/*! \brief Process incoming data from the network we've made aware of
 * @note A client or server endpoint will receive data regularly: it's
 * this function's responsability to traverse the buffers that are received,
 * to parse one or more messages that may be in a UDP message using
 * potentially multiple calls to imquic_parse_packet.
 * @param[in] socket The endpoint that received the data
 * @param[in] sender The network address of who sent this data
 * @param[in] quic The buffer containing the data
 * @param[in] bytes Size of the buffer containing the data */
void imquic_process_message(imquic_network_endpoint *socket, imquic_network_address *sender, uint8_t *quic, size_t bytes);
/*! \brief Parse a QUIC packet from an incoming buffer and handle it
 * @note Considering a UDP message may contain more than one QUIC message, this function returns
 * the size of the QUIC message it finds at the beginning of the buffer, so that, in case there's
 * still more data to process, the caller can call the function again after shifting the pointer.
 * @param[in] socket The endpoint that received the QUIC packet
 * @param[in] sender The network address of who sent this packet
 * @param[out] pconn After parsing the packet, this will be filled with the imquic_connection associated with it
 * @param[out] pkt The imquic_packet instance to write the result of the parsing to
 * @param[in] quic The buffer containing the QUIC packet
 * @param[in] bytes Size of the buffer containing the QUIC packet
 * @param[in] tot Size of the whole datagram containing buffer
 * @returns The size of the parsed packet, if successfuk, or a negative integer otherwise */
int imquic_parse_packet(imquic_network_endpoint *socket, imquic_network_address *sender,
	imquic_connection **pconn, imquic_packet *pkt, uint8_t *quic, size_t bytes, size_t tot);
/*! \brief Helper method to check if we received \c CRYPTO frames we need
 * to go through, and in case pass them to the TLS stack for processing
 * @param conn The imquic_connection to check */
void imquic_check_incoming_crypto(imquic_connection *conn);
/*! \brief Helper method to check if we received \c STREAM frames we need
 * to go process, and handle ourselves or pass to the application layer
 * @param conn The imquic_connection to check */
void imquic_check_incoming_stream(imquic_connection *conn);
///@}

/** @name Parsing QUIC frames
 */
///@{
/*! \brief Parse QUIC frames in a QUIC message payload
 * @note The state of the connection will be updated as the message is
 * parsed, as some frames will trigger a change of state, while others
 * will fill some buffers that we may need to process later.
 * @param conn The imquic_connection that received the message
 * @param pkt The imquic_packet containing the payload to process
 * returns 0 in case of success, a negative integer otherwise */
int imquic_parse_frames(imquic_connection *conn, imquic_packet *pkt);
/*! \brief Helper method to process an \c ACK frame
 * @param conn The imquic_connection that received the message
 * @param pkt The imquic_packet containing the payload to process
 * @param bytes Buffer containing the frame
 * @param blen Size of the buffer containing the frame
 * @param level Encryption level of the packet containing this frame
 * @returns The size of the frame, if successful, or 0 otherwise */
size_t imquic_payload_parse_ack(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen, enum ssl_encryption_level_t level);
/*! \brief Helper method to process a \c RESET_STREAM frame
 * @param conn The imquic_connection that received the message
 * @param pkt The imquic_packet containing the payload to process
 * @param bytes Buffer containing the frame
 * @param blen Size of the buffer containing the frame
 * @returns The size of the frame, if successful, or 0 otherwise */
size_t imquic_payload_parse_reset_stream(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen);
/*! \brief Helper method to process a \c STOP_SENDING frame
 * @param conn The imquic_connection that received the message
 * @param pkt The imquic_packet containing the payload to process
 * @param bytes Buffer containing the frame
 * @param blen Size of the buffer containing the frame
 * @returns The size of the frame, if successful, or 0 otherwise */
size_t imquic_payload_parse_stop_sending(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen);
/*! \brief Helper method to process a \c CRYPTO frame, and in case add
 * all chunks to the buffer associated with the related encryption level,
 * so that it can be processed later.
 * @param conn The imquic_connection that received the message
 * @param pkt The imquic_packet containing the payload to process
 * @param bytes Buffer containing the frame
 * @param blen Size of the buffer containing the frame
 * @param level Encryption level of the packet containing this frame
 * @returns The size of the frame, if successful, or 0 otherwise */
size_t imquic_payload_parse_crypto(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen, enum ssl_encryption_level_t level);
/*! \brief Helper method to process a \c NEW_TOKEN frame
 * @param conn The imquic_connection that received the message
 * @param pkt The imquic_packet containing the payload to process
 * @param bytes Buffer containing the frame
 * @param blen Size of the buffer containing the frame
 * @returns The size of the frame, if successful, or 0 otherwise */
size_t imquic_payload_parse_new_token(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen);
/*! \brief Helper method to process a \c STREAM frame, and handle it
 * accordingly, e.g., by creating the stream locally (if previously unknown),
 * update the associated buffer with the new data, update the state of
 * the stream, and notify the stack using internal callbacks
 * @param conn The imquic_connection that received the message
 * @param pkt The imquic_packet containing the payload to process
 * @param bytes Buffer containing the frame
 * @param blen Size of the buffer containing the frame
 * @returns The size of the frame, if successful, or 0 otherwise */
size_t imquic_payload_parse_stream(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen);
/*! \brief Helper method to process a \c MAX_DATA frame
 * @param conn The imquic_connection that received the message
 * @param pkt The imquic_packet containing the payload to process
 * @param bytes Buffer containing the frame
 * @param blen Size of the buffer containing the frame
 * @returns The size of the frame, if successful, or 0 otherwise */
size_t imquic_payload_parse_max_data(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen);
/*! \brief Helper method to process a \c MAX_STREAM_DATA frame
 * @param conn The imquic_connection that received the message
 * @param pkt The imquic_packet containing the payload to process
 * @param bytes Buffer containing the frame
 * @param blen Size of the buffer containing the frame
 * @returns The size of the frame, if successful, or 0 otherwise */
size_t imquic_payload_parse_max_stream_data(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen);
/*! \brief Helper method to process a \c MAX_STREAMS frame
 * @param conn The imquic_connection that received the message
 * @param pkt The imquic_packet containing the payload to process
 * @param bytes Buffer containing the frame
 * @param blen Size of the buffer containing the frame
 * @returns The size of the frame, if successful, or 0 otherwise */
size_t imquic_payload_parse_max_streams(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen);
/*! \brief Helper method to process a \c DATA_BLOCKED frame
 * @param conn The imquic_connection that received the message
 * @param pkt The imquic_packet containing the payload to process
 * @param bytes Buffer containing the frame
 * @param blen Size of the buffer containing the frame
 * @returns The size of the frame, if successful, or 0 otherwise */
size_t imquic_payload_parse_data_blocked(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen);
/*! \brief Helper method to process a \c STREAM_DATA_BLOCKED frame
 * @param conn The imquic_connection that received the message
 * @param pkt The imquic_packet containing the payload to process
 * @param bytes Buffer containing the frame
 * @param blen Size of the buffer containing the frame
 * @returns The size of the frame, if successful, or 0 otherwise */
size_t imquic_payload_parse_stream_data_blocked(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen);
/*! \brief Helper method to process a \c STREAMS_BLOCKED frame
 * @param conn The imquic_connection that received the message
 * @param pkt The imquic_packet containing the payload to process
 * @param bytes Buffer containing the frame
 * @param blen Size of the buffer containing the frame
 * @returns The size of the frame, if successful, or 0 otherwise */
size_t imquic_payload_parse_streams_blocked(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen);
/*! \brief Helper method to process a \c NEW_CONNECTION_ID frame
 * @param conn The imquic_connection that received the message
 * @param pkt The imquic_packet containing the payload to process
 * @param bytes Buffer containing the frame
 * @param blen Size of the buffer containing the frame
 * @returns The size of the frame, if successful, or 0 otherwise */
size_t imquic_payload_parse_new_connection_id(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen);
/*! \brief Helper method to process a \c RETIRE_CONNECTION_ID frame
 * @param conn The imquic_connection that received the message
 * @param pkt The imquic_packet containing the payload to process
 * @param bytes Buffer containing the frame
 * @param blen Size of the buffer containing the frame
 * @returns The size of the frame, if successful, or 0 otherwise */
size_t imquic_payload_parse_retire_connection_id(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen);
/*! \brief Helper method to process a \c PATH_CHALLENGE frame
 * @param conn The imquic_connection that received the message
 * @param pkt The imquic_packet containing the payload to process
 * @param bytes Buffer containing the frame
 * @param blen Size of the buffer containing the frame
 * @returns The size of the frame, if successful, or 0 otherwise */
size_t imquic_payload_parse_path_challenge(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen);
/*! \brief Helper method to process a \c PATH_RESPONSE frame
 * @param conn The imquic_connection that received the message
 * @param pkt The imquic_packet containing the payload to process
 * @param bytes Buffer containing the frame
 * @param blen Size of the buffer containing the frame
 * @returns The size of the frame, if successful, or 0 otherwise */
size_t imquic_payload_parse_path_response(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen);
/*! \brief Helper method to process a \c CONNECTION_CLOSE frame, and
 * handle it accordingly by closing the connection locally too
 * @param conn The imquic_connection that received the message
 * @param pkt The imquic_packet containing the payload to process
 * @param bytes Buffer containing the frame
 * @param blen Size of the buffer containing the frame
 * @returns The size of the frame, if successful, or 0 otherwise */
size_t imquic_payload_parse_connection_close(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen);
/*! \brief Helper method to process a \c DATAGRAM frame, and notify the
 * stack about it via internal callbacks
 * @param conn The imquic_connection that received the message
 * @param pkt The imquic_packet containing the payload to process
 * @param bytes Buffer containing the frame
 * @param blen Size of the buffer containing the frame
 * @returns The size of the frame, if successful, or 0 otherwise */
size_t imquic_payload_parse_datagram(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen);
///@}

/** @name Adding QUIC frames to a packet
 */
///@{
/*! \brief Helper method to add a \c PADDING frame to a buffer
 * @param conn The imquic_connection that will send the message
 * @param pkt The imquic_packet containing the payload to expand
 * @param bytes Buffer to add the frame to
 * @param blen Size of the buffer
 * @param padding How many bytes of padding to add
 * @returns The size of the frame, if successful, or 0 otherwise */
size_t imquic_payload_add_padding(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen, size_t padding);
/*! \brief Helper method to add a \c PING frame to a buffer
 * @param conn The imquic_connection that will send the message
 * @param pkt The imquic_packet containing the payload to expand
 * @param bytes Buffer to add the frame to
 * @param blen Size of the buffer
 * @returns The size of the frame, if successful, or 0 otherwise */
size_t imquic_payload_add_ping(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen);
/*! \brief Helper method to add a \c ACK frame to a buffer
 * @param conn The imquic_connection that will send the message
 * @param pkt The imquic_packet containing the payload to expand
 * @param bytes Buffer to add the frame to
 * @param blen Size of the buffer
 * @param received The list of packets we did receive
 * @param delay The value to put in the delay part of the frame
 * @param ecn_counts Array of three ECN-related properties to put in the frame, if any
 * @returns The size of the frame, if successful, or 0 otherwise */
size_t imquic_payload_add_ack(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen, GList *received, uint64_t delay, uint64_t *ecn_counts);
/*! \brief Helper method to add a \c RESET_STREAM frame to a buffer
 * @param conn The imquic_connection that will send the message
 * @param pkt The imquic_packet containing the payload to expand
 * @param bytes Buffer to add the frame to
 * @param blen Size of the buffer
 * @param stream_id ID of the stream to reset
 * @param error_code Error code to report in the frame
 * @param final_size Final size to report in the frame
 * @returns The size of the frame, if successful, or 0 otherwise */
size_t imquic_payload_add_reset_stream(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen, uint64_t stream_id, uint64_t error_code, uint64_t final_size);
/*! \brief Helper method to add a \c STOP_SENDING frame to a buffer
 * @param conn The imquic_connection that will send the message
 * @param pkt The imquic_packet containing the payload to expand
 * @param bytes Buffer to add the frame to
 * @param blen Size of the buffer
 * @param stream_id ID of the stream whose sending must stop
 * @param error_code Error code to report in the frame
 * @returns The size of the frame, if successful, or 0 otherwise */
size_t imquic_payload_add_stop_sending(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen, uint64_t stream_id, uint64_t error_code);
/*! \brief Helper method to add a \c CRYPTO frame to a buffer
 * @param conn The imquic_connection that will send the message
 * @param pkt The imquic_packet containing the payload to expand
 * @param bytes Buffer to add the frame to
 * @param blen Size of the buffer
 * @param crypto Buffer containing the TLS data to send
 * @param crypto_offset Offset this TLS data is at, relatively to the whole \c CRYPTO exchange
 * @param crypto_length Size of the TLS data buffer
 * @returns The size of the frame, if successful, or 0 otherwise */
size_t imquic_payload_add_crypto(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen, uint8_t *crypto, size_t crypto_offset, size_t crypto_length);
/*! \brief Helper method to add a \c NEW_TOKEN frame to a buffer
 * @param conn The imquic_connection that will send the message
 * @param pkt The imquic_packet containing the payload to expand
 * @param bytes Buffer to add the frame to
 * @param blen Size of the buffer
 * @param token Buffer containing the token to add
 * @param token_length Size of the token buffer
 * @returns The size of the frame, if successful, or 0 otherwise */
size_t imquic_payload_add_new_token(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen, uint8_t *token, size_t token_length);
/*! \brief Helper method to add a \c STREAM frame to a buffer
 * @param conn The imquic_connection that will send the message
 * @param pkt The imquic_packet containing the payload to expand
 * @param bytes Buffer to add the frame to
 * @param blen Size of the buffer
 * @param stream_id ID of the stream this data belongs to
 * @param stream Buffer containing the stream data to send
 * @param stream_offset Offset this stream data is at, relatively to the whole \c STREAM exchange
 * @param stream_length Size of the stream data buffer
 * @param complete Whether this data marks the end of the \c STREAM in this direction
 * @param last Whether this is the last frame in the packet, and so we can omit the Length field
 * @returns The size of the frame, if successful, or 0 otherwise */
size_t imquic_payload_add_stream(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen, uint64_t stream_id, uint8_t *stream, size_t stream_offset, size_t stream_length, gboolean complete, gboolean last);
/*! \brief Helper method to add a \c MAX_DATA frame to a buffer
 * @param conn The imquic_connection that will send the message
 * @param pkt The imquic_packet containing the payload to expand
 * @param bytes Buffer to add the frame to
 * @param blen Size of the buffer
 * @param max_data The new value to report
 * @returns The size of the frame, if successful, or 0 otherwise */
size_t imquic_payload_add_max_data(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen, uint64_t max_data);
/*! \brief Helper method to add a \c MAX_STREAM_DATA frame to a buffer
 * @param conn The imquic_connection that will send the message
 * @param pkt The imquic_packet containing the payload to expand
 * @param bytes Buffer to add the frame to
 * @param blen Size of the buffer
 * @param stream_id ID of the stream this new limit applies to
 * @param max_data The new value to report
 * @returns The size of the frame, if successful, or 0 otherwise */
size_t imquic_payload_add_max_stream_data(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen, uint64_t stream_id, uint64_t max_data);
/*! \brief Helper method to add a \c MAX_STREAMS frame to a buffer
 * @param conn The imquic_connection that will send the message
 * @param pkt The imquic_packet containing the payload to expand
 * @param bytes Buffer to add the frame to
 * @param blen Size of the buffer
 * @param bidirectional Whether this impacts bidirectional or unidirectional streams
 * @param max_streams The new value to report
 * @returns The size of the frame, if successful, or 0 otherwise */
size_t imquic_payload_add_max_streams(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen, gboolean bidirectional, uint64_t max_streams);
/*! \brief Helper method to add a \c DATA_BLOCKED frame to a buffer
 * @param conn The imquic_connection that will send the message
 * @param pkt The imquic_packet containing the payload to expand
 * @param bytes Buffer to add the frame to
 * @param blen Size of the buffer
 * @param max_data The limit at which the blocking occurred
 * @returns The size of the frame, if successful, or 0 otherwise */
size_t imquic_payload_add_data_blocked(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen, uint64_t max_data);
/*! \brief Helper method to add a \c STREAM_DATA_BLOCKED frame to a buffer
 * @param conn The imquic_connection that will send the message
 * @param pkt The imquic_packet containing the payload to expand
 * @param bytes Buffer to add the frame to
 * @param blen Size of the buffer
 * @param stream_id ID of the stream that has been blocked
 * @param max_data The limit at which the blocking occurred
 * @returns The size of the frame, if successful, or 0 otherwise */
size_t imquic_payload_add_stream_data_blocked(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen, uint64_t stream_id, uint64_t max_data);
/*! \brief Helper method to add a \c STREAMS_BLOCKED frame to a buffer
 * @param conn The imquic_connection that will send the message
 * @param pkt The imquic_packet containing the payload to expand
 * @param bytes Buffer to add the frame to
 * @param blen Size of the buffer
 * @param bidirectional Whether this impacts bidirectional or unidirectional streams
 * @param max_streams The limit at which the blocking occurred
 * @returns The size of the frame, if successful, or 0 otherwise */
size_t imquic_payload_add_streams_blocked(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen, gboolean bidirectional, uint64_t max_streams);
/*! \brief Helper method to add a \c NEW_CONNECTION_ID frame to a buffer
 * @param conn The imquic_connection that will send the message
 * @param pkt The imquic_packet containing the payload to expand
 * @param bytes Buffer to add the frame to
 * @param blen Size of the buffer
 * @param seqnum Sequence number of the Connection ID
 * @param retire_prior_to Connection IDs that should be retired
 * @param cid The Connection ID value
 * @param reset_token Stateless reset token
 * @returns The size of the frame, if successful, or 0 otherwise */
size_t imquic_payload_add_new_connection_id(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen, uint64_t seqnum, uint64_t retire_prior_to, imquic_connection_id *cid, uint8_t *reset_token);
/*! \brief Helper method to add a \c RETIRE_CONNECTION_ID frame to a buffer
 * @param conn The imquic_connection that will send the message
 * @param pkt The imquic_packet containing the payload to expand
 * @param bytes Buffer to add the frame to
 * @param blen Size of the buffer
 * @param seqnum Sequence number of the Connection ID to retire
 * @returns The size of the frame, if successful, or 0 otherwise */
size_t imquic_payload_add_retire_connection_id(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen, uint64_t seqnum);
/*! \brief Helper method to add a \c PATH_CHALLENGE frame to a buffer
 * @param conn The imquic_connection that will send the message
 * @param pkt The imquic_packet containing the payload to expand
 * @param bytes Buffer to add the frame to
 * @param blen Size of the buffer
 * @param data Data to send as part of the challenge
 * @returns The size of the frame, if successful, or 0 otherwise */
size_t imquic_payload_add_path_challenge(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen, uint8_t *data);
/*! \brief Helper method to add a \c PATH_RESPONSE frame to a buffer
 * @param conn The imquic_connection that will send the message
 * @param pkt The imquic_packet containing the payload to expand
 * @param bytes Buffer to add the frame to
 * @param blen Size of the buffer
 * @param data Data to send as part of the response
 * @returns The size of the frame, if successful, or 0 otherwise */
size_t imquic_payload_add_path_response(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen, uint8_t *data);
/*! \brief Helper method to add a \c CONNECTION_CLOSE frame to a buffer
 * @param conn The imquic_connection that will send the message
 * @param pkt The imquic_packet containing the payload to expand
 * @param bytes Buffer to add the frame to
 * @param blen Size of the buffer
 * @param error_code Error code to report in the frame
 * @param frame_type The frame type that caused the connection to be closed
 * @param reason A verbose description of the error, if any
 * @returns The size of the frame, if successful, or 0 otherwise */
size_t imquic_payload_add_connection_close(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen, imquic_error_code error_code, imquic_frame_type frame_type, const char *reason);
/*! \brief Helper method to add a \c HANDSHAKE_DONE frame to a buffer
 * @param conn The imquic_connection that will send the message
 * @param pkt The imquic_packet containing the payload to expand
 * @param bytes Buffer to add the frame to
 * @param blen Size of the buffer
 * @returns The size of the frame, if successful, or 0 otherwise */
size_t imquic_payload_add_handshake_done(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen);
/*! \brief Helper method to add a \c DATAGRAM frame to a buffer
 * @param conn The imquic_connection that will send the message
 * @param pkt The imquic_packet containing the payload to expand
 * @param bytes Buffer to add the frame to
 * @param blen Size of the buffer
 * @param datagram Buffer containing the datagram data to send
 * @param datagram_length Size of the datagram data buffer
 * @param last Whether this is the last frame in the packet, and so we can omit the Length field
 * @returns The size of the frame, if successful, or 0 otherwise */
size_t imquic_payload_add_datagram(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen, uint8_t *datagram, size_t datagram_length, gboolean last);
///@}

/** @name Adding QUIC transport parameters to a buffer
 */
///@{
/*! \brief Helper to add a QUIC transport parameter with no value to a buffer
 * @param bytes Buffer to add the transport parameter to
 * @param blen Size of the buffer
 * @param param ID of the parameter to add
 * @returns The size of the parameter, if successful, or 0 otherwise */
size_t imquic_transport_parameter_add_novalue(uint8_t *bytes, size_t blen, imquic_transport_parameter param);
/*! \brief Helper to add a QUIC transport parameter with a numeric value to a buffer
 * @param bytes Buffer to add the transport parameter to
 * @param blen Size of the buffer
 * @param param ID of the parameter to add
 * @param number The numeric value of the parameter to add
 * @returns The size of the parameter, if successful, or 0 otherwise */
size_t imquic_transport_parameter_add_int(uint8_t *bytes, size_t blen, imquic_transport_parameter param, uint64_t number);
/*! \brief Helper to add a QUIC transport parameter with generic data to a buffer
 * @param bytes Buffer to add the transport parameter to
 * @param blen Size of the buffer
 * @param param ID of the parameter to add
 * @param buf The data acting as a value for the parameter to add
 * @param buflen The size of the data value
 * @returns The size of the parameter, if successful, or 0 otherwise */
size_t imquic_transport_parameter_add_data(uint8_t *bytes, size_t blen, imquic_transport_parameter param, uint8_t *buf, size_t buflen);
/*! \brief Helper to add a QUIC transport parameter with a Connection ID to a buffer
 * @param bytes Buffer to add the transport parameter to
 * @param blen Size of the buffer
 * @param param ID of the parameter to add
 * @param cid The Connection ID value of the parameter to add
 * @returns The size of the parameter, if successful, or 0 otherwise */
size_t imquic_transport_parameter_add_connection_id(uint8_t *bytes, size_t blen, imquic_transport_parameter param, imquic_connection_id *cid);
///@}

/** @name Parsing QUIC transport parameters
 */
///@{
/*! \brief Helper to parse a buffer containing QUIC transport parameters,
 * and update the associated imquic_connection instance accordingly
 * @param conn The imquic_connection instance to update with the peer parameters
 * @param bytes The buffer containing the QUIC transport parameters
 * @param blen The size of the buffer to parse
 * @returns 0 in case of success, a negative integer otherwise */
int imquic_parse_transport_parameters(imquic_connection *conn, uint8_t *bytes, size_t blen);
///@}

/** @name Sending QUIC messages
 */
///@{
/*! \brief Helper method to generate a packet containing an \c ACK and send it
 * @note This may include a few other frames too, in case the stack thinks they're needed
 * @param conn The imquic_connection to send the message on
 * @param level The encryption level at which the message should be sent
 * @param src The source Connection ID, if any
 * @param dest The destinatiob Connection ID, if any
 * @returns 0 in case of success, or a negative integer otherwise */
int imquic_send_ack(imquic_connection *conn, enum ssl_encryption_level_t level, imquic_connection_id *src, imquic_connection_id *dest);
/*! \brief Helper method to generate one or more packets containing one or more \c CRYPTO frames and send them
 * @note This may include a few other frames too, in case the stack thinks they're needed
 * @param conn The imquic_connection to send the message(s) on
 * @param src The source Connection ID, if any
 * @param dest The destinatiob Connection ID, if any
 * @returns 0 in case of success, or a negative integer otherwise */
int imquic_send_pending_crypto(imquic_connection *conn, imquic_connection_id *src, imquic_connection_id *dest);
/*! \brief Helper method to generate a packet containing a \c PING and send it
 * @note This may include a few other frames too, in case the stack thinks they're neede
 * @param conn The imquic_connection to send the message on
 * @param dest The destinatiob Connection ID, if any
 * @returns 0 in case of success, or a negative integer otherwise */
int imquic_send_keepalive(imquic_connection *conn, imquic_connection_id *dest);
/*! \brief Helper method to generate a packet containing more flow control credits and send it
 * @note This may include a few other frames too, in case the stack thinks they're neede
 * @param conn The imquic_connection to send the message on
 * @param dest The destinatiob Connection ID, if any
 * @param type The frame to send, specifying which credits to grant
 * @param stream_id The ID of the stream the credits apply to
 * @returns 0 in case of success, or a negative integer otherwise */
int imquic_send_credits(imquic_connection *conn, imquic_connection_id *dest, imquic_frame_type type, uint64_t stream_id);
/*! \brief Helper method to generate a packet containing a request for more flow control credits and send it
 * @note This may include a few other frames too, in case the stack thinks they're neede
 * @param conn The imquic_connection to send the message on
 * @param dest The destinatiob Connection ID, if any
 * @param type The frame to send, specifying which credits to ask for
 * @param stream_id The ID of the stream the credits apply to
 * @returns 0 in case of success, or a negative integer otherwise */
int imquic_send_blocked(imquic_connection *conn, imquic_connection_id *dest, imquic_frame_type type, uint64_t stream_id);
/*! \brief Helper method to generate one or more packets containing one or more \c STREAM frames and send them
 * @note This may include a few other frames too, in case the stack thinks they're neede
 * @param conn The imquic_connection to send the message(s) on
 * @param dest The destinatiob Connection ID, if any
 * @returns 0 in case of success, or a negative integer otherwise */
int imquic_send_pending_stream(imquic_connection *conn, imquic_connection_id *dest);
/*! \brief Helper method to generate one or more packets containing one or more \c DATAGRAM frames and send them
 * @note This may include a few other frames too, in case the stack thinks they're neede
 * @param conn The imquic_connection to send the message(s) on
 * @param dest The destinatiob Connection ID, if any
 * @returns 0 in case of success, or a negative integer otherwise */
int imquic_send_pending_datagram(imquic_connection *conn, imquic_connection_id *dest);
/*! \brief Helper method to generate a packet containing a \c CONNECTION_CLOSE and send it
 * @note This may include a few other frames too, in case the stack thinks they're neede
 * @param conn The imquic_connection to send the message on
 * @param error_code Error code to report in the frame
 * @param frame_type The frame type that caused the connection to be closed
 * @param reason A verbose description of the error, if any
 * @returns 0 in case of success, or a negative integer otherwise */
int imquic_send_close_connection(imquic_connection *conn, imquic_error_code error_code, imquic_frame_type frame_type, const char *reason);
/*! \brief Serialize an imquic packet object to a QUIC packet ready to be
 * sent, taking care of header protection and encryption as well
 * @param conn The imquic_connection to serialize the packet for
 * @param pkt The imquic_packet containing the packet to serialize
 * @returns 0 in case of success, or a negative integer otherwise */
int imquic_serialize_packet(imquic_connection *conn, imquic_packet *pkt);
/*! \brief Send a QUIC packet to the peer
 * @note The imquic_packet instance should not be accessed after this
 * call, as it will either be freed (not needed anymore), or stored in
 * a map in case we need to retransmit it later if ACKs tell us to
 * @param conn The imquic_connection to send the message on
 * @param pkt The imquic_packet containing the packet to send
 * @returns 0 in case of success, or a negative integer otherwise */
int imquic_send_packet(imquic_connection *conn, imquic_packet *pkt);
/*! \brief Retransmit a previously sent packet
 * @param conn The imquic_connection to retransmit the message on
 * @param sent_pkt The imquic_sent_packet containing the packet to retransmit
 * @returns 0 in case of success, or a negative integer otherwise */
int imquic_retransmit_packet(imquic_connection *conn, imquic_sent_packet *sent_pkt);
///@}

/*! \brief Callback fired when the event loop has an event for a specific connection
 * @note At the moment, this is used as a way to use the event loop to
 * check if/when we have stuff to send (e.g., ACKs, data, etc.).
 * @param conn The imquic_connection instance the event is for
 * @returns G_SOURCE_CONTINUE if the event should be fired again in
 * the future, G_SOURCE_REMOVE otherwise */
gboolean imquic_handle_event(imquic_connection *conn);

/*! \brief Helper to start a new client endpoint, and so attempt a connection
 * @note This is not a blocking method: it will only kickstart the connection
 * process, but it will not wait for it to succeed or fail. There will
 * be asynchronous callbacks fired to handle those events instead.
 * @param socket The network endpoint to start the connection from
 * @returns 0 in case of success, a negative integer otherwise */
int imquic_start_quic_client(imquic_network_endpoint *socket);

#endif
