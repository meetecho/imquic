/*! \file   stream.h
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright MIT License
 * \brief  QUIC STREAM abstraction (headers)
 * \details Abstraction of QUIC STREAMs, to facilitate the management
 * of client/server unidirectional/bidirectional streams created within
 * the contect of a QUIC connection.
 *
 * \ingroup Core
 */

#ifndef IMQUIC_STREAM_H
#define IMQUIC_STREAM_H

#include <stdint.h>

#include <glib.h>

#include "buffer.h"
#include "refcount.h"

/*! \brief Stream states */
typedef enum imquic_stream_state {
	/*! \brief Inactive */
	IMQUIC_STREAM_INACTIVE,
	/*! \brief Ready */
	IMQUIC_STREAM_READY,
	/*! \brief Blocked */
	IMQUIC_STREAM_BLOCKED,
	/*! \brief Reset */
	IMQUIC_STREAM_RESET,
	/*! \brief Complete */
	IMQUIC_STREAM_COMPLETE
} imquic_stream_state;
/*! \brief Helper function to serialize to string the name of a imquic_stream_state value.
 * @param state The imquic_stream_state value
 * @returns The state name as a string, if valid, or NULL otherwise */
const char *imquic_stream_state_str(imquic_stream_state state);

/*! \brief QUIC stream */
typedef struct imquic_stream {
	/*! \brief Stream ID and actual ID */
	uint64_t stream_id, actual_id;
	/*! \brief Whether the stream is client or server originated, and bidirectional or unidirectional */
	gboolean client_initiated, bidirectional;
	/*! \brief Whether the stream can send and receive data */
	gboolean can_send, can_receive;
	/*! \brief Stream incoming and outgoing final size (for flow control) */
	uint64_t in_finalsize, out_finalsize;
	/*! \brief Stream incoming and outgoing state */
	imquic_stream_state in_state, out_state;
	/*! \brief Number of bytes to skip, when dealing with offsets (e.g., to hide
	 * the shifted offsets when a protocol is encapsulated on a WebTransport */
	size_t skip_in, skip_out;
	/*! \brief Incoming and outgoing buffers */
	imquic_buffer *in_data, *out_data;
	/*! \brief Flow control state for this stream */
	uint64_t local_max_data, remote_max_data;
	/*! \brief Mutex */
	imquic_mutex mutex;
	/*! \brief Whether this instance has been destroyed (reference counting) */
	volatile gint destroyed;
	/*! \brief Reference counter */
	imquic_refcount ref;
} imquic_stream;
/*! \brief Helper method to create a new stream
 * @param stream_id The stream ID
 * @param is_server Whether the endpoint this stream is added to is a server
 * @returns A pointer to a new imquic_stream instance, if successful, or NULL otherwise */
imquic_stream *imquic_stream_create(uint64_t stream_id, gboolean is_server);
/*! \brief Helper method to check whether an endpoint can send data on this stream
 * @note This checks characteristics of the stream (e.g., client-originated,
 * bidirectional, etc.), the stream state, and whether a stream is complete
 * @param stream The imquic_stream instance to check
 * @param offset Offset in the stream from where the new data would be sent
 * @param length Length of the data that would be sent
 * @param verbose Whether details on the checks should be logged in a verbose way with warnings
 * @returns TRUE if data can be sent, FALSE otherwise */
gboolean imquic_stream_can_send(imquic_stream *stream, uint64_t offset, uint64_t length, gboolean verbose);
/*! \brief Helper method to check whether an endpoint can receive data on this stream
 * @note This checks characteristics of the stream (e.g., client-originated,
 * bidirectional, etc.), the stream state, and whether a stream is complete
 * @param stream The imquic_stream instance to check
 * @param offset Offset in the stream from where the new data would be received
 * @param length Length of the data that would be received
 * @param verbose Whether details on the checks should be logged in a verbose way with warnings
 * @returns TRUE if data can be received, FALSE otherwise */
gboolean imquic_stream_can_receive(imquic_stream *stream, uint64_t offset, uint64_t length, gboolean verbose);
/*! \brief Helper method to mark a stream as complete in one direction
 * @note This may end up marking the stream as complete in general,
 * depending on the stream state or the unidirectional nature of the stream
 * @param stream The imquic_stream instance to update
 * @param incoming Whether the stream is now complete on the way in or on the way out
 * @returns TRUE in case of success, or FALSE otherwise */
gboolean imquic_stream_mark_complete(imquic_stream *stream, gboolean incoming);
/*! \brief Helper method to check whether an existing stream is now done
 * @param stream The imquic_stream instance to check
 * @returns TRUE if the stream is now done, FALSE otherwise */
gboolean imquic_stream_is_done(imquic_stream *stream);
/*! \brief Helper method to destroy an existing imquic_stream instance
 * @param stream The imquic_stream instance to destroy */
void imquic_stream_destroy(imquic_stream *stream);

/** @name Stream utilities
 */
///@{
/*! \brief Parse a QUIC stream ID to its actual ID and its other properties
 * @param[in] stream_id The QUIC stream ID to parse
 * @param[out] id The actual client/server uni/bidirectional ID
 * @param[out] client_initiated Whether this stream is client initiated
 * @param[out] bidirectional Whether this stream is bidirectional */
void imquic_parse_stream_id(uint64_t stream_id, uint64_t *id, gboolean *client_initiated, gboolean *bidirectional);
/*! \brief Build a QUIC stream ID out of its actual ID and its other properties
 * @param[in] id The actual client/server uni/bidirectional ID
 * @param[in] client_initiated Whether this stream is client initiated
 * @param[in] bidirectional Whether this stream is bidirectional
 * @returns The QUIC stream ID */
uint64_t imquic_build_stream_id(uint64_t id, gboolean client_initiated, gboolean bidirectional);
///@}

#endif
