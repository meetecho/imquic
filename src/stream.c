/*! \file   stream.c
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright MIT License
 * \brief  QUIC STREAM abstraction
 * \details Abstraction of QUIC STREAMs, to facilitate the management
 * of client/server unidirectional/bidirectional streams created within
 * the contect of a QUIC connection.
 *
 * \ingroup Core
 */

#include "internal/stream.h"
#include "imquic/debug.h"

const char *imquic_stream_state_str(imquic_stream_state state) {
	switch(state) {
		case IMQUIC_STREAM_INACTIVE:
			return "inactive";
		case IMQUIC_STREAM_READY:
			return "ready";
		case IMQUIC_STREAM_BLOCKED:
			return "blocked";
		case IMQUIC_STREAM_RESET:
			return "reset";
		case IMQUIC_STREAM_COMPLETE:
			return "complete";
		default: break;
	}
	return NULL;
}

/* Stream initialization */
static void imquic_stream_free(const imquic_refcount *stream_ref) {
	imquic_stream *stream = imquic_refcount_containerof(stream_ref, imquic_stream, ref);
	imquic_buffer_destroy(stream->in_data);
	imquic_buffer_destroy(stream->out_data);
	g_free(stream);
}

imquic_stream *imquic_stream_create(uint64_t stream_id, gboolean is_server) {
	imquic_stream *stream = g_malloc0(sizeof(imquic_stream));
	stream->stream_id = stream_id;
	imquic_parse_stream_id(stream_id, &stream->actual_id, &stream->client_initiated, &stream->bidirectional);
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "New stream: %"SCNu64" (%"SCNu64", %s initiated, %s)\n",
		stream_id, stream->actual_id,
		stream->client_initiated ? "client" : "server",
		stream->bidirectional ? "bidirectional" : "unidirectional");
	stream->can_send = (is_server == !stream->client_initiated) || stream->bidirectional;
	stream->can_receive = (is_server == stream->client_initiated) || stream->bidirectional;
	stream->in_state = stream->can_receive ? IMQUIC_STREAM_READY : IMQUIC_STREAM_INACTIVE;
	stream->out_state = stream->can_send ? IMQUIC_STREAM_READY : IMQUIC_STREAM_INACTIVE;
	stream->in_data = stream->can_receive ? imquic_buffer_create(stream_id) : NULL;
	stream->out_data = stream->can_send ? imquic_buffer_create(stream_id) : NULL;
	imquic_mutex_init(&stream->mutex);
	imquic_refcount_init(&stream->ref, imquic_stream_free);
	return stream;
}

gboolean imquic_stream_can_send(imquic_stream *stream, uint64_t offset, uint64_t length, gboolean verbose) {
	if(stream == NULL)
		return FALSE;
	if(!stream->can_send || stream->out_state == IMQUIC_STREAM_INACTIVE || stream->out_data == NULL) {
		if(verbose)
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't send data, stream %"SCNu64" is unidirectional\n", stream->stream_id);
		return FALSE;
	}
	if(stream->out_state == IMQUIC_STREAM_COMPLETE || stream->in_state == IMQUIC_STREAM_RESET || stream->out_state == IMQUIC_STREAM_RESET) {
		if(verbose)
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't send data, stream %"SCNu64" is complete/reset\n", stream->stream_id);
		return FALSE;
	}
	if(stream->out_finalsize > 0 && (offset + length) > stream->out_finalsize) {
		if(verbose)
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't send data, final size for stream %"SCNu64" is known and this goes beyond it\n", stream->stream_id);
		return FALSE;
	}
	return TRUE;
}

gboolean imquic_stream_can_receive(imquic_stream *stream, uint64_t offset, uint64_t length, gboolean verbose) {
	if(stream == NULL)
		return FALSE;
	if(!stream->can_receive || stream->in_state == IMQUIC_STREAM_INACTIVE || stream->in_data == NULL) {
		if(verbose)
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't receive data, stream %"SCNu64" is unidirectional\n", stream->stream_id);
		return FALSE;
	}
	if(stream->in_state == IMQUIC_STREAM_COMPLETE || stream->in_state == IMQUIC_STREAM_RESET || stream->in_state == IMQUIC_STREAM_RESET) {
		if(verbose)
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't receive data, stream %"SCNu64" is complete/reset\n", stream->stream_id);
		return FALSE;
	}
	if(stream->in_finalsize > 0 && (offset + length) > stream->in_finalsize) {
		if(verbose)
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't receive data, final size for stream %"SCNu64" is known and this goes beyond it\n", stream->stream_id);
		return FALSE;
	}
	return TRUE;
}

gboolean imquic_stream_mark_complete(imquic_stream *stream, gboolean incoming) {
	if(stream == NULL)
		return FALSE;
	/* We only mark the final size here: switching the state to complete is done elsewhere */
	if(incoming) {
		if(stream->in_data == NULL)	/* Nothing to do */
			return TRUE;
		GList *last = g_list_last(stream->in_data->chunks);
		imquic_buffer_chunk *last_chunk = (imquic_buffer_chunk *)(last ? last->data : NULL);
		stream->in_finalsize = last_chunk ? (last_chunk->offset + last_chunk->length) : stream->in_data->base_offset;
		IMQUIC_LOG(IMQUIC_LOG_HUGE, "Stream %"SCNu64" has a known size for incoming data\n", stream->stream_id);
	} else {
		if(stream->out_data == NULL)	/* Nothing to do */
			return TRUE;
		GList *last = g_list_last(stream->out_data->chunks);
		imquic_buffer_chunk *last_chunk = (imquic_buffer_chunk *)(last ? last->data : NULL);
		stream->out_finalsize = last_chunk ? (last_chunk->offset + last_chunk->length) : stream->out_data->base_offset;
		IMQUIC_LOG(IMQUIC_LOG_HUGE, "Stream %"SCNu64" has a known size for outgoing data\n", stream->stream_id);
	}
	return TRUE;
}

gboolean imquic_stream_is_done(imquic_stream *stream) {
	if(stream == NULL)
		return FALSE;
	gboolean in_done = FALSE, out_done = FALSE;
	if(stream->in_state == IMQUIC_STREAM_COMPLETE || stream->in_state == IMQUIC_STREAM_RESET || stream->in_state == IMQUIC_STREAM_INACTIVE)
		in_done = TRUE;
	if(stream->out_state == IMQUIC_STREAM_COMPLETE || stream->out_state == IMQUIC_STREAM_RESET || stream->out_state == IMQUIC_STREAM_INACTIVE)
		out_done = TRUE;
	return in_done && out_done;
}

void imquic_stream_destroy(imquic_stream *stream) {
	if(stream && g_atomic_int_compare_and_exchange(&stream->destroyed, 0, 1))
		imquic_refcount_decrease(&stream->ref);
}

/* Reading and writing Stream ID */
void imquic_parse_stream_id(uint64_t stream_id, uint64_t *id, gboolean *client_initiated, gboolean *bidirectional) {
	uint64_t bits = stream_id & 0x00000003;
	*id = stream_id >> 2;
	*client_initiated = (bits == 0 || bits == 2);
	*bidirectional = (bits == 0 || bits == 1);
}

uint64_t imquic_build_stream_id(uint64_t id, gboolean client_initiated, gboolean bidirectional) {
	uint64_t stream_id = id << 2;
	if(!client_initiated && bidirectional)
		stream_id += 0x01;
	else if(client_initiated && !bidirectional)
		stream_id += 0x02;
	else if(!client_initiated && !bidirectional)
		stream_id += 0x03;
	return stream_id;
}
