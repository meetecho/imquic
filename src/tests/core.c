#include "internal/connection.h"
#include "internal/qpack.h"
#include "internal/stream.h"
#include "internal/utils.h"

static void test_entry_size(void) {
	imquic_qpack_entry *entry = imquic_qpack_entry_create("abc", "xyz");
	g_assert_cmpuint(imquic_qpack_entry_size(entry), ==, 38);
	imquic_qpack_entry_destroy(entry);
	entry = imquic_qpack_entry_create(NULL, NULL);
	g_assert_cmpuint(imquic_qpack_entry_size(entry), ==, 32);
	imquic_qpack_entry_destroy(entry);
	g_assert_cmpuint(imquic_qpack_entry_size(NULL), ==, 0);
}

static void assert_invalid_header(const uint8_t *data, size_t size) {
	uint8_t *bytes = g_malloc(size);
	memcpy(bytes, data, size);
	imquic_qpack_context *ctx = imquic_qpack_context_create(4096);
	size_t read = 123;
	GList *headers = imquic_qpack_process(ctx, bytes, size, &read);
	g_assert((headers) == NULL);
	g_assert_cmpuint(read, ==, 0);
	imquic_qpack_context_destroy(ctx);
	g_free(bytes);
}

static void test_header_truncated(void) {
	const uint8_t prefix[] = { 0 };
	const uint8_t name_ref[] = { 0, 0, 0x51 };
	const uint8_t literal_name[] = { 0, 0, 0x21, 'x' };
	assert_invalid_header(prefix, sizeof(prefix));
	assert_invalid_header(name_ref, sizeof(name_ref));
	assert_invalid_header(literal_name, sizeof(literal_name));
}

static void test_header_indexes(void) {
	const uint8_t indexed[] = { 0, 0, 0xff, 0x24 };
	const uint8_t name_ref[] = { 0, 0, 0x5f, 0x54, 1, 'x' };
	assert_invalid_header(indexed, sizeof(indexed));
	assert_invalid_header(name_ref, sizeof(name_ref));
	const uint8_t valid[] = { 0, 0, 0xff, 0x23 };
	imquic_qpack_context *ctx = imquic_qpack_context_create(4096);
	size_t read = 0;
	GList *headers = imquic_qpack_process(ctx, (uint8_t *)valid, sizeof(valid), &read);
	g_assert_cmpuint(g_list_length(headers), ==, 1);
	g_assert_cmpstr(((imquic_qpack_entry *)headers->data)->name, ==, "x-frame-options");
	g_assert_cmpuint(read, ==, sizeof(valid));
	g_list_free_full(headers, (GDestroyNotify)imquic_qpack_entry_destroy);
	imquic_qpack_context_destroy(ctx);
}

static void test_header_literals(void) {
	const uint8_t huffman[] = { 0, 0, 0x51, 0x85, 0xff };
	const uint8_t plain[] = { 0, 0, 0x51, 5, 'a' };
	const uint8_t name[] = { 0, 0, 0x23, 'a' };
	assert_invalid_header(huffman, sizeof(huffman));
	assert_invalid_header(plain, sizeof(plain));
	assert_invalid_header(name, sizeof(name));
}

static void test_header_valid(void) {
	const uint8_t data[] = { 0, 0, 0x51, 3, 'a', 'b', 'c', 0x21, 'x', 0 };
	imquic_qpack_context *ctx = imquic_qpack_context_create(4096);
	size_t read = 0;
	GList *headers = imquic_qpack_process(ctx, (uint8_t *)data, sizeof(data), &read);
	g_assert_cmpuint(g_list_length(headers), ==, 2);
	imquic_qpack_entry *entry = headers->data;
	g_assert_cmpstr(entry->name, ==, ":path");
	g_assert_cmpstr(entry->value, ==, "abc");
	entry = headers->next->data;
	g_assert_cmpstr(entry->name, ==, "x");
	g_assert((entry->value) == NULL);
	g_assert_cmpuint(read, ==, sizeof(data));
	g_list_free_full(headers, (GDestroyNotify)imquic_qpack_entry_destroy);
	imquic_qpack_context_destroy(ctx);
}

static void test_header_huffman_limits(void) {
	for(size_t count = 255; count <= 256; count++) {
		uint8_t data[170] = { 0, 0, 0x51 };
		size_t encoded_length = (count * 5 + 7) / 8;
		size_t start = 3 + imquic_write_pfxint(encoded_length, 7, data + 3, sizeof(data) - 3);
		data[3] |= 0x80;
		/* 'a' is 00011; pad the final byte with ones. */
		for(size_t bit = 0; bit < encoded_length * 8; bit++) {
			if(bit >= count * 5 || bit % 5 >= 3)
				data[start + bit / 8] |= 1 << (7 - bit % 8);
		}
		imquic_qpack_context *ctx = imquic_qpack_context_create(4096);
		size_t read = 123;
		GList *headers = imquic_qpack_process(ctx, data, start + encoded_length, &read);
		if(count == 255) {
			g_assert(headers != NULL);
			g_assert_cmpuint(strlen(((imquic_qpack_entry *)headers->data)->value), ==, count);
			g_assert_cmpuint(read, ==, start + encoded_length);
		} else {
			g_assert(headers == NULL);
			g_assert_cmpuint(read, ==, 0);
		}
		g_list_free_full(headers, (GDestroyNotify)imquic_qpack_entry_destroy);
		imquic_qpack_context_destroy(ctx);
	}
}

static void assert_incomplete_encoder(const uint8_t *data, size_t size) {
	uint8_t *bytes = g_malloc(size);
	memcpy(bytes, data, size);
	imquic_qpack_context *ctx = imquic_qpack_context_create(4096);
	g_assert_cmpuint(imquic_qpack_decode(ctx, bytes, size), ==, 0);
	g_assert_cmpuint(ctx->rtable->index, ==, 0);
	g_assert_cmpuint(ctx->rtable->size, ==, 0);
	imquic_qpack_context_destroy(ctx);
	g_free(bytes);
}

static void test_encoder_truncated(void) {
	const uint8_t ref[] = { 0xc0 };
	const uint8_t literal[] = { 0x41, 'x' };
	const uint8_t value[] = { 0xc0, 0x85, 0xff };
	const uint8_t plain[] = { 0xc0, 5, 'x' };
	const uint8_t name[] = { 0x43, 'x' };
	assert_incomplete_encoder(ref, sizeof(ref));
	assert_incomplete_encoder(literal, sizeof(literal));
	assert_incomplete_encoder(value, sizeof(value));
	assert_incomplete_encoder(plain, sizeof(plain));
	assert_incomplete_encoder(name, sizeof(name));
}

static void test_encoder_indexes(void) {
	const uint8_t data[] = { 0xff, 0x24, 1, 'x' };
	assert_incomplete_encoder(data, sizeof(data));
}

static void test_encoder_valid(void) {
	uint8_t data[] = { 0x41, 'x', 1, 'y', 0xc0 };
	imquic_qpack_context *ctx = imquic_qpack_context_create(4096);
	g_assert_cmpuint(imquic_qpack_decode(ctx, data, sizeof(data)), ==, 4);
	g_assert_cmpuint(ctx->rtable->index, ==, 1);
	g_assert_cmpuint(ctx->rtable->size, ==, 34);
	imquic_qpack_entry *entry = ctx->rtable->list->data;
	g_assert_cmpstr(entry->name, ==, "x");
	g_assert_cmpstr(entry->value, ==, "y");
	imquic_qpack_context_destroy(ctx);
}

static void test_integer_overflow(void) {
	uint8_t data[16];
	memset(data, 0xff, sizeof(data));
	data[15] = 0;
	uint8_t length = 123;
	g_assert_cmpuint(imquic_read_pfxint(8, data, sizeof(data), &length), ==, 0);
	g_assert_cmpuint(length, ==, 0);
}

static void test_integer_roundtrip(void) {
	const uint64_t values[] = { 0, 30, 31, 254, 255, 256, UINT64_MAX };
	for(uint8_t n = 1; n <= 8; n++) {
		for(size_t i = 0; i < G_N_ELEMENTS(values); i++) {
			uint8_t bytes[16] = { 0 }, length = 0;
			uint8_t written = imquic_write_pfxint(values[i], n, bytes, sizeof(bytes));
			g_assert_cmpuint(written, >, 0);
			g_assert_cmpuint(imquic_read_pfxint(n, bytes, written, &length), ==, values[i]);
			g_assert_cmpuint(length, ==, written);
			if(written > 1) {
				imquic_read_pfxint(n, bytes, written - 1, &length);
				g_assert_cmpuint(length, ==, 0);
			}
		}
	}
}

static void test_stream_permissions(void) {
	for(int server = 0; server <= 1; server++) {
		for(uint64_t id = 0; id < 4; id++) {
			imquic_stream *stream = imquic_stream_create(id, server);
			gboolean local = stream->client_initiated != server;
			g_assert_cmpint(stream->can_send, ==, stream->bidirectional || local);
			g_assert_cmpint(stream->can_receive, ==, stream->bidirectional || !local);
			g_assert(!(imquic_stream_is_done(stream)));
			if(stream->can_send) imquic_stream_mark_complete(stream, FALSE);
			if(stream->can_receive) imquic_stream_mark_complete(stream, TRUE);
			g_assert(imquic_stream_is_done(stream));
			imquic_stream_destroy(stream);
		}
	}
}

static void test_stream_control(void) {
	imquic_connection conn = { 0 };
	imquic_mutex_init(&conn.mutex);
	conn.streams = g_hash_table_new(g_int64_hash, g_int64_equal);
	conn.queued_events = g_async_queue_new_full((GDestroyNotify)imquic_connection_event_destroy);
	for(uint64_t id = 0; id < 4; id++) {
		imquic_stream *stream = imquic_stream_create(id, FALSE);
		g_hash_table_insert(conn.streams, &stream->stream_id, stream);
		imquic_connection_reset_stream(&conn, id, 42);
		imquic_connection_event *event = g_async_queue_try_pop(conn.queued_events);
		if(id != 3) {
			g_assert((event) != NULL);
			g_assert_cmpint(event->type, ==, IMQUIC_CONNECTION_EVENT_RESET_STREAM);
			g_assert_cmpuint(event->error_code, ==, 42);
			imquic_connection_event_destroy(event);
		} else g_assert((event) == NULL);
		imquic_connection_stop_sending_stream(&conn, id, 43);
		event = g_async_queue_try_pop(conn.queued_events);
		if(id != 2) {
			g_assert((event) != NULL);
			g_assert_cmpint(event->type, ==, IMQUIC_CONNECTION_EVENT_STOP_SENDING);
			g_assert_cmpint(stream->in_state, ==, IMQUIC_STREAM_RESET);
			g_assert_cmpuint(event->error_code, ==, 43);
			imquic_connection_event_destroy(event);
		} else g_assert((event) == NULL);
		g_hash_table_remove_all(conn.streams);
		imquic_stream_destroy(stream);
	}
	g_hash_table_unref(conn.streams);
	g_async_queue_unref(conn.queued_events);
}

int main(int argc, char *argv[]) {
	g_test_init(&argc, &argv, NULL);
	imquic_set_log_level(0);
	g_test_add_func("/qpack/entry-size", test_entry_size);
	g_test_add_func("/qpack/header-truncated", test_header_truncated);
	g_test_add_func("/qpack/header-indexes", test_header_indexes);
	g_test_add_func("/qpack/header-literals", test_header_literals);
	g_test_add_func("/qpack/header-valid", test_header_valid);
	g_test_add_func("/qpack/header-huffman-limits", test_header_huffman_limits);
	g_test_add_func("/qpack/encoder-truncated", test_encoder_truncated);
	g_test_add_func("/qpack/encoder-indexes", test_encoder_indexes);
	g_test_add_func("/qpack/encoder-valid", test_encoder_valid);
	g_test_add_func("/integer/overflow", test_integer_overflow);
	g_test_add_func("/integer/roundtrip", test_integer_roundtrip);
	g_test_add_func("/stream/permissions", test_stream_permissions);
	g_test_add_func("/stream/control", test_stream_control);
	return g_test_run();
}
