/*
 * imquic
 *
 * Author:  Lorenzo Miniero <lorenzo@meetecho.com>
 * License: MIT
 *
 * Basic MoQ push-to-talk application using LOC
 *
 */

#include <arpa/inet.h>

#include <imquic/imquic.h>
#include <imquic/moq.h>

#include <opus/opus.h>

#include <SDL2/SDL.h>

#include "moq-loc-ptt-options.h"
#include "moq-utils.h"
#include "monogram.h"

/* Command line options */
static demo_options options = { 0 };

/* Signal */
static volatile int stop = 0;
static void imquic_demo_handle_signal(int signum) {
	switch(g_atomic_int_get(&stop)) {
		case 0:
			IMQUIC_PRINT("Stopping LOC push-to-talk, please wait...\n");
			break;
		case 1:
			IMQUIC_PRINT("In a hurry? I'm trying to free resources cleanly, here!\n");
			break;
		default:
			IMQUIC_PRINT("Ok, leaving immediately...\n");
			break;
	}
	g_atomic_int_inc(&stop);
	if(g_atomic_int_get(&stop) > 2)
		exit(1);
}

/* Audio buffer */
typedef struct imquic_demo_audio_buffer {
	uint16_t *samples;
	size_t num;
} imquic_demo_audio_buffer;
static void imquic_demo_audio_buffer_destroy(imquic_demo_audio_buffer *buf) {
	if(buf == NULL)
		return;
	g_free(buf->samples);
	g_free(buf);
}

/* Participant instance */
typedef struct imquic_demo_moq_ptt_participant {
	imquic_moq_namespace *track_namespace;
	imquic_moq_track *track_name;
	char *full_name;
	uint64_t request_id, track_alias;
	OpusDecoder *audiodec;
	GAsyncQueue *queue;
} imquic_demo_moq_ptt_participant;
static void imquic_demo_moq_ptt_participant_destroy(imquic_demo_moq_ptt_participant *p) {
	if(p == NULL)
		return;
	imquic_moq_namespace_free(p->track_namespace);
	imquic_moq_track_free(p->track_name);
	g_free(p->full_name);
	if(p->audiodec != NULL)
		opus_decoder_destroy(p->audiodec);
	if(p->queue != NULL)
		g_async_queue_unref(p->queue);
	g_free(p);
}
static imquic_demo_moq_ptt_participant *imquic_demo_moq_ptt_participant_create(imquic_moq_namespace *track_namespace,
		imquic_moq_track *track_name, uint64_t request_id, uint64_t track_alias) {
	imquic_demo_moq_ptt_participant *p = g_malloc0(sizeof(imquic_demo_moq_ptt_participant));
	p->track_namespace = imquic_moq_namespace_duplicate(track_namespace);
	p->track_name = imquic_moq_track_duplicate(track_name);
	char tns_buffer[256], tn_buffer[256], full_buffer[512];
	const char *ns = imquic_moq_namespace_str(track_namespace, tns_buffer, sizeof(tns_buffer), TRUE);
	const char *name = imquic_moq_track_str(track_name, tn_buffer, sizeof(tn_buffer));
	g_snprintf(full_buffer, sizeof(full_buffer), "%s--%s\n", ns, name);
	p->full_name = g_strdup(full_buffer);
	p->request_id = request_id;
	p->track_alias = track_alias;
	p->queue = g_async_queue_new_full((GDestroyNotify)imquic_demo_audio_buffer_destroy);
	int opus_error;
	p->audiodec = opus_decoder_create(48000, 1, &opus_error);
	if(opus_error != OPUS_OK) {
		/* Error creating audio decoder */
		IMQUIC_LOG(IMQUIC_LOG_ERR, "Error opening audio decoder\n");
		imquic_demo_moq_ptt_participant_destroy(p);
		return NULL;
	}
	return p;
}
static GHashTable *participants = NULL, *participants_by_reqid = NULL;
static imquic_mutex mutex = IMQUIC_MUTEX_INITIALIZER;

/* Local participant state */
static imquic_connection *moq_conn = NULL;
static imquic_moq_version moq_version = IMQUIC_MOQ_VERSION_ANY;
static uint64_t max_request_id = 100, sub_request_id = 0,
	pub_request_id = 0, pub_track_alias = 0;
static imquic_moq_namespace pub_namespace[2] = { 0 };
static imquic_moq_track pub_track = { 0 };
static char pub_tns_buffer[256], pub_tn_buffer[256];
static const char *pub_tns = NULL, *pub_tn = NULL;
static int IMQUIC_LOG_LOCPROP = IMQUIC_LOG_NONE;

typedef enum imquic_demo_state {
	DEMO_CONNECTING = 0,
	DEMO_IDLE,
	DEMO_TALKING,
} imquic_demo_state;
static const char *imquic_demo_state_str(imquic_demo_state state) {
	switch(state) {
		case DEMO_CONNECTING:
			return "Connecting to relay...";
		case DEMO_IDLE:
			return "Keep SPACE pressed to talk";
		case DEMO_TALKING:
			return "Release SPACE to stop talking";
		default:
			break;
	}
	return NULL;
};
static imquic_demo_state state = DEMO_CONNECTING;

/* Global SDL resources */
static SDL_Window *window = NULL;
static SDL_Renderer *renderer = NULL;
static int screen_w = 640, screen_h = 360;
static SDL_AudioDeviceID recdev, playdev;
static const char *imquic_demo_sdl_audioformat_str(SDL_AudioFormat format) {
	switch(format) {
		case AUDIO_U16SYS:
			return "AUDIO_U16SYS";
		case AUDIO_S16SYS:
			return "AUDIO_S16SYS";
		case AUDIO_S32SYS:
			return "AUDIO_S32SYS";
		case AUDIO_F32SYS:
			return "AUDIO_F32SYS";
		default:
			break;
	}
	return NULL;
}

/* Audio related stuff */
static GThread *audio_thread = NULL;
static OpusEncoder *audioenc = NULL;
static const int samples = 960;
static uint32_t want = samples * 2, cached = 0;
static uint8_t audio[1920], outgoing[500];
static size_t outlen = sizeof(outgoing);
static int64_t audio_ts = 0;
static uint64_t audio_group_id = 0, audio_object_id = 0;

static int imquic_demo_decode_audio(imquic_demo_moq_ptt_participant *p, uint8_t *buffer, size_t length) {
	if(p == NULL || p->audiodec == NULL)
		return -1;
	/* Decode the audio frame */
	opus_int16 samples[960];
	int ret = opus_decode(p->audiodec, buffer, length, samples, sizeof(samples), 0);
	if(ret < 0) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "Error decoding audio frame: %d (%s)\n",
			ret, opus_strerror(ret));
		return -1;
	}
	IMQUIC_LOG(IMQUIC_LOG_VERB, "Decoded %zu bytes to %d samples\n", length, ret);
	/* Queue the audio for later mixing */
	imquic_demo_audio_buffer *buf = g_malloc(sizeof(imquic_demo_audio_buffer));
	buf->num = ret;
	buf->samples = g_malloc(buf->num * 2);
	memcpy((uint8_t *)buf->samples, (uint8_t *)samples, buf->num * 2);
	g_async_queue_push(p->queue, buf);
	return 0;
}

static void *imquic_demo_audio_thread(void *user_data) {
	IMQUIC_LOG(IMQUIC_LOG_INFO, "Starting audio thread\n");

	int64_t now = g_get_monotonic_time(), before = now;
	uint16_t mix[960];
	uint32_t queued = 0;

	while(!g_atomic_int_get(&stop)) {
		/* FIXME Loop */
		now = g_get_monotonic_time();
		if(now - before < 18000) {
			g_usleep(5000);
			continue;
		}
		before += 20000;
		/* Create a mix */
		memset(mix, 0, sizeof(mix));
		GHashTableIter iter;
		gpointer value;
		imquic_mutex_lock(&mutex);
		g_hash_table_iter_init(&iter, participants);
		while(g_hash_table_iter_next(&iter, NULL, &value)) {
			imquic_demo_moq_ptt_participant *p = (imquic_demo_moq_ptt_participant *)value;
			imquic_demo_audio_buffer *buf = g_async_queue_try_pop(p->queue);
			if(buf != NULL) {
				/* FIXME We should make sure the buffer doesn't contain
				 * more samples than the mix is configured to work with */
				uint i = 0;
				for(i=0; i<buf->num; i++)
					mix[i] += buf->samples[i];
				imquic_demo_audio_buffer_destroy(buf);
			}
		}
		imquic_mutex_unlock(&mutex);
		/* Play the mix */
		queued = SDL_GetQueuedAudioSize(playdev);
		if(queued >= 10000) {
			IMQUIC_LOG(IMQUIC_LOG_VERB, "  -- Too many chunks in queue, clearing\n");
			SDL_ClearQueuedAudio(playdev);
		}
		SDL_QueueAudio(playdev, mix, sizeof(mix));
	}

	IMQUIC_LOG(IMQUIC_LOG_INFO, "Leaving audio thread\n");
	return NULL;
}

static int imquic_demo_send_audio(void) {
	if(recdev == 0)
		return 0;
	uint32_t avail = SDL_GetQueuedAudioSize(recdev);
	if(avail == 0)
		return 0;
	IMQUIC_LOG(IMQUIC_LOG_VERB, "%"SCNu32" audio chunks available\n", avail);

	if((cached + avail) >= want)
		avail = want - cached;
	IMQUIC_LOG(IMQUIC_LOG_VERB, "  -- Dequeueing %"SCNu32" chunks (%d samples, current index %"SCNu32")\n",
		avail, avail/2, cached);
	uint32_t got = SDL_DequeueAudio(recdev, audio + cached, avail);
	IMQUIC_LOG(IMQUIC_LOG_VERB, "  -- -- Got %"SCNu32"/%"SCNu32" chunks (%"SCNu32" samples)\n", got, avail, got/2);
	cached += got;
	if(cached == want) {
		/* We have enough to send, encode the audio */
		IMQUIC_LOG(IMQUIC_LOG_VERB, "  -- %"SCNu32" chunks cached, encoding to Opus\n", cached);
		int length = opus_encode(audioenc, (opus_int16 *)audio, cached/2, outgoing, outlen);
		cached = 0;
		if(length < 0) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "Error encoding the Opus frame: %d (%s)\n", length, opus_strerror(length));
			audio_ts += 20000;	/* FIXME */
			return 0;
		}
		IMQUIC_LOG(IMQUIC_LOG_VERB, "  -- -- Encoded samples to %d bytes\n", length);
		/* Write the LOC info first as properties */
		GList *props = NULL;
		imquic_moq_property timescale = { 0 };
		timescale.id = IMQUIC_MOQ_LOC_TIMESCALE;
		timescale.value.number = G_USEC_PER_SEC;
		props = g_list_append(props, &timescale);
		imquic_moq_property timestamp = { 0 };
		timestamp.id = IMQUIC_MOQ_LOC_TIMESTAMP;
		timestamp.value.number = audio_ts;
		props = g_list_append(props, &timestamp);
		audio_ts += 20000;	/* FIXME */
		/* FIXME We currently don't support LOC private properties, so
		 * we always send a 0x00 as a payload prefix to signal it's empty */
		uint8_t loc_pvt_props = 0;
		/* Prepare a MoQ object and send it */
		imquic_moq_object object = {
			.request_id = pub_request_id,
			.track_alias = pub_track_alias,
			.group_id = audio_group_id++,
			.subgroup_id = 0,	/* FIXME */
			.object_id = audio_object_id,
			.payload_prefix = &loc_pvt_props,
			.payload_prefix_len = 1,
			.payload = outgoing,
			.payload_len = length,
			.properties = props,
			.delivery = IMQUIC_MOQ_USE_DATAGRAM
		};
		imquic_moq_send_object(moq_conn, &object);
		g_list_free(props);
	}
	/* Done */
	return 0;
}

/* imquic callbacks */
static void imquic_demo_new_connection(imquic_connection *conn, void *user_data) {
	/* Got new connection */
	imquic_connection_ref(conn);
	moq_conn = conn;
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] New MoQ connection (configuring parameters)\n", imquic_get_connection_name(conn));
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s]   -- %s (%s)\n", imquic_get_connection_name(conn),
		imquic_is_connection_webtransport(conn) ? "WebTransport" : "Raw QUIC",
		imquic_is_connection_webtransport(conn) ? imquic_get_connection_wt_protocol(conn) : imquic_get_connection_alpn(conn));
	imquic_moq_set_max_request_id(conn, max_request_id);
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Waiting for MoQ connection to be ready (SETUP)...\n",
		imquic_get_connection_name(conn));
}

static void imquic_demo_ready(imquic_connection *conn) {
	/* Negotiation was done */
	const char *peer = imquic_moq_get_remote_implementation(conn);
	moq_version = imquic_moq_get_version(conn);
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] MoQ connection ready\n", imquic_get_connection_name(conn));
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s]   -- %s\n", imquic_get_connection_name(conn),
		imquic_moq_version_str(moq_version));
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s]   -- %s\n", imquic_get_connection_name(conn),
		peer ? peer : "unknown implementation");
	/* Only send a SUBSCRIBE_NAMESPACE and/or a SUBSCRIBE_TRACKS: the relay will
	 * send us a PUBLISH request when there's something we can subscribe to */
	imquic_moq_request_parameters params;
	imquic_moq_request_parameters_init_defaults(&params);
	params.forward_set = TRUE;
	params.forward = TRUE;
	imquic_moq_namespace *bak = pub_namespace[0].next;
	pub_namespace[0].next = NULL;
	if(imquic_moq_get_version(conn) < IMQUIC_MOQ_VERSION_18) {
		/* Older versions of MoQ used SUBSCRIBE_NAMESPACE to get PUBLISH too */
		sub_request_id = imquic_moq_get_next_request_id(conn);
		imquic_moq_subscribe_namespace(conn, sub_request_id, pub_namespace, IMQUIC_MOQ_WANT_PUBLISH, &params);
	} else {
		/* Use SUBSCRIBE_TRACKS for PUBLISH */
		sub_request_id = imquic_moq_get_next_request_id(conn);
		imquic_moq_subscribe_tracks(conn, sub_request_id, pub_namespace, &params);
	}
	pub_namespace[0].next = bak;
}

static void imquic_demo_subscribe_namespace_accepted(imquic_connection *conn, uint64_t request_id, imquic_moq_request_parameters *parameters) {
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Subscription to namespace '%"SCNu64"' accepted, waiting for PUBLISH requests\n",
		imquic_get_connection_name(conn), request_id);
	state = DEMO_IDLE;
}

static void imquic_demo_subscribe_namespace_error(imquic_connection *conn, uint64_t request_id, imquic_moq_request_error_code error_code,
		const char *reason, uint64_t retry_interval, imquic_moq_redirect *redirect) {
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Got an error subscribing to namespace in request '%"SCNu64"': error %d (%s)\n",
		imquic_get_connection_name(conn), request_id, error_code, reason);
	/* Stop here */
	g_atomic_int_inc(&stop);
}

static void imquic_demo_subscribe_tracks_accepted(imquic_connection *conn, uint64_t request_id, imquic_moq_request_parameters *parameters) {
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Subscription to namespace '%"SCNu64"' tracks accepted, waiting for PUBLISH requests\n",
		imquic_get_connection_name(conn), request_id);
	state = DEMO_IDLE;
}

static void imquic_demo_subscribe_tracks_error(imquic_connection *conn, uint64_t request_id, imquic_moq_request_error_code error_code,
		const char *reason, uint64_t retry_interval, imquic_moq_redirect *redirect) {
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Got an error subscribing to namespace tracks in request '%"SCNu64"': error %d (%s)\n",
		imquic_get_connection_name(conn), request_id, error_code, reason);
	/* Stop here */
	g_atomic_int_inc(&stop);
}

static void imquic_demo_publish_accepted(imquic_connection *conn, uint64_t request_id, imquic_moq_request_parameters *parameters) {
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Publish '%"SCNu64"' accepted\n",
		imquic_get_connection_name(conn), request_id);
	/* Create audio encoder */
	int opus_error;
	audioenc = opus_encoder_create(48000, 1, OPUS_APPLICATION_VOIP, &opus_error);
	if(opus_error != OPUS_OK) {
		/* Error creating audio decoder */
		IMQUIC_LOG(IMQUIC_LOG_ERR, "Error opening audio encoder\n");
		return;
	}
	/* Start capturing and sending audio */
	SDL_AudioSpec want, have;
	SDL_zero(want);
	want.freq = 48000;
	want.format = AUDIO_S16SYS;
	want.channels = 1;
	want.samples = 960;
	recdev = SDL_OpenAudioDevice(NULL, 1, &want, &have, 0);
	if(!recdev) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "Error opening recording audio device: %s\n", SDL_GetError());
		opus_encoder_destroy(audioenc);
		audioenc = NULL;
		return;
	}
	IMQUIC_LOG(IMQUIC_LOG_INFO, "Opened recording audio device %d: %"SCNu16", %"SCNu8" channels, %s, %"SCNu16" samples\n",
		recdev, have.freq, have.channels, imquic_demo_sdl_audioformat_str(have.format), have.samples);
	SDL_PauseAudioDevice(recdev, 0);
}

static void imquic_demo_incoming_publish(imquic_connection *conn, uint64_t request_id,
		imquic_moq_namespace *tns, imquic_moq_track *tn, uint64_t track_alias, imquic_moq_request_parameters *parameters, GList *track_properties) {
	/* We received a publish */
	char tns_buffer[256], tn_buffer[256];
	const char *ns = imquic_moq_namespace_str(tns, tns_buffer, sizeof(tns_buffer), TRUE);
	if(!strcasecmp(ns, ".2e")) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] Reserved namespace\n", imquic_get_connection_name(conn));
		imquic_moq_reject_publish(conn, request_id, IMQUIC_MOQ_REQERR_DOES_NOT_EXIST, "Reserved namespace", 0, NULL);
		return;
	}
	const char *name = imquic_moq_track_str(tn, tn_buffer, sizeof(tn_buffer));
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Incoming publish for '%s--%s' (ID %"SCNu64"/%"SCNu64"; %d properties)\n",
		imquic_get_connection_name(conn), ns, name, request_id, track_alias, g_list_length(track_properties));
	if(parameters->auth_token_set)
		imquic_moq_print_auth_info(conn, parameters->auth_token, parameters->auth_token_len);
	if(track_properties != NULL)
		imquic_moq_properties_print(imquic_moq_get_version(conn), IMQUIC_LOG_INFO, track_properties);
	/* Create a new participant from this track alias */
	imquic_demo_moq_ptt_participant *p = imquic_demo_moq_ptt_participant_create(tns, tn, request_id, track_alias);
	if(p != NULL) {
		imquic_mutex_lock(&mutex);
		g_hash_table_insert(participants_by_reqid, imquic_uint64_dup(request_id), p);
		g_hash_table_insert(participants, imquic_uint64_dup(track_alias), p);
		imquic_mutex_unlock(&mutex);
	}
	/* Done */
	imquic_moq_request_parameters rparams;
	imquic_moq_request_parameters_init_defaults(&rparams);
	rparams.forward_set = TRUE;
	rparams.forward = TRUE;
	rparams.subscriber_priority_set = TRUE;
	rparams.subscriber_priority = 128;
	rparams.group_order_set = TRUE;
	rparams.group_order = IMQUIC_MOQ_ORDERING_ASCENDING;
	rparams.subscription_filter_set = TRUE;
	imquic_moq_accept_publish(conn, request_id, &rparams);
}

static void imquic_demo_incoming_object(imquic_connection *conn, imquic_moq_object *object) {
	/* We received an object */
	if(!options.quiet) {
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Incoming object: reqid=%"SCNu64", alias=%"SCNu64", group=%"SCNu64", subgroup=%"SCNu64" (first=%d), id=%"SCNu64", payload=%zu bytes, properties=%d, delivery=%s, status=%s, eos=%d\n",
			imquic_get_connection_name(conn), object->request_id, object->track_alias,
			object->group_id, object->subgroup_id, object->first_of_subgroup, object->object_id,
			object->payload_len, g_list_length(object->properties), imquic_moq_delivery_str(object->delivery),
			imquic_moq_object_status_str(object->object_status), object->end_of_stream);
	}
	/* Check if we need to leave */
	if(g_atomic_int_get(&stop))
		return;
	/* Make sure we have a payload to process*/
	if(object->payload == NULL || object->payload_len == 0) {
		if(!options.quiet && object->end_of_stream) {
			IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Stream closed (status '%s' and eos=%d on empty packet)\n",
				imquic_get_connection_name(conn), imquic_moq_object_status_str(object->object_status), object->end_of_stream);
		}
		return;
	}
	/* If we got here, it's an audio object */
	imquic_mutex_lock(&mutex);
	imquic_demo_moq_ptt_participant *p = g_hash_table_lookup(participants, &object->track_alias);
	imquic_mutex_unlock(&mutex);
	if(p == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "  -- No participant found for track alias '%"SCNu64"\n", object->track_alias);
		return;
	}
	if(object->properties == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "  -- No properties, missing LOC info?\n");
	} else {
		/* Parse the properties to get access to the LOC info */
		IMQUIC_LOG(IMQUIC_LOG_LOCPROP, "  -- %d properties\n", g_list_length(object->properties));
		imquic_moq_properties_print(moq_version, IMQUIC_LOG_VERB, object->properties);
		uint64_t timestamp = 0, timescale = 0;
		GList *temp = object->properties;
		while(temp) {
			imquic_moq_property *prop = (imquic_moq_property *)temp->data;
			switch(prop->id) {
				case IMQUIC_MOQ_LOC_TIMESCALE: {
					timescale = prop->value.number;
					IMQUIC_LOG(IMQUIC_LOG_LOCPROP, "  -- -- %s: %"SCNu64"\n",
						imquic_moq_property_type_str(moq_version, prop->id), timescale);
					break;
				}
				case IMQUIC_MOQ_LOC_TIMESTAMP: {
					timestamp = prop->value.number;
					IMQUIC_LOG(IMQUIC_LOG_LOCPROP, "  -- -- %s: %"SCNu64"\n",
						imquic_moq_property_type_str(moq_version, prop->id), timestamp);
					break;
				}
				default: {
					IMQUIC_LOG(IMQUIC_LOG_WARN, "  -- -- Unknown property '%"SCNu32"'\n", prop->id);
					break;
				}
			}
			temp = temp->next;
		}
		IMQUIC_LOG(IMQUIC_LOG_LOCPROP, "  -- Payload: %zu bytes\n", object->payload_len);
		/* Check if there are private properties too */
		uint8_t length = 0;
		size_t prop_len = imquic_read_moqint(moq_version, object->payload, object->payload_len, &length);
		if(length == 0 || length > object->payload_len) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Broken private properties yet, ignoring object\n");
			return;
		}
		size_t skip = length;
		GList *pvt_properties = NULL;
		if(prop_len > 0) {
			pvt_properties = imquic_moq_parse_properties(moq_version, object->payload + skip, prop_len);
			IMQUIC_LOG(IMQUIC_LOG_LOCPROP, "  -- %d private properties\n", g_list_length(pvt_properties));
			if(pvt_properties != NULL)
				imquic_moq_properties_print(moq_version, IMQUIC_LOG_VERB, pvt_properties);
		}
		skip += prop_len;
		/* Decode the frame */
		imquic_demo_decode_audio(p, object->payload + skip, object->payload_len - skip);
	}
	if(object->end_of_stream) {
		if(!options.quiet) {
			IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Stream closed (status '%s' and eos=%d)\n",
				imquic_get_connection_name(conn), imquic_moq_object_status_str(object->object_status), object->end_of_stream);
		}
	}
}

static void imquic_demo_publish_done(imquic_connection *conn, uint64_t request_id, imquic_moq_pub_done_code status_code, uint64_t streams_count, const char *reason) {
	/* Our subscription is done */
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Subscription via ID %"SCNu64" is done, using %"SCNu64" streams: status %d (%s)\n",
		imquic_get_connection_name(conn), request_id, streams_count, status_code, reason);
	imquic_mutex_lock(&mutex);
	imquic_demo_moq_ptt_participant *p = g_hash_table_lookup(participants_by_reqid, &request_id);
	if(p != NULL) {
		g_hash_table_remove(participants_by_reqid, &request_id);
		g_hash_table_remove(participants, &p->track_alias);
	}
	imquic_mutex_unlock(&mutex);

}

static void imquic_demo_incoming_goaway(imquic_connection *conn, const char *uri, uint64_t timeout) {
	/* Connection was closed */
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Got a GOAWAY: %s (timeout=%"SCNu64"ms)\n",
		imquic_get_connection_name(conn), uri, timeout);
	/* Stop here */
	g_atomic_int_inc(&stop);
}

static void imquic_demo_connection_failed(void *user_data) {
	/* Connection failed */
	IMQUIC_LOG(IMQUIC_LOG_INFO, "Connection failed\n");
	/* Stop here */
	g_atomic_int_inc(&stop);
}

static void imquic_demo_connection_gone(imquic_connection *conn, uint64_t error_code, const char *reason) {
	/* Connection was closed */
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] MoQ connection gone\n", imquic_get_connection_name(conn));
	if(conn == moq_conn)
		imquic_connection_unref(conn);
	moq_conn = NULL;
	/* Stop here */
	g_atomic_int_inc(&stop);
}

/* SDL input handling and rendering */
static int imquic_demo_handle_input(void) {
	if(g_atomic_int_get(&stop))
		return -1;
	/* Poll for events */
	SDL_Event e = { 0 };
	while(SDL_PollEvent(&e) != 0) {
		if(e.type == SDL_QUIT ||
				(e.type == SDL_WINDOWEVENT && e.window.event == SDL_WINDOWEVENT_CLOSE) ||
				(e.type == SDL_KEYDOWN && e.key.keysym.sym == SDLK_ESCAPE)) {
			/* Close the application */
			g_atomic_int_set(&stop, 1);
			break;
		} else if(state == DEMO_IDLE && e.type == SDL_KEYDOWN && e.key.keysym.sym == SDLK_SPACE) {
			IMQUIC_LOG(IMQUIC_LOG_INFO, "SPACE pressed, sending PUBLISH\n");
			/* Reset the publisher state */
			cached = 0;
			audio_ts = 0;
			audio_group_id = 0;
			audio_object_id = 0;
			/* Send a PUBLISH */
			imquic_moq_request_parameters params;
			imquic_moq_request_parameters_init_defaults(&params);
			params.group_order_set = TRUE;
			params.group_order = IMQUIC_MOQ_ORDERING_ASCENDING;
			params.forward_set = TRUE;
			params.forward = TRUE;
			pub_request_id = imquic_moq_get_next_request_id(moq_conn);
			imquic_moq_publish(moq_conn, pub_request_id, &pub_namespace[0], &pub_track, pub_track_alias, &params, NULL);
			state = DEMO_TALKING;
		} else if(state == DEMO_TALKING && e.type == SDL_KEYUP && e.key.keysym.sym == SDLK_SPACE) {
			IMQUIC_LOG(IMQUIC_LOG_INFO, "SPACE released, sending PUBLISH_DONE\n");
			/* Stop publishing */
			if(recdev > 0)
				SDL_CloseAudioDevice(recdev);
			recdev = 0;
			if(audioenc != NULL)
				opus_encoder_destroy(audioenc);
			audioenc = NULL;
			imquic_moq_publish_done(moq_conn, pub_request_id, IMQUIC_MOQ_PUBDONE_TRACK_ENDED, "Done talking");
			pub_request_id = 0;
			pub_track_alias++;
			state = DEMO_IDLE;
		}
	}
	/* Done */
	return 0;
}

static uint32_t last_tick = 0;
static float scale = 2.0;
static int imquic_demo_render(void) {
	if(g_atomic_int_get(&stop))
		return -1;
	uint32_t ticks = SDL_GetTicks();
	if(last_tick == 0)
		last_tick = ticks;
	/* Aim for about 30fps rendering independently of the video rate */
	if(ticks - last_tick >= (1000/30)) {
		SDL_SetRenderDrawColor(renderer, 255, 255, 255, 255);
		SDL_RenderClear(renderer);
		/* Render text */
		int x = 0, y = 0;
		char buffer[100];
		size_t blen = sizeof(buffer);
		g_snprintf(buffer, blen, "[[%s]]", pub_tns);
		monogram_write(renderer, buffer, x, y, scale, screen_w, screen_h);
		y += (MONOGRAM_GLYPH_HEIGHT * scale);
		monogram_write(renderer, imquic_demo_state_str(state), x, y, scale, screen_w, screen_h);
		y += (MONOGRAM_GLYPH_HEIGHT * scale);
		y += (MONOGRAM_GLYPH_HEIGHT * scale);
		/* Write info on all active participants */
		GHashTableIter iter;
		gpointer value;
		imquic_mutex_lock(&mutex);
		g_hash_table_iter_init(&iter, participants);
		while(g_hash_table_iter_next(&iter, NULL, &value)) {
			imquic_demo_moq_ptt_participant *p = (imquic_demo_moq_ptt_participant *)value;
			g_snprintf(buffer, blen, "[talking] %s", p->full_name);
			monogram_write(renderer, buffer, x, y, scale, screen_w, screen_h);
			y += (MONOGRAM_GLYPH_HEIGHT * scale);
		}
		imquic_mutex_unlock(&mutex);
		/* Render to the screen */
		SDL_RenderPresent(renderer);
	}
	/* Done */
	return 0;
}

/* Main */
int main(int argc, char *argv[]) {
	/* Handle SIGINT (CTRL-C), SIGTERM (from service managers) */
	signal(SIGINT, imquic_demo_handle_signal);
	signal(SIGTERM, imquic_demo_handle_signal);

	IMQUIC_PRINT("imquic version %s\n", imquic_get_version_string_full());
	IMQUIC_PRINT("  -- %s (commit hash)\n", imquic_get_build_sha());
	IMQUIC_PRINT("  -- %s (build time)\n\n", imquic_get_build_time());

	/* Initialize some command line options defaults */
	options.debug_level = IMQUIC_LOG_INFO;
	/* Let's call our cmdline parser */
	if(!demo_options_parse(&options, argc, argv)) {
		demo_options_show_usage();
		demo_options_destroy();
		exit(1);
	}
	/* Logging level */
	imquic_set_log_level(options.debug_level);
	/* Debugging */
	if(options.debug_locks)
		imquic_set_lock_debugging(TRUE);
	if(options.debug_refcounts)
		imquic_set_refcount_debugging(TRUE);
	if(options.debug_loc_properties && !options.quiet)
		IMQUIC_LOG_LOCPROP = IMQUIC_LOG_INFO;

	/* Initialize SDL backends */
	int ret = 0;
	if(SDL_Init(SDL_INIT_TIMER | SDL_INIT_AUDIO) < 0) {
		IMQUIC_LOG(IMQUIC_LOG_FATAL, "Error initializing SDL2: %s\n", SDL_GetError());
		goto done;
	}

	/* Parse the command line arguments*/
	if(options.remote_host == NULL || options.remote_port == 0) {
		IMQUIC_LOG(IMQUIC_LOG_FATAL, "Invalid QUIC server address\n");
		ret = 1;
		goto done;
	}
	if(options.port > 65535) {
		IMQUIC_LOG(IMQUIC_LOG_FATAL, "Invalid port\n");
		ret = 1;
		goto done;
	}
	if(!options.raw_quic && !options.webtransport) {
		IMQUIC_LOG(IMQUIC_LOG_FATAL, "No raw QUIC or WebTransport enabled (enable at least one)\n");
		ret = 1;
		goto done;
	}
	if(options.ticket_file != NULL)
		IMQUIC_LOG(IMQUIC_LOG_INFO, "Early data support enabled (ticket file '%s')\n", options.ticket_file);
	if(options.moq_version != NULL) {
		if(!strcasecmp(options.moq_version, "any")) {
			IMQUIC_LOG(IMQUIC_LOG_INFO, "Negotiating version of MoQ between %d and %d\n",
				IMQUIC_MOQ_VERSION_MIN - IMQUIC_MOQ_VERSION_BASE, IMQUIC_MOQ_VERSION_MAX - IMQUIC_MOQ_VERSION_BASE);
			moq_version = IMQUIC_MOQ_VERSION_ANY;
		} else {
			moq_version = IMQUIC_MOQ_VERSION_BASE + atoi(options.moq_version);
			if(moq_version < IMQUIC_MOQ_VERSION_MIN || moq_version > IMQUIC_MOQ_VERSION_MAX) {
				IMQUIC_LOG(IMQUIC_LOG_FATAL, "Unsupported MoQ version %s\n", options.moq_version);
				ret = 1;
				goto done;
			}
			IMQUIC_LOG(IMQUIC_LOG_INFO, "Negotiating version of MoQ %d\n", moq_version - IMQUIC_MOQ_VERSION_BASE);
		}
	}

	if(options.name == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_FATAL, "Missing name\n");
		ret = 1;
		goto done;
	}
	pub_namespace[0].buffer = (uint8_t *)"push2talk";
	pub_namespace[0].length = strlen("push2talk");
	pub_namespace[0].next = &pub_namespace[1];
	pub_namespace[1].buffer = (uint8_t *)options.name;
	pub_namespace[1].length = strlen(options.name);
	pub_namespace[1].next = NULL;
	uint64_t tns_num = 0;
	if(!imquic_moq_namespace_is_valid(&pub_namespace[0], TRUE, &tns_num)) {
		IMQUIC_LOG(IMQUIC_LOG_FATAL, "Invalid track namespace\n");
		ret = 1;
		goto done;
	}
	pub_tns = imquic_moq_namespace_str(pub_namespace, pub_tns_buffer, sizeof(pub_tns_buffer), TRUE);
	IMQUIC_LOG(IMQUIC_LOG_INFO, "Using namespace '%s' (%"SCNu64" tuples)\n", pub_tns, tns_num);
	pub_track.buffer = (uint8_t *)"audio";
	pub_track.length = strlen("audio");
	pub_tn = imquic_moq_track_str(&pub_track, pub_tn_buffer, sizeof(pub_tn_buffer));
	IMQUIC_LOG(IMQUIC_LOG_INFO, "Using track name '%s'\n", pub_tn);

	/* Participants table */
	participants_by_reqid = g_hash_table_new_full(g_int64_hash, g_int64_equal,
		(GDestroyNotify)g_free, NULL);
	participants = g_hash_table_new_full(g_int64_hash, g_int64_equal,
		(GDestroyNotify)g_free, (GDestroyNotify)imquic_demo_moq_ptt_participant_destroy);

	/* Check if we need to create a QLOG file, and which we should save */
	gboolean qlog_quic = FALSE, qlog_http3 = FALSE, qlog_moq = FALSE;
	if(options.qlog_path != NULL) {
		IMQUIC_LOG(IMQUIC_LOG_INFO, "Creating QLOG file(s) in '%s'\n", options.qlog_path);
		if(options.qlog_sequential)
			IMQUIC_LOG(IMQUIC_LOG_INFO, "  -- Using sequential JSON\n");
		int i = 0;
		while(options.qlog_logging != NULL && options.qlog_logging[i] != NULL) {
			if(!strcasecmp(options.qlog_logging[i], "quic")) {
				IMQUIC_LOG(IMQUIC_LOG_INFO, "  -- Logging QUIC events\n");
				qlog_quic = TRUE;
			} else if(!strcasecmp(options.qlog_logging[i], "http3") && options.webtransport) {
				IMQUIC_LOG(IMQUIC_LOG_INFO, "  -- Logging HTTP/3 events\n");
				qlog_http3 = TRUE;
			} else if(!strcasecmp(options.qlog_logging[i], "moq")) {
				IMQUIC_LOG(IMQUIC_LOG_INFO, "  -- Logging MoQT events\n");
				qlog_moq = TRUE;
				if(options.qlog_moq_messages)
					IMQUIC_LOG(IMQUIC_LOG_INFO, "  -- -- Logging the payload of MoQT control messages\n");
				if(options.qlog_moq_objects)
					IMQUIC_LOG(IMQUIC_LOG_INFO, "  -- -- Logging the payload of MoQT objects\n");
			}
			i++;
		}
	}
	IMQUIC_LOG(IMQUIC_LOG_INFO, "\n");

	/* Initialize the library */
	if(imquic_init(options.secrets_log) < 0) {
		ret = 1;
		goto done;
	}

	/* Create a client endpoint */
	imquic_server *client = imquic_create_moq_client("moq-loc-ptt",
		IMQUIC_CONFIG_INIT,
		IMQUIC_CONFIG_TLS_CERT, options.cert_pem,
		IMQUIC_CONFIG_TLS_KEY, options.cert_key,
		IMQUIC_CONFIG_TLS_NO_VERIFY, TRUE,
		IMQUIC_CONFIG_LOCAL_BIND, options.ip,
		IMQUIC_CONFIG_LOCAL_PORT, options.port,
		IMQUIC_CONFIG_REMOTE_HOST, options.remote_host,
		IMQUIC_CONFIG_REMOTE_PORT, options.remote_port,
		IMQUIC_CONFIG_SNI, options.sni,
		IMQUIC_CONFIG_RAW_QUIC, options.raw_quic,
		IMQUIC_CONFIG_WEBTRANSPORT, options.webtransport,
		IMQUIC_CONFIG_EARLY_DATA, (options.ticket_file != NULL),
		IMQUIC_CONFIG_TICKET_FILE, options.ticket_file,
		IMQUIC_CONFIG_HTTP3_PATH, options.path,
		IMQUIC_CONFIG_QLOG_PATH, options.qlog_path,
		IMQUIC_CONFIG_QLOG_QUIC, qlog_quic,
		IMQUIC_CONFIG_QLOG_HTTP3, qlog_http3,
		IMQUIC_CONFIG_QLOG_MOQ, qlog_moq,
		IMQUIC_CONFIG_QLOG_MOQ_MESSAGES, options.qlog_moq_messages,
		IMQUIC_CONFIG_QLOG_MOQ_OBJECTS, options.qlog_moq_objects,
		IMQUIC_CONFIG_QLOG_SEQUENTIAL, options.qlog_sequential,
		IMQUIC_CONFIG_MOQ_VERSION, moq_version,
		IMQUIC_CONFIG_MOQ_GREASE, options.test_grease,
		IMQUIC_CONFIG_DONE, NULL);
	if(client == NULL) {
		ret = 1;
		goto done;
	}
	if(options.raw_quic) {
		IMQUIC_LOG(IMQUIC_LOG_INFO, "ALPN(s):\n");
		int i = 0;
		const char **alpns = imquic_get_endpoint_alpns(client);
		while(alpns[i] != NULL) {
			IMQUIC_LOG(IMQUIC_LOG_INFO, "  -- %s\n", alpns[i]);
			i++;
		}
	}
	if(options.webtransport && imquic_get_endpoint_wt_protocols(client) != NULL) {
		IMQUIC_LOG(IMQUIC_LOG_INFO, "WebTransport Protocol(s):\n");
		int i = 0;
		const char **wt_protocols = imquic_get_endpoint_wt_protocols(client);
		while(wt_protocols[i] != NULL) {
			IMQUIC_LOG(IMQUIC_LOG_INFO, "  -- %s\n", wt_protocols[i]);
			i++;
		}
	}
	imquic_set_new_moq_connection_cb(client, imquic_demo_new_connection);
	imquic_set_moq_ready_cb(client, imquic_demo_ready);
	imquic_set_subscribe_namespace_accepted_cb(client, imquic_demo_subscribe_namespace_accepted);
	imquic_set_subscribe_namespace_error_cb(client, imquic_demo_subscribe_namespace_error);
	imquic_set_subscribe_tracks_accepted_cb(client, imquic_demo_subscribe_tracks_accepted);
	imquic_set_subscribe_tracks_error_cb(client, imquic_demo_subscribe_tracks_error);
	imquic_set_publish_accepted_cb(client, imquic_demo_publish_accepted);
	imquic_set_incoming_publish_cb(client, imquic_demo_incoming_publish);
	imquic_set_incoming_object_cb(client, imquic_demo_incoming_object);
	imquic_set_publish_done_cb(client, imquic_demo_publish_done);
	imquic_set_incoming_goaway_cb(client, imquic_demo_incoming_goaway);
	imquic_set_connection_failed_cb(client, imquic_demo_connection_failed);
	imquic_set_moq_connection_gone_cb(client, imquic_demo_connection_gone);
	imquic_start_endpoint(client);

	/* Create a window */
	window = SDL_CreateWindow("imquic-moq-loc-ptt", SDL_WINDOWPOS_UNDEFINED, SDL_WINDOWPOS_UNDEFINED,
		screen_w, screen_h, SDL_WINDOW_SHOWN);
	if(window == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_FATAL, "Error creating window: %s\n", SDL_GetError());
		goto done;
	}
	renderer = SDL_CreateRenderer(window, -1, SDL_RENDERER_ACCELERATED);
	if(renderer == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_FATAL, "Error creating renderer: %s\n", SDL_GetError());
		goto done;
	}

	/* Open the embedded font for text rendering */
	monogram_load_font(renderer);

	/* SDL audio playback */
	SDL_AudioSpec want, have;
	SDL_zero(want);
	want.freq = 48000;
	want.format = AUDIO_S16SYS;
	want.channels = 1;
	want.samples = 960;
	playdev = SDL_OpenAudioDevice(NULL, 0, &want, &have, 0);
	if(!playdev) {
		IMQUIC_LOG(IMQUIC_LOG_FATAL, "Error opening playback audio device: %s\n", SDL_GetError());
		goto done;
	}
	IMQUIC_LOG(IMQUIC_LOG_INFO, "Opened playback audio device %d: %"SCNu16", %"SCNu8" channels, %s, %"SCNu16" samples\n",
		playdev, have.freq, have.channels, imquic_demo_sdl_audioformat_str(have.format), have.samples);
	SDL_PauseAudioDevice(playdev, 0);
	/* Audio thread */
	GError *error = NULL;
	audio_thread = g_thread_try_new("loc-ptt", &imquic_demo_audio_thread, NULL, &error);
	if(error != NULL) {
		IMQUIC_LOG(IMQUIC_LOG_FATAL, "Got error %d (%s) trying to start audio thread\n",
			error->code, error->message ? error->message : "??");
		goto done;
	}

	/* Loop */
	while(!g_atomic_int_get(&stop)) {
		/* Check if we're capturing and sending audio */
		if(recdev > 0 && imquic_demo_send_audio() < 0) {
			g_atomic_int_set(&stop, 1);
			break;
		}
		/* Handle the user input */
		if(imquic_demo_handle_input() < 0) {
			g_atomic_int_set(&stop, 1);
			break;
		}
		/* Render */
		if(imquic_demo_render() < 0) {
			g_atomic_int_set(&stop, 1);
			break;
		}
		/* Sleep a bit */
		SDL_Delay(10);
	}

	if(state == DEMO_TALKING)
		imquic_moq_publish_done(moq_conn, pub_request_id, IMQUIC_MOQ_PUBDONE_GOING_AWAY, "Closing app");

	/* Shutdown the client */
	imquic_shutdown_endpoint(client);

done:
	imquic_deinit();
	if(ret == 1)
		demo_options_show_usage();
	demo_options_destroy();

	/* Participants */
	if(participants != NULL)
		g_hash_table_unref(participants);

	/* Audio */
	if(audio_thread != NULL)
		g_thread_join(audio_thread);
	if(audioenc != NULL)
		opus_encoder_destroy(audioenc);

	/* SDL stuff */
	monogram_unload_font();
	SDL_Quit();

	/* Done */
	IMQUIC_PRINT("Bye!\n");
	exit(ret);
}
