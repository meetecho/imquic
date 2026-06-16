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

/* Participant instance */
typedef struct imquic_demo_moq_ptt_participant {
	imquic_moq_namespace *track_namespace;
	imquic_moq_track *track_name;
	char *full_name;
	uint64_t request_id, track_alias;
	OpusDecoder *audiodec;
} imquic_demo_moq_ptt_participant;
static void imquic_demo_moq_ptt_participant_destroy(imquic_demo_moq_ptt_participant *p) {
	if(p == NULL)
		return;
	imquic_moq_namespace_free(p->track_namespace);
	imquic_moq_track_free(p->track_name);
	g_free(p->full_name);
	if(p->audiodec != NULL)
		opus_decoder_destroy(p->audiodec);
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
static imquic_moq_namespace sub_namespace[32] = { 0 };
static char sub_tns_buffer[256];
static const char *sub_tns = NULL;
static int IMQUIC_LOG_LOCPROP = IMQUIC_LOG_NONE;

/* Global SDL resources */
static SDL_Window *window = NULL;
static SDL_Renderer *renderer = NULL;
static int screen_w = 640, screen_h = 360;
static SDL_AudioDeviceID dev;
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

/* Decoder related stuff */
static int imquic_demo_decode_audio(imquic_demo_moq_ptt_participant *p, uint8_t *buffer, size_t length) {
	if(p == NULL || p->audiodec == NULL)
		return -1;
	/* Decode the audio frame */
	opus_int16 samples[1920];
	int ret = opus_decode(p->audiodec, buffer, length, samples, sizeof(samples), 0);
	if(ret < 0) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "Error decoding audio frame: %d (%s)\n",
			ret, opus_strerror(ret));
		return -1;
	}
	/* Queue the audio for later mixing */

	//~ /* Queue the samples for playback */
	//~ IMQUIC_LOG(IMQUIC_LOG_VERB, "Decoded %zu bytes to %d samples\n", length, ret);
	//~ Uint32 queued = SDL_GetQueuedAudioSize(dev);
	//~ IMQUIC_LOG(IMQUIC_LOG_VERB, "  -- Have %d chunks available, %"SCNu32" are still queued\n",
		//~ ret*2, queued);
	//~ if(queued >= 10000) {
		//~ IMQUIC_LOG(IMQUIC_LOG_VERB, "  -- Too many chunks in queue, clearing\n");
		//~ SDL_ClearQueuedAudio(dev);
	//~ }
	//~ SDL_QueueAudio(dev, (uint8_t *)samples, ret*2);
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
	if(imquic_moq_get_version(conn) < IMQUIC_MOQ_VERSION_18) {
		/* Older versions of MoQ used SUBSCRIBE_NAMESPACE to get PUBLISH too */
		sub_request_id = imquic_moq_get_next_request_id(conn);
		imquic_moq_subscribe_namespace(conn, sub_request_id, sub_namespace, IMQUIC_MOQ_WANT_PUBLISH, &params);
	} else {
		/* Use SUBSCRIBE_TRACKS for PUBLISH */
		sub_request_id = imquic_moq_get_next_request_id(conn);
		imquic_moq_subscribe_tracks(conn, sub_request_id, sub_namespace, &params);
	}
}

static void imquic_demo_subscribe_namespace_accepted(imquic_connection *conn, uint64_t request_id, imquic_moq_request_parameters *parameters) {
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Subscription to namespace '%"SCNu64"' accepted, waiting for PUBLISH requests\n",
		imquic_get_connection_name(conn), request_id);
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
	/* TODO Start sending objects */
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
	SDL_Rect rect = { 0 };
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
		monogram_write(renderer, "Hello, this is a test...", x, y, scale, screen_w, screen_h);
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
	SDL_Delay(10);
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
	if(SDL_Init(SDL_INIT_TIMER | SDL_INIT_AUDIO) < 0) {
		IMQUIC_LOG(IMQUIC_LOG_FATAL, "Error initializing SDL2: %s\n", SDL_GetError());
		goto done;
	}

	/* Parse the command line arguments*/
	int ret = 0;
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

	if(options.track_namespace == NULL || options.track_namespace[0] == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_FATAL, "Missing track namespace(s)\n");
		ret = 1;
		goto done;
	}
	int i = 0;
	while(options.track_namespace[i] != NULL) {
		const char *track_namespace = options.track_namespace[i];
		sub_namespace[i].buffer = (uint8_t *)track_namespace;
		sub_namespace[i].length = strlen(track_namespace);
		sub_namespace[i].next = (options.track_namespace[i+1] != NULL) ? &sub_namespace[i+1] : NULL;
		i++;
	}
	uint64_t tns_num = 0;
	if(!imquic_moq_namespace_is_valid(&sub_namespace[0], TRUE, &tns_num)) {
		IMQUIC_LOG(IMQUIC_LOG_FATAL, "Invalid track namespace\n");
		ret = 1;
		goto done;
	}
	sub_tns = imquic_moq_namespace_str(sub_namespace, sub_tns_buffer, sizeof(sub_tns_buffer), TRUE);
	IMQUIC_LOG(IMQUIC_LOG_INFO, "Using namespace '%s' (%"SCNu64" tuples)\n", sub_tns, tns_num);

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
	imquic_server *client = imquic_create_moq_client("moq-loc-recv",
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
	window = SDL_CreateWindow("imquic-moq-loc-recv", SDL_WINDOWPOS_UNDEFINED, SDL_WINDOWPOS_UNDEFINED,
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
	dev = SDL_OpenAudioDevice(NULL, 0, &want, &have, 0);
	if(!dev) {
		IMQUIC_LOG(IMQUIC_LOG_FATAL, "Error opening audio device: %s\n", SDL_GetError());
		goto done;
	}
	IMQUIC_LOG(IMQUIC_LOG_INFO, "Opened audio device %d: %"SCNu16", %"SCNu8" channels, %s, %"SCNu16" samples\n",
		dev, have.freq, have.channels, imquic_demo_sdl_audioformat_str(have.format), have.samples);
	SDL_PauseAudioDevice(dev, 0);

	/* Loop */
	while(!g_atomic_int_get(&stop)) {
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
	}

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

	/* SDL stuff */
	monogram_unload_font();
	SDL_Quit();

	/* Done */
	IMQUIC_PRINT("Bye!\n");
	exit(ret);
}
