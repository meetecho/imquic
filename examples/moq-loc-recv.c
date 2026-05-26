/*
 * imquic
 *
 * Author:  Lorenzo Miniero <lorenzo@meetecho.com>
 * License: MIT
 *
 * Basic MoQ audio/video subscriber using LOC
 *
 */

#include <arpa/inet.h>

#include <imquic/imquic.h>
#include <imquic/moq.h>

#include <libavutil/avutil.h>
#include <libavutil/imgutils.h>
#include <libavutil/opt.h>
#include <libavcodec/avcodec.h>
#include <libavformat/avformat.h>
#include <libswscale/swscale.h>
#ifndef AV_CH_LAYOUT_MONO
#include <libavutil/channel_layout.h>
#endif

#include <opus/opus.h>

#include <SDL2/SDL.h>

#include "moq-loc-recv-options.h"
#include "moq-utils.h"

/* Command line options */
static demo_options options = { 0 };

/* Signal */
static volatile int stop = 0;
static void imquic_demo_handle_signal(int signum) {
	switch(g_atomic_int_get(&stop)) {
		case 0:
			IMQUIC_PRINT("Stopping LOC receiver, please wait...\n");
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

/* Subscriber state */
static imquic_connection *moq_conn = NULL;
static imquic_moq_version moq_version = IMQUIC_MOQ_VERSION_ANY;
static uint64_t max_request_id = 100,
	catalog_request_id = 0, catalog_fetch_request_id = 0,
	audio_request_id = 0, video_request_id = 0,
	catalog_track_alias = 0, audio_track_alias = 0, video_track_alias = 0;
static imquic_moq_namespace sub_namespace[32] = { 0 };
static imquic_moq_track catalog_trackname = { 0 },
	audio_trackname = { 0 }, video_trackname = { 0 };
static char sub_tns_buffer[256], audio_tn_buffer[256], video_tn_buffer[256];
static const char *sub_tns = NULL, *catalog_tn = "catalog",
	*audio_tn = NULL, *video_tn = NULL;
static int IMQUIC_LOG_LOCPROP = IMQUIC_LOG_NONE;

/* Global SDL resources */
static SDL_Window *window = NULL;
static SDL_Renderer *renderer = NULL;
static SDL_Texture *texture = NULL;
static int screen_w = -1, screen_h = -1, texture_w = -1, texture_h = -1;
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
static imquic_moq_catalog *catalog = NULL;
static OpusDecoder *audiodec = NULL;
static AVCodecContext *videodec_ctx = NULL;

static int imquic_demo_create_audio_decoder(void) {
	if(options.audio_track_name == NULL)
		return -1;
	/* Audio (Opus) */
	int opus_error;
	audiodec = opus_decoder_create(48000, 1, &opus_error);
	if(opus_error != OPUS_OK) {
		/* Error creating audio decoder */
		IMQUIC_LOG(IMQUIC_LOG_ERR, "Error opening audio decoder\n");
		return -1;
	}
	/* SDL audio playback */
	SDL_AudioSpec want, have;
	SDL_zero(want);
	want.freq = 48000;
	want.format = AUDIO_S16SYS;
	want.channels = 1;
	want.samples = 960;
	dev = SDL_OpenAudioDevice(NULL, 0, &want, &have, 0);
	if(!dev) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "Error opening audio device: %s\n", SDL_GetError());
		return -2;
	}
	IMQUIC_LOG(IMQUIC_LOG_INFO, "Opened audio device %d: %"SCNu16", %"SCNu8" channels, %s, %"SCNu16" samples\n",
		dev, have.freq, have.channels, imquic_demo_sdl_audioformat_str(have.format), have.samples);
	SDL_PauseAudioDevice(dev, 0);
	return 0;
}

static int imquic_demo_create_video_decoder(uint8_t *extradata, size_t extradata_size) {
	if(options.video_track_name == NULL)
		return -1;
	/* Video (H.264) */
	AVCodec *video_codec = (AVCodec *)avcodec_find_decoder_by_name("h264");
	videodec_ctx = avcodec_alloc_context3(video_codec);
	videodec_ctx->coded_width = 640;	/* Just a placeholder */
	videodec_ctx->coded_height = 480;	/* Just a placeholder */
	if(extradata != NULL && extradata_size > 0) {
		videodec_ctx->extradata = av_malloc(extradata_size + AV_INPUT_BUFFER_PADDING_SIZE);
		memcpy(videodec_ctx->extradata, extradata, extradata_size);
		memset(videodec_ctx->extradata + extradata_size, 0, AV_INPUT_BUFFER_PADDING_SIZE);
		videodec_ctx->extradata_size = extradata_size;
	}
	if(avcodec_open2(videodec_ctx, video_codec, NULL) < 0) {
		/* Error creating video decoder */
		IMQUIC_LOG(IMQUIC_LOG_ERR, "Error opening video decoder\n");
		return -1;
	}
	return 0;
}

static int imquic_demo_decode_audio(uint8_t *buffer, size_t length) {
	if(audiodec == NULL)
		return -1;
	/* Decode the audio frame */
	opus_int16 samples[1920];
	int ret = opus_decode(audiodec, buffer, length, samples, sizeof(samples), 0);
	if(ret < 0) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "Error decoding audio frame: %d (%s)\n",
			ret, opus_strerror(ret));
		return -1;
	}
	/* Queue the samples for playback */
	IMQUIC_LOG(IMQUIC_LOG_VERB, "Decoded %zu bytes to %d samples\n", length, ret);
	Uint32 queued = SDL_GetQueuedAudioSize(dev);
	IMQUIC_LOG(IMQUIC_LOG_VERB, "  -- Have %d chunks available, %"SCNu32" are still queued\n",
		ret*2, queued);
	if(queued >= 10000) {
		IMQUIC_LOG(IMQUIC_LOG_VERB, "  -- Too many chunks in queue, clearing\n");
		SDL_ClearQueuedAudio(dev);
	}
	SDL_QueueAudio(dev, (uint8_t *)samples, ret*2);

	return 0;

}

static gboolean got_keyframe = FALSE;
static int imquic_demo_decode_video(uint8_t *buffer, size_t length, gboolean keyframe) {
	if(videodec_ctx == NULL)
		return -1;
	/* We only start decoding after we receive the first keyframe */
	if(!got_keyframe) {
		if(!keyframe) {
			IMQUIC_LOG(IMQUIC_LOG_VERB, "Still waiting for a video keyframe, skipping this frame...\n");
			return 0;
		}
		got_keyframe = TRUE;
	}
	/* Switch from AVCC to Annex-B */
	size_t avcc_offset = 0, nal_size = 0;
	while(length >= avcc_offset + 4) {
		memcpy(&nal_size, buffer + avcc_offset, 4);
		nal_size = ntohl(nal_size);
		if(nal_size > 0) {
			*(buffer + avcc_offset) = 0x00;
			*(buffer + avcc_offset + 1) = 0x00;
			*(buffer + avcc_offset + 2) = 0x00;
			*(buffer + avcc_offset + 3) = 0x01;
		}
		avcc_offset += 4 + nal_size;
	}
	/* Decode the video frame */
	AVPacket avpacket = { 0 };
	avpacket.pts = AV_NOPTS_VALUE;
	avpacket.dts = AV_NOPTS_VALUE;
	avpacket.pos = -1;
	avpacket.data = buffer;
	avpacket.size = length;
	if(keyframe)
		avpacket.flags |= AV_PKT_FLAG_KEY;
	int ret = avcodec_send_packet(videodec_ctx, &avpacket);
	if(ret < 0) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "Error decoding video frame: %d (%s)\n",
			ret, av_err2str(ret));
		return -1;
	}
	AVFrame *decoded_frame = av_frame_alloc();
	ret = avcodec_receive_frame(videodec_ctx, decoded_frame);
	if(ret == AVERROR(EAGAIN)) {
		/* Encoder needs more input? */
		IMQUIC_LOG(IMQUIC_LOG_VERB, "  -- Skipping decoding of video frame: %d (%s)\n",
			ret, av_err2str(ret));
		av_frame_free(&decoded_frame);
		return 0;
	} else if(ret < 0) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "Error decoding video frame: %d (%s)\n",
			ret, av_err2str(ret));
		av_frame_free(&decoded_frame);
		return -1;
	}
	/* If we don't have a window yet, create one now */
	if(window == NULL) {
		screen_w = decoded_frame->width;
		screen_h = decoded_frame->height;
		window = SDL_CreateWindow("imquic-moq-loc-recv", SDL_WINDOWPOS_UNDEFINED, SDL_WINDOWPOS_UNDEFINED,
			screen_w, screen_h, SDL_WINDOW_SHOWN);
		if(window == NULL) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "Error creating window: %s\n", SDL_GetError());
			av_frame_free(&decoded_frame);
			return -2;
		}
		renderer = SDL_CreateRenderer(window, -1, SDL_RENDERER_ACCELERATED);
		if(renderer == NULL) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "Error creating renderer: %s\n", SDL_GetError());
			av_frame_free(&decoded_frame);
			return -3;
		}
	} else {
		/* Check if we need to resize the window */
		if(decoded_frame->width != screen_w || decoded_frame->height != screen_h) {
			screen_w = decoded_frame->width;
			screen_h = decoded_frame->height;
			SDL_SetWindowSize(window, screen_w, screen_h);
		}
	}
	/* Copy the frame to the texture */
	if(decoded_frame->width != texture_w || decoded_frame->height != texture_h) {
		/* Regenerate the texture */
		IMQUIC_LOG(IMQUIC_LOG_INFO, "Video resolution: %dx%d\n", decoded_frame->width, decoded_frame->height);
		texture_w = decoded_frame->width;
		texture_h = decoded_frame->height;
		if(texture != NULL)
			SDL_DestroyTexture(texture);
		texture = SDL_CreateTexture(renderer, SDL_PIXELFORMAT_YV12,
			SDL_TEXTUREACCESS_STATIC, texture_w, texture_h);
	}
	SDL_UpdateYUVTexture(texture, NULL,
		decoded_frame->data[0], decoded_frame->linesize[0],
		decoded_frame->data[1], decoded_frame->linesize[1],
		decoded_frame->data[2], decoded_frame->linesize[2]);
	SDL_RenderCopy(renderer, texture, NULL, NULL);
	av_frame_free(&decoded_frame);
	/* Done, render to the screen */
	SDL_RenderPresent(renderer);
	return 0;
}

static void imquic_demo_destroy_audio_decoder(void) {
	if(audiodec != NULL)
		opus_decoder_destroy(audiodec);
	audiodec = NULL;
}

static void imquic_demo_destroy_video_decoder(void) {
	if(videodec_ctx != NULL)
		avcodec_free_context(&videodec_ctx);
	videodec_ctx = NULL;
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
	moq_version = imquic_moq_get_version(conn);
	/* Let's subscribe to the provided namespace/track(s) */
	imquic_moq_request_parameters params;
	imquic_moq_request_parameters_init_defaults(&params);
	params.forward_set = TRUE;
	params.forward = TRUE;
	params.subscriber_priority_set = TRUE;
	params.subscriber_priority = 128;
	/* We always get the catalog track first, if available */
	catalog_request_id = imquic_moq_get_next_request_id(conn);
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Subscribing to '%s--%s' (catalog), using ID %"SCNu64"\n",
		imquic_get_connection_name(conn), sub_tns, catalog_tn, catalog_request_id);
	imquic_moq_subscribe(conn, catalog_request_id, sub_namespace, &catalog_trackname, &params);
	if(options.use_catalog) {
		/* We wait for the catalog to subscribe to the media tracks */
		return;
	}
	/* If we got here, we also subscribe to the audio and/or video tracks */
	if(options.audio_track_name != NULL) {
		audio_request_id = imquic_moq_get_next_request_id(conn);
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Subscribing to '%s--%s' (audio), using ID %"SCNu64"\n",
			imquic_get_connection_name(conn), sub_tns, audio_tn, audio_request_id);
		/* Send a SUBSCRIBE */
		imquic_moq_subscribe(conn, audio_request_id, sub_namespace, &audio_trackname, &params);
	}
	if(options.video_track_name != NULL) {
		video_request_id = imquic_moq_get_next_request_id(conn);
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Subscribing to '%s--%s' (video), using ID %"SCNu64"\n",
			imquic_get_connection_name(conn), sub_tns, video_tn, video_request_id);
		/* Send a SUBSCRIBE */
		imquic_moq_subscribe(conn, video_request_id, sub_namespace, &video_trackname, &params);
	}
}

static void imquic_demo_subscribe_accepted(imquic_connection *conn, uint64_t request_id, uint64_t track_alias,
		imquic_moq_request_parameters *parameters, GList *track_properties) {
	if(request_id == catalog_request_id) {
		/* This is the catalog track: check if we need to perform a
		 * Joining FETCH too, in case objects are already available */
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Catalog subscription %"SCNu64" accepted (expires=%"SCNu64"; %d properties)\n",
			imquic_get_connection_name(conn), request_id, parameters->expires, g_list_length(track_properties));
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s]   -- Track Alias: %"SCNu64"\n",
			imquic_get_connection_name(conn), track_alias);
		catalog_track_alias = track_alias;
		if(parameters->largest_object_set) {
			/* There's a largest object, send a Joining FETCH */
			IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s]   -- Largest Location: %"SCNu64"/%"SCNu64"\n",
				imquic_get_connection_name(conn),
				parameters->largest_object.group, parameters->largest_object.object);
			/* Send a Joining Fetch referencing this subscription */
			imquic_moq_request_parameters fparams;
			imquic_moq_request_parameters_init_defaults(&fparams);
			catalog_fetch_request_id = imquic_moq_get_next_request_id(conn);
			int join_offset = parameters->largest_object.group;
			IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Sending Joining Fetch for subscription %"SCNu64", using ID %"SCNu64" (offset=%d)\n",
				imquic_get_connection_name(conn), request_id, catalog_fetch_request_id, join_offset);
			imquic_moq_joining_fetch(conn, catalog_fetch_request_id, request_id, FALSE, join_offset, &fparams);
		}
		return;
	}
	gboolean video = (options.video_track_name != NULL && request_id == video_request_id);
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] %s subscription %"SCNu64" accepted (expires=%"SCNu64"; %d properties)\n",
		imquic_get_connection_name(conn), video ? "Video" : "Audio",
		request_id, parameters->expires, g_list_length(track_properties));
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s]   -- Track Alias: %"SCNu64"\n",
		imquic_get_connection_name(conn), track_alias);
	if(video)
		video_track_alias = track_alias;
	else
		audio_track_alias = track_alias;
	if(parameters->largest_object_set) {
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s]   -- Largest Location: %"SCNu64"/%"SCNu64"\n",
			imquic_get_connection_name(conn),
			parameters->largest_object.group, parameters->largest_object.object);
	}
	if(track_properties != NULL)
		imquic_moq_properties_print(imquic_moq_get_version(conn), IMQUIC_LOG_VERB, track_properties);
}

static void imquic_demo_subscribe_error(imquic_connection *conn, uint64_t request_id, imquic_moq_request_error_code error_code,
		const char *reason, uint64_t retry_interval, imquic_moq_redirect *redirect) {
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Got an error subscribing via ID %"SCNu64": error %d (%s)\n",
		imquic_get_connection_name(conn), request_id, error_code, reason);
	/* Check if it's a redirect (needs v18 at least) or an actual error */
	if(error_code == IMQUIC_MOQ_REQERR_REDIRECT) {
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s]  -- This is a redirect:\n", imquic_get_connection_name(conn));
		if(redirect->connect_uri != NULL) {
			IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s]  -- -- Connect URI: %s\n",
				imquic_get_connection_name(conn), redirect->connect_uri);
		}
		if(redirect->track_namespace != NULL) {
			char buffer[256];
			const char *ns = imquic_moq_namespace_str(redirect->track_namespace, buffer, sizeof(buffer), TRUE);
			IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s]  -- -- Namespace: %s\n",
				imquic_get_connection_name(conn), ns);
		}
		if(redirect->track_name != NULL) {
			char buffer[256];
			const char *name = imquic_moq_track_str(redirect->track_name, buffer, sizeof(buffer));
			IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s]  -- -- Track name: %s\n",
				imquic_get_connection_name(conn), name);
		}
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] We don't support redirection in this demo, give up\n",
			imquic_get_connection_name(conn));
	}
	/* Stop here */
	g_atomic_int_inc(&stop);
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
	if(object->payload == NULL || object->payload_len == 0) {
		if(!options.quiet && object->end_of_stream) {
			IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Stream closed (status '%s' and eos=%d on empty packet)\n",
				imquic_get_connection_name(conn), imquic_moq_object_status_str(object->object_status), object->end_of_stream);
		}
		return;
	}
	if(object->track_alias == catalog_track_alias || object->delivery == IMQUIC_MOQ_USE_FETCH) {
		/* This is from the catalog track */
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Catalog: %.*s\n",
			imquic_get_connection_name(conn), (int)object->payload_len, (char *)object->payload);
		if(options.use_catalog && catalog == NULL) {
			/* Let's parse the catalog to see if there are tracks we can subscribe to */
			char *json = g_malloc(object->payload_len + 1);
			memcpy(json, object->payload, object->payload_len);
			json[object->payload_len] = '\0';
			catalog = imquic_moq_catalog_parse(json);
			g_free(json);
			if(catalog == NULL) {
				/* Something went wrong */
				g_atomic_int_set(&stop, 1);
				return;
			}
			GList *temp = catalog->tracks;
			while(temp) {
				imquic_moq_catalog_track *track = (imquic_moq_catalog_track *)temp->data;
				if(track->role && !strcasecmp(track->role, "audio")) {
					/* Audio track */
					if(audio_tn != NULL) {
						IMQUIC_LOG(IMQUIC_LOG_WARN, "  -- We already have an audio track, skipping '%s\n", track->track_name);
						temp = temp->next;
						continue;
					}
					/* FIXME This could be encoded already */
					audio_trackname.buffer = (uint8_t *)track->track_name;
					audio_trackname.length = strlen(track->track_name);
					if(!imquic_moq_track_is_valid(&audio_trackname)) {
						IMQUIC_LOG(IMQUIC_LOG_ERR, "  -- Invalid audio track name '%s'\n", track->track_name);
						g_atomic_int_set(&stop, 1);
						return;
					}
					if(track->codec && strcasecmp(track->codec, "opus")) {
						IMQUIC_LOG(IMQUIC_LOG_ERR, "  -- Unsupported audio codec '%s'\n", track->codec);
						g_atomic_int_set(&stop, 1);
						return;
					}
					audio_tn = imquic_moq_track_str(&audio_trackname, audio_tn_buffer, sizeof(audio_tn_buffer));
					IMQUIC_LOG(IMQUIC_LOG_INFO, "  -- Using track name '%s' for audio\n", audio_tn);
				} else if(track->role && !strcasecmp(track->role, "video")) {
					/* Video track */
					if(video_tn != NULL) {
						IMQUIC_LOG(IMQUIC_LOG_WARN, "  -- We already have an video track, skipping '%s\n", track->track_name);
						temp = temp->next;
						continue;
					}
					/* FIXME This could be encoded already */
					video_trackname.buffer = (uint8_t *)track->track_name;
					video_trackname.length = strlen(track->track_name);
					if(!imquic_moq_track_is_valid(&video_trackname)) {
						IMQUIC_LOG(IMQUIC_LOG_ERR, "  -- Invalid video track name '%s'\n", track->track_name);
						g_atomic_int_set(&stop, 1);
						return;
					}
					if(track->codec && strcasecmp(track->codec, "avc1.42001F")) {
						IMQUIC_LOG(IMQUIC_LOG_ERR, "  -- Unsupported video codec '%s'\n", track->codec);
						g_atomic_int_set(&stop, 1);
						return;
					}
					video_tn = imquic_moq_track_str(&video_trackname, video_tn_buffer, sizeof(video_tn_buffer));
					IMQUIC_LOG(IMQUIC_LOG_INFO, "  -- Using track name '%s' for video\n", video_tn);
				} else {
					IMQUIC_LOG(IMQUIC_LOG_WARN, "  -- Unsupported '%s' track\n", track->role);
				}
				temp = temp->next;
			}
			/* Subscribe to the tracks we found */
			imquic_moq_request_parameters params;
			imquic_moq_request_parameters_init_defaults(&params);
			params.forward_set = TRUE;
			params.forward = TRUE;
			params.subscriber_priority_set = TRUE;
			params.subscriber_priority = 128;
			if(audio_tn != NULL) {
				audio_request_id = imquic_moq_get_next_request_id(conn);
				IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Subscribing to '%s--%s' (audio), using ID %"SCNu64"\n",
					imquic_get_connection_name(conn), sub_tns, audio_tn, audio_request_id);
				/* Send a SUBSCRIBE */
				imquic_moq_subscribe(conn, audio_request_id, sub_namespace, &audio_trackname, &params);
			}
			if(video_tn != NULL) {
				video_request_id = imquic_moq_get_next_request_id(conn);
				IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Subscribing to '%s--%s' (video), using ID %"SCNu64"\n",
					imquic_get_connection_name(conn), sub_tns, video_tn, video_request_id);
				/* Send a SUBSCRIBE */
				imquic_moq_subscribe(conn, video_request_id, sub_namespace, &video_trackname, &params);
			}
		}
		return;
	}
	/* If we got here, it's an audio or video object */
	if(object->properties != NULL)
		imquic_moq_properties_print(imquic_moq_get_version(conn), IMQUIC_LOG_VERB, object->properties);
	/* FIXME Assuming LOC from https://github.com/facebookexperimental/moq-encoder-player/
	 * which uses the MoQ-MI draft: https://datatracker.ietf.org/doc/html/draft-cenzano-moq-media-interop */
	if(object->properties == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "  -- No properties, missing LOC info?\n");
	} else {
		/* Parse the properties to get access to the LOC info */
		IMQUIC_LOG(IMQUIC_LOG_LOCPROP, "  -- %d properties\n", g_list_length(object->properties));
		imquic_demo_media_type media_type = DEMO_MEDIA_NONE;
		struct imquic_moq_property_data *loc_header = NULL, *loc_extradata = NULL;
		GList *temp = object->properties;
		while(temp) {
			imquic_moq_property *prop = (imquic_moq_property *)temp->data;
			switch(prop->id) {
				case DEMO_LOC_MEDIA_TYPE: {
					media_type = prop->value.number;
					IMQUIC_LOG(IMQUIC_LOG_LOCPROP, "  -- -- %s: %s\n",
						imquic_demo_loc_property_str(prop->id),
						imquic_demo_media_type_str(media_type));
					break;
				}
				case DEMO_LOC_H264_HEADER: {
					loc_header = &prop->value.data;
					IMQUIC_LOG(IMQUIC_LOG_LOCPROP, "  -- -- %s: %zu bytes\n",
						imquic_demo_loc_property_str(prop->id),
						loc_header->length);
					break;
				}
				case DEMO_LOC_H264_EXTRADATA: {
					loc_extradata = &prop->value.data;
					IMQUIC_LOG(IMQUIC_LOG_LOCPROP, "  -- -- %s: %zu bytes\n",
						imquic_demo_loc_property_str(prop->id),
						loc_extradata->length);
					break;
				}
				case DEMO_LOC_OPUS_HEADER: {
					loc_header = &prop->value.data;
					IMQUIC_LOG(IMQUIC_LOG_LOCPROP, "  -- -- %s: %zu bytes\n",
						imquic_demo_loc_property_str(prop->id),
						loc_header->length);
					break;
				}
				case DEMO_LOC_AAC_HEADER: {
					loc_header = &prop->value.data;
					IMQUIC_LOG(IMQUIC_LOG_LOCPROP, "  -- -- %s: %zu bytes\n",
						imquic_demo_loc_property_str(prop->id),
						loc_header->length);
					break;
				}
				default: {
					IMQUIC_LOG(IMQUIC_LOG_WARN, "  -- -- Unknown property '%"SCNu32"'\n", prop->id);
					break;
				}
			}
			temp = temp->next;
		}
		if(loc_header != NULL && media_type != DEMO_MEDIA_NONE && media_type != DEMO_MEDIA_TEXT) {
			IMQUIC_LOG(IMQUIC_LOG_LOCPROP, "  -- LOC header (%zu bytes):\n", loc_header->length);
			uint8_t length = 0;
			size_t offset = 0;
			uint64_t seq_id = imquic_varint_read(&loc_header->buffer[offset], loc_header->length-offset, &length);
			IMQUIC_LOG(IMQUIC_LOG_LOCPROP, "  -- -- Sequence ID: %"SCNu64"\n", seq_id);
			offset += length;
			uint64_t pts = imquic_varint_read(&loc_header->buffer[offset], loc_header->length-offset, &length);
			IMQUIC_LOG(IMQUIC_LOG_LOCPROP, "  -- -- PTS: %"SCNu64"\n", pts);
			offset += length;
			if(media_type == DEMO_MEDIA_H264) {
				uint64_t dts = imquic_varint_read(&loc_header->buffer[offset], loc_header->length-offset, &length);
				IMQUIC_LOG(IMQUIC_LOG_LOCPROP, "  -- -- DTS: %"SCNu64"\n", dts);
				offset += length;
			}
			uint64_t timebase = imquic_varint_read(&loc_header->buffer[offset], loc_header->length-offset, &length);
			IMQUIC_LOG(IMQUIC_LOG_LOCPROP, "  -- -- Timebase: %"SCNu64"\n", timebase);
			offset += length;
			if(media_type == DEMO_MEDIA_OPUS || media_type == DEMO_MEDIA_AAC) {
				uint64_t sample_freq = imquic_varint_read(&loc_header->buffer[offset], loc_header->length-offset, &length);
				IMQUIC_LOG(IMQUIC_LOG_LOCPROP, "  -- -- Sample Frequency: %"SCNu64"\n", sample_freq);
				offset += length;
				uint64_t channels = imquic_varint_read(&loc_header->buffer[offset], loc_header->length-offset, &length);
				IMQUIC_LOG(IMQUIC_LOG_LOCPROP, "  -- -- Channels: %"SCNu64"\n", channels);
				offset += length;
			}
			uint64_t duration = imquic_varint_read(&loc_header->buffer[offset], loc_header->length-offset, &length);
			IMQUIC_LOG(IMQUIC_LOG_LOCPROP, "  -- -- Duration: %"SCNu64"\n", duration);
			offset += length;
			uint64_t Wallclock = imquic_varint_read(&loc_header->buffer[offset], loc_header->length-offset, &length);
			IMQUIC_LOG(IMQUIC_LOG_LOCPROP, "  -- -- Wallclock: %"SCNu64"\n", Wallclock);
			offset += length;
		}
		if(loc_extradata != NULL && media_type == DEMO_MEDIA_H264) {
			/* We have AVCC extradata*/
			IMQUIC_LOG(IMQUIC_LOG_LOCPROP, "  -- LOC extradata (%zu bytes):\n", loc_extradata->length);
			for(size_t i=0; i<loc_extradata->length; ++i)
				IMQUIC_LOG(IMQUIC_LOG_LOCPROP, "%02x", loc_extradata->buffer[i]);
			IMQUIC_LOG(IMQUIC_LOG_LOCPROP, "\n");
			uint8_t *avcc_data = loc_extradata->buffer;
			/* Read extradata */
			IMQUIC_LOG(IMQUIC_LOG_LOCPROP, "  -- -- Version:       %"SCNu8"\n", avcc_data[0]);
			IMQUIC_LOG(IMQUIC_LOG_LOCPROP, "  -- -- Profile:       %"SCNu8"\n", avcc_data[1]);
			IMQUIC_LOG(IMQUIC_LOG_LOCPROP, "  -- -- Compatibility: %"SCNu8"\n", avcc_data[2]);
			IMQUIC_LOG(IMQUIC_LOG_LOCPROP, "  -- -- Level:         %"SCNu8"\n", avcc_data[3]);
			IMQUIC_LOG(IMQUIC_LOG_LOCPROP, "  -- -- NAL length -1: %"SCNu8"\n", avcc_data[4] & 0x03);
			IMQUIC_LOG(IMQUIC_LOG_LOCPROP, "  -- -- SPS number:    %"SCNu8"\n", avcc_data[5] & 0x1F);
		}
		IMQUIC_LOG(IMQUIC_LOG_LOCPROP, "  -- Payload: %zu bytes\n", object->payload_len);
		/* Decode the frame */
		if(media_type == DEMO_MEDIA_OPUS) {
			/* Decode audio, and create a decoder if we don't have one yet */
			if(audiodec == NULL && imquic_demo_create_audio_decoder() < -1) {
				/* Stop here */
				g_atomic_int_inc(&stop);
				return;
			}
			imquic_demo_decode_audio(object->payload, object->payload_len);
		} else if(media_type == DEMO_MEDIA_H264) {
			/* Decode video */
			if(loc_extradata != NULL) {
				/* Use the extradata to (re)create the video decoder context */
				if(videodec_ctx != NULL)
					imquic_demo_destroy_video_decoder();
				if(imquic_demo_create_video_decoder(loc_extradata->buffer, loc_extradata->length) < -1) {
					/* Stop here */
					g_atomic_int_inc(&stop);
					return;
				}
			}
			imquic_demo_decode_video(object->payload, object->payload_len, loc_extradata != NULL);
		}
	}
	if(!options.quiet && object->end_of_stream) {
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Stream closed (status '%s' and eos=%d)\n",
			imquic_get_connection_name(conn), imquic_moq_object_status_str(object->object_status), object->end_of_stream);
	}
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

	/* Subscribe to the catalog track */
	catalog_trackname.buffer = (uint8_t *)catalog_tn;
	catalog_trackname.length = strlen(catalog_tn);
	/* Depending on whether we'll rely on the catalog or not, we may
	 * need to create track names for audio and/or video too */
	if(options.use_catalog) {
		IMQUIC_LOG(IMQUIC_LOG_INFO, "Will use the catalog to autodetect audio/video tracks\n");
	} else {
		/* Create tracknames for audio and/or video */
		if(options.audio_track_name == NULL && options.video_track_name == NULL) {
			IMQUIC_LOG(IMQUIC_LOG_FATAL, "Missing track name(s)\n");
			ret = 1;
			goto done;
		}
		if(options.audio_track_name != NULL) {
			audio_trackname.buffer = (uint8_t *)options.audio_track_name;
			audio_trackname.length = strlen(options.audio_track_name);
			if(!imquic_moq_track_is_valid(&audio_trackname)) {
				IMQUIC_LOG(IMQUIC_LOG_FATAL, "Invalid audio track name\n");
				ret = 1;
				goto done;
			}
			audio_tn = imquic_moq_track_str(&audio_trackname, audio_tn_buffer, sizeof(audio_tn_buffer));
			IMQUIC_LOG(IMQUIC_LOG_INFO, "Using track name '%s' for audio\n", audio_tn);
		}
		if(options.video_track_name != NULL) {
			video_trackname.buffer = (uint8_t *)options.video_track_name;
			video_trackname.length = strlen(options.video_track_name);
			if(!imquic_moq_track_is_valid(&video_trackname)) {
				IMQUIC_LOG(IMQUIC_LOG_FATAL, "Invalid video track name\n");
				ret = 1;
				goto done;
			}
			video_tn = imquic_moq_track_str(&video_trackname, video_tn_buffer, sizeof(video_tn_buffer));
			IMQUIC_LOG(IMQUIC_LOG_INFO, "Using track name '%s' for video\n", video_tn);
		}
	}

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

	/* Initialize SDL backends */
	if(SDL_Init(SDL_INIT_TIMER | SDL_INIT_AUDIO | SDL_INIT_VIDEO) < 0) {
		IMQUIC_LOG(IMQUIC_LOG_FATAL, "Error initializing SDL2: %s\n", SDL_GetError());
		goto done;
	}

	/* FFmpeg initialization */
#if (LIBAVFORMAT_VERSION_INT < AV_VERSION_INT(58,9,100))
	av_register_all();
#endif
	avformat_network_init();
	if(options.debug_ffmpeg)
		av_log_set_level(AV_LOG_DEBUG);

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
	imquic_set_subscribe_accepted_cb(client, imquic_demo_subscribe_accepted);
	imquic_set_subscribe_error_cb(client, imquic_demo_subscribe_error);
	imquic_set_incoming_object_cb(client, imquic_demo_incoming_object);
	imquic_set_incoming_goaway_cb(client, imquic_demo_incoming_goaway);
	imquic_set_connection_failed_cb(client, imquic_demo_connection_failed);
	imquic_set_moq_connection_gone_cb(client, imquic_demo_connection_gone);
	imquic_start_endpoint(client);

	while(!stop) {
		/* TODO Loop */
		g_usleep(100000);
	}

	/* Shutdown the client */
	imquic_shutdown_endpoint(client);

done:
	imquic_deinit();
	if(ret == 1)
		demo_options_show_usage();
	demo_options_destroy();

	/* Decoder stuff */
	imquic_moq_catalog_destroy(catalog);
	avformat_network_deinit();
	imquic_demo_destroy_audio_decoder();
	imquic_demo_destroy_video_decoder();

	/* SDL stuff */
	if(texture != NULL)
		SDL_DestroyTexture(texture);
	SDL_Quit();

	/* Done */
	IMQUIC_PRINT("Bye!\n");
	exit(ret);
}
