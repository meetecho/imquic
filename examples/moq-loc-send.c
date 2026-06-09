/*
 * imquic
 *
 * Author:  Lorenzo Miniero <lorenzo@meetecho.com>
 * License: MIT
 *
 * Basic MoQ audio/video publisher using LOC
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
#include <libavdevice/avdevice.h>

#include <opus/opus.h>

#include <SDL2/SDL.h>

#include "moq-loc-send-options.h"
#include "moq-utils.h"

/* Command line options */
static demo_options options = { 0 };

/* Signal */
static volatile int stop = 0, connected = 0;
static void imquic_demo_handle_signal(int signum) {
	switch(g_atomic_int_get(&stop)) {
		case 0:
			IMQUIC_PRINT("Stopping LOC sender, please wait...\n");
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

/* Publisher state */
static imquic_connection *moq_conn = NULL;
static imquic_moq_version moq_version = IMQUIC_MOQ_VERSION_ANY;
static uint64_t max_request_id = 100,
	moq_tns_request_id = 0,
	catalog_request_id = 0, catalog_track_alias = 0,
	audio_request_id = 0, audio_track_alias = 1,
	video_request_id = 0, video_track_alias = 2;
static imquic_moq_namespace pub_namespace[32] = { 0 };
static imquic_moq_track catalog_trackname = { 0 },
	audio_trackname = { 0 }, video_trackname = { 0 };
static char pub_tns_buffer[256], audio_tn_buffer[256], video_tn_buffer[256];
static const char *pub_tns = NULL, *catalog_tn = "catalog",
	*audio_tn = NULL, *video_tn = NULL;
static volatile int catalog_started = 0, catalog_done = 0,
	audio_started = 0, audio_done = 0,
	video_started = 0, video_done = 0;
static uint64_t audio_group_id = 0, audio_object_id = 0,
	video_group_id = 0, video_object_id = 0;
static int64_t audio_ts = 0, video_ts = 0;
static imquic_moq_location audio_sub_start = { 0 }, audio_sub_end = { 0 },
	video_sub_start = { 0 }, video_sub_end = { 0 };

/* Global SDL resources */
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

/* Encoder related stuff */
static imquic_moq_catalog *catalog = NULL;
static OpusEncoder *audioenc = NULL;
static AVFormatContext *webcam_fmt = NULL;
static unsigned int video_stream = -1;
static imquic_demo_video_codec codec = DEMO_H264_AVCC;
static AVCodec *video_codec = NULL;
static AVCodecContext *webcam_ctx = NULL, *videoenc_ctx = NULL;
static struct SwsContext *sws = NULL;
static GThread *audio_thread = NULL, *video_capture_thread = NULL, *video_enc_thread = NULL;
static AVFrame *latest_frame = NULL;
static imquic_mutex mutex = IMQUIC_MUTEX_INITIALIZER;

static void *imquic_demo_audio_thread(void *user_data);
static void *imquic_demo_video_capture_thread(void *user_data);
static void *imquic_demo_video_enc_thread(void *user_data);

static int imquic_demo_create_audio_encoder(void) {
	if(options.audio_track_name == NULL)
		return -1;
	/* Audio (Opus) */
	int opus_error;
	audioenc = opus_encoder_create(48000, 1, OPUS_APPLICATION_VOIP, &opus_error);
	if(opus_error != OPUS_OK) {
		/* Error creating audio decoder */
		IMQUIC_LOG(IMQUIC_LOG_ERR, "Error opening audio encoder\n");
		return -1;
	}
	/* SDL audio capture */
	SDL_AudioSpec want, have;
	SDL_zero(want);
	want.freq = 48000;
	want.format = AUDIO_S16SYS;
	want.channels = 1;
	want.samples = 960;
	dev = SDL_OpenAudioDevice(NULL, 1, &want, &have, 0);
	if(!dev) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "Error opening audio device: %s\n", SDL_GetError());
		return -2;
	}
	IMQUIC_LOG(IMQUIC_LOG_INFO, "Opened audio device %d: %"SCNu16", %"SCNu8" channels, %s, %"SCNu16" samples\n",
		dev, have.freq, have.channels, imquic_demo_sdl_audioformat_str(have.format), have.samples);

	GError *error = NULL;
	audio_thread = g_thread_try_new("loc-send-audio", &imquic_demo_audio_thread, NULL, &error);
	if(error != NULL) {
		IMQUIC_LOG(IMQUIC_LOG_FATAL, "Got error %d (%s) trying to start audio thread\n",
			error->code, error->message ? error->message : "??");
		return -3;
	}
	/* Done */
	return 0;
}

static int imquic_demo_create_video_encoder(void) {
	if(options.video_track_name == NULL)
		return -1;
	/* FIXME Webcam capture (this currently assumes a Linux target) */
	const AVInputFormat *vf = av_find_input_format(options.video_format);
	if(vf == NULL) {
		/* v4l2 error */
		IMQUIC_LOG(IMQUIC_LOG_ERR, "Couldn't find '%s' format\n", options.video_format);
		return -1;
	}
	/* FIXME These should be configurable */
	AVDictionary *opts = NULL;
	char webcam_fps[5];
	g_snprintf(webcam_fps, sizeof(webcam_fps), "%d", options.video_framerate);
	av_dict_set(&opts, "framerate", webcam_fps, 0);
	av_dict_set(&opts, "video_size", options.video_resolution, 0);
	av_dict_set(&opts, "input_format", "yuyv422", 0);
	int ret = avformat_open_input(&webcam_fmt, options.video_device, vf, &opts);
	if(ret < 0) {
		/* Webcam error */
		av_dict_free(&opts);
		IMQUIC_LOG(IMQUIC_LOG_ERR, "Error opening video device '%s'\n", options.video_device);
		return -1;
	}
	ret = avformat_find_stream_info(webcam_fmt, NULL);
	if(ret < 0) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "Error accessing video device stream info\n");
		return -1;
	}
	for(unsigned int i=0; i<webcam_fmt->nb_streams; i++) {
		if(webcam_fmt->streams[i]->codecpar &&
				webcam_fmt->streams[i]->codecpar->codec_type == AVMEDIA_TYPE_VIDEO) {
			video_stream = i;
			IMQUIC_LOG(IMQUIC_LOG_INFO, "Opened video capture device (stream #%d)\n", video_stream);
			IMQUIC_LOG(IMQUIC_LOG_INFO, "  -- Capture rate: %d/%d (%d/%d)\n",
				webcam_fmt->streams[i]->avg_frame_rate.num,
				webcam_fmt->streams[i]->avg_frame_rate.den,
				webcam_fmt->streams[i]->r_frame_rate.num,
				webcam_fmt->streams[i]->r_frame_rate.den);
			break;
		}
	}
	const AVCodec *webcam_codec = avcodec_find_decoder(webcam_fmt->streams[video_stream]->codecpar->codec_id);
	webcam_ctx = avcodec_alloc_context3(webcam_codec);
	avcodec_parameters_to_context(webcam_ctx, webcam_fmt->streams[video_stream]->codecpar);
	if(avcodec_open2(webcam_ctx, webcam_codec, NULL) < 0) {
		/* Error creating video decoder */
		IMQUIC_LOG(IMQUIC_LOG_ERR, "Error opening video device decoder\n");
		return -1;
	}

	/* Create a video encoder */
	int width = options.width, height = options.height, fps = options.video_framerate;
	videoenc_ctx = avcodec_alloc_context3(video_codec);
	videoenc_ctx->bit_rate = 1000 * 1024;
	videoenc_ctx->rc_max_rate = videoenc_ctx->bit_rate + (videoenc_ctx->bit_rate/10);
	videoenc_ctx->rc_buffer_size = 2 * videoenc_ctx->bit_rate;
	videoenc_ctx->width = width;
	videoenc_ctx->height = height;
	videoenc_ctx->time_base = (AVRational){ 1, fps };
	videoenc_ctx->gop_size = fps * 5;
	videoenc_ctx->pix_fmt = AV_PIX_FMT_YUV420P;
	videoenc_ctx->flags |= AV_CODEC_FLAG_GLOBAL_HEADER;
	if(codec == DEMO_H264_AVCC || codec == DEMO_H264_ANNEXB) {
		videoenc_ctx->profile = FF_PROFILE_H264_BASELINE;
		videoenc_ctx->level = 41;
	}
	char br[20];
	if(codec == DEMO_H264_AVCC || codec == DEMO_H264_ANNEXB) {
		g_snprintf(br, sizeof(br), "%"SCNi64, videoenc_ctx->bit_rate/1024);
		av_opt_set(videoenc_ctx->priv_data, "b", br, AV_OPT_SEARCH_CHILDREN);
		av_opt_set(videoenc_ctx->priv_data, "crf", "18", AV_OPT_SEARCH_CHILDREN);
		av_opt_set(videoenc_ctx->priv_data, "profile", "baseline", 0);
		av_opt_set(videoenc_ctx->priv_data, "preset", "ultrafast", 0);
		av_opt_set(videoenc_ctx->priv_data, "tune", "zerolatency", 0);
	} else if(codec == DEMO_VP8) {
		av_opt_set(videoenc_ctx->priv_data, "speed", "7", 0);
		av_opt_set_double(videoenc_ctx->priv_data, "max-intra-rate", 300, 0);
		av_opt_set(videoenc_ctx->priv_data, "quality", "realtime", 0);
		av_opt_set(videoenc_ctx->priv_data, "threads", "2", 0);
	} else if(codec == DEMO_VP9) {
		av_opt_set(videoenc_ctx->priv_data, "speed", "7", 0);
		av_opt_set_double(videoenc_ctx->priv_data, "max-intra-rate", 300, 0);
		av_opt_set(videoenc_ctx->priv_data, "quality", "realtime", 0);
		av_opt_set(videoenc_ctx->priv_data, "lag-in-frames", "0", 0);
		av_opt_set(videoenc_ctx->priv_data, "tile-columns", "2", 0);
		av_opt_set(videoenc_ctx->priv_data, "row-mt", "1", 0);
		av_opt_set(videoenc_ctx->priv_data, "threads", "2", 0);
	}
	if(avcodec_open2(videoenc_ctx, video_codec, NULL) < 0) {
		/* Error creating video encoder */
		IMQUIC_LOG(IMQUIC_LOG_ERR, "Error opening video encoder\n");
		return -1;
	}

	/* Spawn threads: we use one to capture and one to encode in order
	 * to allow us to separate capture rate and encoding rate properly */
	GError *error = NULL;
	video_capture_thread = g_thread_try_new("loc-cap-video", &imquic_demo_video_capture_thread, NULL, &error);
	if(error != NULL) {
		IMQUIC_LOG(IMQUIC_LOG_FATAL, "Got error %d (%s) trying to start video thread\n",
			error->code, error->message ? error->message : "??");
		return -3;
	}
	video_enc_thread = g_thread_try_new("loc-enc-video", &imquic_demo_video_enc_thread, NULL, &error);
	if(error != NULL) {
		IMQUIC_LOG(IMQUIC_LOG_FATAL, "Got error %d (%s) trying to start video thread\n",
			error->code, error->message ? error->message : "??");
		return -4;
	}

	/* Done */
	return 0;
}

static void imquic_demo_destroy_audio_encoder(void) {
	if(audioenc != NULL)
		opus_encoder_destroy(audioenc);
	audioenc = NULL;
}

static void imquic_demo_destroy_video_encoder(void) {
	if(webcam_fmt != NULL)
		avio_close(webcam_fmt->pb);
	if(webcam_ctx != NULL)
		avcodec_free_context(&webcam_ctx);
	if(videoenc_ctx != NULL)
		avcodec_free_context(&videoenc_ctx);
	videoenc_ctx = NULL;
	if(sws != NULL)
		sws_freeContext(sws);
	sws = NULL;
}

/* Annex-B to AVCC translation for SPS/PPS (AVCC extradata) */
static size_t imquic_demo_h264_spspps_to_avcc(uint8_t *avcc_data, uint8_t *buffer, size_t len) {
	/* We use this function to return a metadata JSON object for AVC1 */
	avcc_data[0] = 1;
	/* Let's check if it's the right profile, first */
	size_t index = 0;
	if(buffer[0] == 0x00 && buffer[1] == 0x00 && buffer[2] == 0x01) {
		index = 3;
	} else if(buffer[0] == 0x00 && buffer[1] == 0x00 && buffer[2] == 0x00 && buffer[3] == 0x01) {
		index = 4;
	} else {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "No NAL start code\n");
		return 0;
	}
	if(buffer[index] != 0x67) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "Not an SPS NAL (%02x)\n", buffer[index]);
		return 0;
	}
	size_t sps_index = index;
	index++;
	int profile_idc = *(buffer+index);
	if(profile_idc != 66) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "Profile is not baseline (%d != 66)\n", profile_idc);
	}
	avcc_data[1] = 66;	/* FIXME */
	avcc_data[2] = 3;	/* FIXME */
	avcc_data[3] = 31;	/* FIXME */
	avcc_data[4] = 3;
	avcc_data[5] = 1;
	size_t avcc_size = 6;

	/* Find the next NAL */
	uint16_t sps_size = 0;
	while((index + 3) < len) {
		if(buffer[index] == 0x00 && buffer[index+1] == 0x00 && buffer[index+2] == 0x01) {
			sps_size = index - sps_index;
			index += 3;
			break;
		} else if(buffer[index] == 0x00 && buffer[index+1] == 0x00 && buffer[index+2] == 0x00 && buffer[index+3] == 0x01) {
			sps_size = index - sps_index;
			index += 4;
			break;
		}
		index++;
	}
	size_t pps_index = index;

	/* Append SPS to the AVCC buffer */
	sps_size = htons(sps_size);
	memcpy(&avcc_data[avcc_size], &sps_size, 2);
	avcc_size += 2;
	sps_size = ntohs(sps_size);
	memcpy(&avcc_data[avcc_size], &buffer[sps_index], sps_size);
	avcc_size += sps_size;

	/* Append PPS to the AVCC buffer */
	size_t pps_size = len - pps_index;
	avcc_data[avcc_size] = pps_size ? 1 : 0;
	avcc_size++;
	pps_size = htons(pps_size);
	memcpy(&avcc_data[avcc_size], &pps_size, 2);
	avcc_size += 2;
	pps_size = ntohs(pps_size);
	if(pps_size > 0) {
		memcpy(&avcc_data[avcc_size], &buffer[pps_index], pps_size);
		avcc_size += pps_size;
	}

	/* Done */
	return avcc_size;
}

/* Threads */
static void *imquic_demo_audio_thread(void *user_data) {
	IMQUIC_LOG(IMQUIC_LOG_INFO, "Starting audio thread\n");

	gboolean paused = TRUE;
	int samples = 960, length = 0;
	uint8_t audio[1920], outgoing[500];
	size_t outlen = sizeof(outgoing);
	uint32_t avail = 0, want = samples*2, got = 0, cached = 0;

	while(!stop) {
		/* FIXME Loop */
		if(!g_atomic_int_get(&audio_started)) {
			if(!paused) {
				paused = TRUE;
				SDL_PauseAudioDevice(dev, 1);
			}
			g_usleep(100000);
			continue;
		}
		if(paused) {
			paused = FALSE;
			SDL_PauseAudioDevice(dev, 0);
		}

		avail = SDL_GetQueuedAudioSize(dev);
		if(avail == 0) {
			g_usleep(1000);
			continue;
		}
		IMQUIC_LOG(IMQUIC_LOG_VERB, "%"SCNu32" audio chunks available\n", avail);
		if((cached + avail) >= want)
			avail = want - cached;
		IMQUIC_LOG(IMQUIC_LOG_VERB, "  -- Dequeueing %"SCNu32" chunks (%d samples, current index %"SCNu32")\n",
			avail, avail/2, cached);
		got = SDL_DequeueAudio(dev, audio + cached, avail);
		IMQUIC_LOG(IMQUIC_LOG_VERB, "  -- -- Got %"SCNu32"/%"SCNu32" chunks (%"SCNu32" samples)\n", got, avail, got/2);
		cached += got;
		if(cached == want) {
			/* We have enough to send, encode the audio */
			IMQUIC_LOG(IMQUIC_LOG_VERB, "  -- %"SCNu32" chunks cached, encoding to Opus\n", cached);
			length = opus_encode(audioenc, (opus_int16 *)audio, cached/2, outgoing, outlen);
			cached = 0;
			if(length < 0) {
				IMQUIC_LOG(IMQUIC_LOG_ERR, "Error encoding the Opus frame: %d (%s)\n", length, opus_strerror(length));
				audio_ts += 20000;	/* FIXME */
				continue;
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
			/* Prepare a MoQ object and send it */
			imquic_moq_object object = {
				.request_id = audio_request_id,
				.track_alias = audio_track_alias,
				.group_id = audio_group_id++,
				.subgroup_id = 0,	/* FIXME */
				.object_id = audio_object_id,
				.payload = outgoing,
				.payload_len = length,
				.properties = props,
				.delivery = IMQUIC_MOQ_USE_DATAGRAM,
				.end_of_stream = TRUE
			};
			imquic_moq_send_object(moq_conn, &object);
			g_list_free(props);
		}
	}

	IMQUIC_LOG(IMQUIC_LOG_INFO, "Leaving audio thread\n");
	return NULL;
}

static void *imquic_demo_video_capture_thread(void *user_data) {
	IMQUIC_LOG(IMQUIC_LOG_INFO, "Starting video capture thread\n");

	AVPacket packet = { 0 };
	AVFrame *video_frame = av_frame_alloc();

	while(!stop) {
		/* FIXME Loop */
		if(!g_atomic_int_get(&video_started)) {
			g_usleep(100000);
			continue;
		}

		/* Read from the video device */
		memset(&packet, 0, sizeof(packet));
		packet.pts = AV_NOPTS_VALUE;
		packet.dts = AV_NOPTS_VALUE;
		packet.pos = -1;
		int ret = av_read_frame(webcam_fmt, &packet);
		if(ret < 0) {
			av_packet_unref(&packet);
			IMQUIC_LOG(IMQUIC_LOG_ERR, "Error getting a frame from the video device: %d (%s)\n",
				ret, av_err2str(ret));
			break;
		}
		ret = avcodec_send_packet(webcam_ctx, &packet);
		if(ret < 0) {
			av_packet_unref(&packet);
			if(ret == AVERROR(EAGAIN)) {
				/* Decoder needs more input? */
				continue;
			}
			IMQUIC_LOG(IMQUIC_LOG_ERR, "Error decoding frame from the video device: %d (%s)\n",
				ret, av_err2str(ret));
			break;
		}
		while(TRUE) {
			ret = avcodec_receive_frame(webcam_ctx, video_frame);
			if(ret < 0) {
				if(ret != AVERROR(EAGAIN) && ret != AVERROR_EOF) {
					IMQUIC_LOG(IMQUIC_LOG_ERR, "Error decoding frame from the video device: %d (%s)\n",
						ret, av_err2str(ret));
				}
				break;
			}
			IMQUIC_LOG(IMQUIC_LOG_VERB, "Frame resolution: %dx%d\n",
				video_frame->width, video_frame->height);
			/* Convert the video frame to the right format */
			if(sws == NULL) {
				sws = sws_getContext(video_frame->width, video_frame->height, video_frame->format,
					video_frame->width, video_frame->height, AV_PIX_FMT_YUVA420P, SWS_BICUBIC, NULL, NULL, NULL);
			}
			AVFrame *scaled_frame = av_frame_alloc();
			scaled_frame->width = video_frame->width;
			scaled_frame->height = video_frame->height;
			scaled_frame->format = AV_PIX_FMT_YUVA420P;
			ret = av_image_alloc(scaled_frame->data, scaled_frame->linesize,
				scaled_frame->width, scaled_frame->height, AV_PIX_FMT_YUVA420P, 1);
			if(ret < 0) {
				IMQUIC_LOG(IMQUIC_LOG_ERR, "Error allocating video frame: %d (%s)\n",
					ret, av_err2str(ret));
				av_freep(&scaled_frame->data[0]);
				av_frame_free(&scaled_frame);
				break;
			}
			sws_scale(sws, (const uint8_t * const*)video_frame->data, video_frame->linesize,
				0, video_frame->height, scaled_frame->data, scaled_frame->linesize);
			/* Update the latest video frame, for the encoding thread */
			imquic_mutex_lock(&mutex);
			if(latest_frame != NULL) {
				av_freep(&latest_frame->data[0]);
				av_frame_free(&latest_frame);
			}
			latest_frame = scaled_frame;
			imquic_mutex_unlock(&mutex);
		}
		av_packet_unref(&packet);
	}
	av_frame_free(&video_frame);

	IMQUIC_LOG(IMQUIC_LOG_INFO, "Leaving video capture thread\n");
	return NULL;
}

static void *imquic_demo_video_enc_thread(void *user_data) {
	IMQUIC_LOG(IMQUIC_LOG_INFO, "Starting video encoding thread\n");

	AVPacket packet = { 0 };
	int64_t now = 0, before = 0, wait = G_USEC_PER_SEC/options.video_framerate;

	while(!stop) {
		/* FIXME Loop */
		if(!g_atomic_int_get(&video_started)) {
			g_usleep(100000);
			continue;
		}

		/* Check when it's time to produce a new video frame */
		now = g_get_monotonic_time();
		if(before == 0)
			before = now - wait;
		if((now - before) < (wait - 1000)) {
			usleep(1000);
			continue;
		}
		/* If we got here, it's time to encode a new video frame */
		before += wait;

		imquic_mutex_lock(&mutex);
		if(latest_frame == NULL) {
			/* No frame available yet */
			imquic_mutex_unlock(&mutex);
			continue;
		}
		/* Encode the video frame */
		memset(&packet, 0, sizeof(packet));
		packet.pts = AV_NOPTS_VALUE;
		packet.dts = AV_NOPTS_VALUE;
		packet.pos = -1;
		int ret = avcodec_send_frame(videoenc_ctx, latest_frame);
		imquic_mutex_unlock(&mutex);
		if(ret < 0) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "Error encoding video frame: %d (%s)\n",
				ret, av_err2str(ret));
		} else {
			ret = avcodec_receive_packet(videoenc_ctx, &packet);
			if(ret == AVERROR(EAGAIN)) {
				/* Encoder needs more input? */
				IMQUIC_LOG(IMQUIC_LOG_INFO, "Skipping encoding of video frame: %d (%s)\n",
					ret, av_err2str(ret));
				video_ts += wait;
				continue;
			} else if(ret < 0) {
				IMQUIC_LOG(IMQUIC_LOG_ERR, "Error encoding video frame: %d (%s)\n",
					ret, av_err2str(ret));
				video_ts += wait;
				continue;
			}
		}
		/* Video frame encoded */
		gboolean kf = (packet.flags & AV_PKT_FLAG_KEY);
		IMQUIC_LOG(IMQUIC_LOG_VERB, "  -- Encoded to %d bytes, %s\n",
			packet.size, kf ? "keyframe" : "NOT a keyframe");
		if(kf) {
			/* Keyframe, we'll start a new group */
			if(video_group_id > 0) {
				/* Close the previous stream first */
				imquic_moq_object object = {
					.request_id = video_request_id,
					.track_alias = video_track_alias,
					.group_id = video_group_id,
					.subgroup_id = 0,	/* FIXME */
					.object_id = video_object_id,
					.payload = NULL,
					.payload_len = 0,
					.properties = NULL,
					.delivery = IMQUIC_MOQ_USE_SUBGROUP,
					.end_of_stream = TRUE
				};
				imquic_moq_send_object(moq_conn, &object);
			}
			video_group_id++;
			video_object_id = 0;
		}
		/* Check if we need to switch from Annex-B to AVCC */
		if(codec == DEMO_H264_AVCC) {
			size_t annexb_offset = 0, index = 4, nal_size = 0;
			while((size_t)packet.size >= index) {
				if(packet.data[index] == 0x00 && packet.data[index+1] == 0x00 &&
						packet.data[index+2] == 0x00 && packet.data[3] == 0x01) {
					/* Found a start code, that determined the NAL size */
					nal_size = index - annexb_offset + 4;
					memcpy(packet.data + annexb_offset, &nal_size, 4);
					annexb_offset = index;
					index += 4;
				} else {
					index++;
				}
			}
			nal_size = packet.size - annexb_offset + 4;
			memcpy(packet.data + annexb_offset, &nal_size, 4);
		}
		/* Write the LOC info first as extensions */
		GList *props = NULL;
		imquic_moq_property timescale = { 0 };
		timescale.id = IMQUIC_MOQ_LOC_TIMESCALE;
		timescale.value.number = G_USEC_PER_SEC;
		props = g_list_append(props, &timescale);
		imquic_moq_property timestamp = { 0 };
		timestamp.id = IMQUIC_MOQ_LOC_TIMESTAMP;
		timestamp.value.number = video_ts;
		props = g_list_append(props, &timestamp);
		video_ts += wait;
		imquic_moq_property videoconfig = { 0 };
		uint8_t avcc_data[1500];
		if(kf && videoenc_ctx->extradata != NULL) {
			uint8_t *extradata = videoenc_ctx->extradata;
			size_t extradata_size = videoenc_ctx->extradata_size;
			if(codec == DEMO_H264_AVCC) {
				/* We need to convert the extradata to AVCC format */
				size_t avcc_size = imquic_demo_h264_spspps_to_avcc(avcc_data, videoenc_ctx->extradata, videoenc_ctx->extradata_size);
				if(avcc_size > 0) {
					extradata = avcc_data;
					extradata_size = avcc_size;
				}
			} else {
				/* Send the extradata as it is */
			}
			IMQUIC_LOG(IMQUIC_LOG_VERB, "Generated AVCC: %zu bytes\n    ", extradata_size);
			for(size_t i=0; i<extradata_size; ++i)
				IMQUIC_LOG(IMQUIC_LOG_VERB, "%02x", extradata[i]);
			videoconfig.id = IMQUIC_MOQ_LOC_VIDEO_CONFIG;
			videoconfig.value.data.buffer = extradata;
			videoconfig.value.data.length = extradata_size;
			props = g_list_append(props, &videoconfig);
		}
		/* Prepare a MoQ object and send it */
		imquic_moq_object object = {
			.request_id = video_request_id,
			.track_alias = video_track_alias,
			.group_id = video_group_id,
			.subgroup_id = 0,	/* FIXME */
			.object_id = video_object_id,
			.payload = packet.data,
			.payload_len = packet.size,
			.properties = props,
			.delivery = IMQUIC_MOQ_USE_SUBGROUP,
			.end_of_stream = FALSE
		};
		video_object_id++;
		imquic_moq_send_object(moq_conn, &object);
		g_list_free(props);
		av_packet_unref(&packet);
	}

	IMQUIC_LOG(IMQUIC_LOG_INFO, "Leaving video encoding thread\n");
	return NULL;
}

/* Callbacks */
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
	g_atomic_int_set(&connected, 1);
	/* Let's publish our namespace or publish right away */
	if(!options.publish) {
		/* We use PUBLISH_NAMESPACE + incoming SUBSCRIBE */
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Announcing namespace '%s'\n", imquic_get_connection_name(conn), pub_tns);
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s]  -- Will serve track '%s'\n", imquic_get_connection_name(conn), catalog_tn);
		if(options.audio_track_name != NULL)
			IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s]  -- Will serve track '%s'\n", imquic_get_connection_name(conn), audio_tn);
		if(options.video_track_name != NULL)
			IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s]  -- Will serve track '%s'\n", imquic_get_connection_name(conn), video_tn);
		moq_tns_request_id = imquic_moq_get_next_request_id(conn);
		imquic_moq_publish_namespace(conn, moq_tns_request_id, &pub_namespace[0], NULL);
	} else {
		/* We use PUBLISH */
		gboolean forward = FALSE;
		imquic_moq_request_parameters params;
		imquic_moq_request_parameters_init_defaults(&params);
		params.group_order_set = TRUE;
		params.group_order = IMQUIC_MOQ_ORDERING_ASCENDING;
		params.forward_set = TRUE;
		params.forward = forward;
		/* Catalog track */
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Publishing namespace/track '%s--%s'\n", imquic_get_connection_name(conn), pub_tns, catalog_tn);
		catalog_request_id = imquic_moq_get_next_request_id(conn);
		imquic_moq_publish(conn, catalog_request_id, &pub_namespace[0], &catalog_trackname, catalog_track_alias, &params, NULL);
		/* Audio track */
		if(options.audio_track_name != NULL) {
			IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Publishing namespace/track '%s--%s'\n", imquic_get_connection_name(conn), pub_tns, audio_tn);
			audio_request_id = imquic_moq_get_next_request_id(conn);
			imquic_moq_publish(conn, audio_request_id, &pub_namespace[0], &audio_trackname, audio_track_alias, &params, NULL);
		}
		/* Video track */
		if(options.video_track_name != NULL) {
			IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Publishing namespace/track '%s--%s'\n", imquic_get_connection_name(conn), pub_tns, video_tn);
			video_request_id = imquic_moq_get_next_request_id(conn);
			imquic_moq_publish(conn, video_request_id, &pub_namespace[0], &video_trackname, video_track_alias, &params, NULL);
		}
	}
}

static void imquic_demo_publish_namespace_accepted(imquic_connection *conn, uint64_t request_id, imquic_moq_request_parameters *parameters) {
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Publish Namespace '%"SCNu64"' accepted\n",
		imquic_get_connection_name(conn), request_id);
}

static void imquic_demo_publish_namespace_error(imquic_connection *conn, uint64_t request_id, imquic_moq_request_error_code error_code,
		const char *reason, uint64_t retry_interval, imquic_moq_redirect *redirect) {
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Got an error announcing namespace: error %d (%s)\n",
		imquic_get_connection_name(conn), error_code, reason);
	/* Stop here */
	g_atomic_int_inc(&stop);
}

static void imquic_demo_publish_accepted(imquic_connection *conn, uint64_t request_id, imquic_moq_request_parameters *parameters) {
	if(request_id == catalog_request_id) {
		/* Catalog track */
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Publish '%"SCNu64"' (catalog) accepted\n",
			imquic_get_connection_name(conn), request_id);
		g_atomic_int_set(&catalog_started, 1);
		return;
	}
	/* Audio or video */
	gboolean video = (options.video_track_name != NULL && request_id == video_request_id);
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Publish '%"SCNu64"' (%s) accepted\n",
		imquic_get_connection_name(conn), request_id, video ? "video" : "audio");
	/* Start sending objects */
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s]  -- Starting delivery of %s objects\n",
		imquic_get_connection_name(conn), video ? "video" : "audio");
	if(video)
		g_atomic_int_set(&video_started, 1);
	else
		g_atomic_int_set(&audio_started, 1);
}

static void imquic_demo_publish_error(imquic_connection *conn, uint64_t request_id, imquic_moq_request_error_code error_code,
		const char *reason, uint64_t retry_interval, imquic_moq_redirect *redirect) {
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Got an error publishing with ID %"SCNu64": error %d (%s)\n",
		imquic_get_connection_name(conn), request_id, error_code, reason);
	/* Stop here */
	g_atomic_int_inc(&stop);
}

static void imquic_demo_incoming_subscribe(imquic_connection *conn, uint64_t request_id,
		imquic_moq_namespace *tns, imquic_moq_track *tn, imquic_moq_request_parameters *parameters) {
	char tns_buffer[256], tn_buffer[256];
	const char *ns = imquic_moq_namespace_str(tns, tns_buffer, sizeof(tns_buffer), TRUE);
	if(!strcasecmp(ns, ".2e")) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] Reserved namespace\n", imquic_get_connection_name(conn));
		imquic_moq_reject_subscribe(conn, request_id, IMQUIC_MOQ_REQERR_DOES_NOT_EXIST, "Reserved namespace", 0, NULL);
		return;
	}
	const char *name = imquic_moq_track_str(tn, tn_buffer, sizeof(tn_buffer));
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Incoming subscribe for '%s--%s' (ID %"SCNu64")\n",
		imquic_get_connection_name(conn), ns, name, request_id);
	if(pub_tns == NULL || strcasecmp(ns, pub_tns)) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] Unknown namespace\n", imquic_get_connection_name(conn));
		imquic_moq_reject_subscribe(conn, request_id, IMQUIC_MOQ_REQERR_DOES_NOT_EXIST, "Unknown namespace", 0, NULL);
		return;
	}
	if(!strcasecmp(name, catalog_tn)) {
		/* Catalog track, accept the subscription */
		catalog_request_id = request_id;
		imquic_moq_accept_subscribe(conn, request_id, catalog_track_alias, NULL, NULL);
		g_atomic_int_set(&catalog_started, 1);
		return;
	}
	/* Audio or video */
	if(strcasecmp(name, audio_tn) && strcasecmp(name, video_tn)) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] Unknown track\n", imquic_get_connection_name(conn));
		imquic_moq_reject_subscribe(conn, request_id, IMQUIC_MOQ_REQERR_DOES_NOT_EXIST, "Unknown track", 0, NULL);
		return;
	}
	gboolean video = (options.video_track_name != NULL && !strcasecmp(name, video_tn));
	if(options.publish || (!video && g_atomic_int_get(&audio_started)) || (video && g_atomic_int_get(&video_started))) {
		/* FIXME In this demo, we only allow one subscriber at a time,
		 * as we expect a relay to mediate between us and subscribers */
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] We already have a %s subscriber\n",
			imquic_get_connection_name(conn), video ? "video" : "audio");
		imquic_moq_reject_subscribe(conn, request_id, IMQUIC_MOQ_REQERR_DUPLICATE_SUBSCRIPTION, "We already have a subscriber", 0, NULL);
		return;
	}
	/* TODO Check priority, filters, forwarding */
	if(parameters->group_order == IMQUIC_MOQ_ORDERING_DESCENDING) {
		/* We don't support descending mode yet */
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Descending group order unsupported, will send objects in ascending group order\n",
			imquic_get_connection_name(conn));
	}
	/* Check the filter */
	uint64_t filter_type = parameters->subscription_filter_set ?
		parameters->subscription_filter.type : IMQUIC_MOQ_FILTER_LARGEST_OBJECT;
	gboolean pub_started = g_atomic_int_get(video ? &video_started : &audio_started);
	static imquic_moq_location sub_start = { 0 }, sub_end = { 0 };
	sub_end.group = IMQUIC_MAX_VARINT;
	sub_end.object = IMQUIC_MAX_VARINT;
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s]  -- Requested filter type '%s'\n",
		imquic_get_connection_name(conn), imquic_moq_filter_type_str(filter_type));
	if(filter_type == IMQUIC_MOQ_FILTER_LARGEST_OBJECT) {
		sub_start.group = video ? video_group_id : audio_group_id;
		sub_start.object = video ? video_object_id : audio_object_id;
	} else if(filter_type == IMQUIC_MOQ_FILTER_NEXT_GROUP_START) {
		sub_start.group = (video ? video_group_id : audio_group_id) + 1;
		sub_start.object = 0;
	} else if(filter_type == IMQUIC_MOQ_FILTER_ABSOLUTE_START) {
		sub_start = parameters->subscription_filter.start_location;
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s]  -- -- Start location: [%"SCNu64"/%"SCNu64"]\n",
			imquic_get_connection_name(conn), sub_start.group, sub_start.object);
	} else if(filter_type == IMQUIC_MOQ_FILTER_ABSOLUTE_RANGE) {
		sub_start = parameters->subscription_filter.start_location;
		if(parameters->subscription_filter.end_group == 0)
			sub_end.group = IMQUIC_MAX_VARINT;
		else
			sub_end.group = parameters->subscription_filter.end_group - 1;
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s]  -- -- Start location: [%"SCNu64"/%"SCNu64"] --> End group [%"SCNu64"]\n",
			imquic_get_connection_name(conn), sub_start.group, sub_start.object, sub_end.group);
	}
	/* Accept the subscription */
	imquic_moq_request_parameters rparams;
	imquic_moq_request_parameters_init_defaults(&rparams);
	rparams.expires_set = TRUE;
	rparams.expires = 0;
	rparams.group_order_set = TRUE;
	rparams.group_order = IMQUIC_MOQ_ORDERING_ASCENDING;
	if(pub_started) {
		rparams.largest_object_set = TRUE;
		rparams.largest_object = sub_start;
	}
	imquic_moq_accept_subscribe(conn, request_id,
		video ? video_track_alias : audio_track_alias, &rparams, NULL);
	/* Start sending objects */
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s]  -- Starting delivery of %s objects: [%"SCNu64"/%"SCNu64"] --> [%"SCNu64"/%"SCNu64"]\n",
		imquic_get_connection_name(conn), video ? "video" : "audio",
		sub_start.group, sub_start.object, sub_end.group, sub_end.object);
	if(video) {
		video_request_id = request_id;
		video_sub_start = sub_start;
		video_sub_end = sub_end;
		g_atomic_int_set(&video_started, 1);
	} else {
		audio_request_id = request_id;
		audio_sub_start = sub_start;
		audio_sub_end = sub_end;
		g_atomic_int_set(&audio_started, 1);
	}
}

static void imquic_demo_incoming_unsubscribe(imquic_connection *conn, uint64_t request_id) {
	gboolean video = (options.video_track_name != NULL && request_id == video_request_id);
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Incoming unsubscribe for %s subscription %"SCNu64"\n",
		imquic_get_connection_name(conn), video ? "video" : "audio", request_id);
	/* Stop sending objects */
	if(video)
		g_atomic_int_set(&video_started, 0);
	else
		g_atomic_int_set(&audio_started, 0);
}

static void imquic_demo_incoming_go_away(imquic_connection *conn, const char *uri, uint64_t timeout) {
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

	/* Initialize SDL backends */
	if(SDL_Init(SDL_INIT_TIMER | SDL_INIT_AUDIO) < 0) {
		IMQUIC_LOG(IMQUIC_LOG_FATAL, "Error initializing SDL2: %s\n", SDL_GetError());
		goto done;
	}

	/* FFmpeg initialization */
#if (LIBAVFORMAT_VERSION_INT < AV_VERSION_INT(58,9,100))
	av_register_all();
#endif
	avdevice_register_all();
	if(options.debug_ffmpeg)
		av_log_set_level(AV_LOG_DEBUG);

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

	if(options.track_namespace == NULL && options.track_namespace[0] == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_FATAL, "Missing track namespace(s)\n");
		ret = 1;
		goto done;
	}
	int i = 0;
	while(options.track_namespace[i] != NULL) {
		const char *track_namespace = options.track_namespace[i];
		pub_namespace[i].buffer = (uint8_t *)track_namespace;
		pub_namespace[i].length = strlen(track_namespace);
		pub_namespace[i].next = (options.track_namespace[i+1] != NULL) ? &pub_namespace[i+1] : NULL;
		i++;
	}
	uint64_t tns_num = 0;
	if(!imquic_moq_namespace_is_valid(&pub_namespace[0], TRUE, &tns_num)) {
		IMQUIC_LOG(IMQUIC_LOG_FATAL, "Invalid track namespace\n");
		ret = 1;
		goto done;
	}
	pub_tns = imquic_moq_namespace_str(pub_namespace, pub_tns_buffer, sizeof(pub_tns_buffer), TRUE);
	IMQUIC_LOG(IMQUIC_LOG_INFO, "Using namespace '%s' (%"SCNu64" tuples)\n", pub_tns, tns_num);

	/* Create a catalog track */
	catalog_trackname.buffer = (uint8_t *)catalog_tn;
	catalog_trackname.length = strlen(catalog_tn);
	catalog = imquic_moq_catalog_create("draft-01");
	IMQUIC_LOG(IMQUIC_LOG_INFO, "Using track name '%s' for catalog\n", catalog_tn);
	IMQUIC_LOG(IMQUIC_LOG_INFO, "  -- Will use track_alias=%"SCNu64"\n",
		catalog_track_alias);

	if(options.audio_track_name == NULL || options.video_track_name == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_FATAL, "Missing track name(s)\n");
		ret = 1;
		goto done;
	}
	if(options.audio_track_name != NULL) {
		/* Create an audio track */
		audio_trackname.buffer = (uint8_t *)options.audio_track_name;
		audio_trackname.length = strlen(options.audio_track_name);
		if(!imquic_moq_track_is_valid(&audio_trackname)) {
			IMQUIC_LOG(IMQUIC_LOG_FATAL, "Invalid audio track name\n");
			ret = 1;
			goto done;
		}
		audio_tn = imquic_moq_track_str(&audio_trackname, audio_tn_buffer, sizeof(audio_tn_buffer));
		IMQUIC_LOG(IMQUIC_LOG_INFO, "Using track name '%s' for audio\n", audio_tn);
		IMQUIC_LOG(IMQUIC_LOG_INFO, "  -- Will use track_alias=%"SCNu64"\n",
			audio_track_alias);
		/* Add the audio track to the catalog */
		imquic_moq_catalog_track *track = imquic_moq_catalog_create_track(pub_tns, audio_tn, "loc", TRUE);
		track->role = g_strdup("audio");
		track->render_group = 1;
		track->target_latency = 200;
		track->codec = g_strdup("opus");
		track->samplerate = 48000;
		track->channel_config = g_strdup("1");
		track->bitrate = 32000;
		imquic_moq_catalog_add_track(catalog, track);
	}
	if(options.video_track_name != NULL) {
		/* Create a video track */
		video_trackname.buffer = (uint8_t *)options.video_track_name;
		video_trackname.length = strlen(options.video_track_name);
		if(!imquic_moq_track_is_valid(&video_trackname)) {
			IMQUIC_LOG(IMQUIC_LOG_FATAL, "Invalid video track name\n");
			ret = 1;
			goto done;
		}
		video_tn = imquic_moq_track_str(&video_trackname, video_tn_buffer, sizeof(video_tn_buffer));
		IMQUIC_LOG(IMQUIC_LOG_INFO, "Using track name '%s' for video\n", video_tn);
		IMQUIC_LOG(IMQUIC_LOG_INFO, "  -- Will use track_alias=%"SCNu64"\n",
			video_track_alias);
		if(options.video_format == NULL)
			options.video_format = "v4l2";
		IMQUIC_LOG(IMQUIC_LOG_INFO, "  -- Will use the '%s' video format\n", options.video_format);
		if(options.video_device == NULL)
			options.video_device = "/dev/video0";
		IMQUIC_LOG(IMQUIC_LOG_INFO, "  -- Will use the '%s' video device\n", options.video_device);
		if(options.video_resolution == NULL)
			options.video_resolution = "640x480";
		if(sscanf(options.video_resolution, "%dx%d", &options.width, &options.height) != 2 ||
				options.width <= 0 || options.height <= 0) {
			IMQUIC_LOG(IMQUIC_LOG_FATAL, "Invalid video resolution\n");
			ret = 1;
			goto done;
		}
		if(options.video_framerate <= 0)
			options.video_framerate = 25;
		IMQUIC_LOG(IMQUIC_LOG_INFO, "  -- Will capture video at '%dx%d@%d'\n",
			options.width, options.height, options.video_framerate);
		if(options.video_codec != NULL) {
			codec = imquic_demo_video_codec_from_str(options.video_codec);
			if(codec == DEMO_UNKOWN) {
				IMQUIC_LOG(IMQUIC_LOG_FATAL, "Unsupported video codec '%s'\n", options.video_codec);
				ret = 1;
				goto done;
			}
		}
		IMQUIC_LOG(IMQUIC_LOG_INFO, "  -- Will use video codec '%s'\n",
			imquic_demo_video_codec_str(codec));
		if(codec == DEMO_H264_AVCC || codec == DEMO_H264_ANNEXB) {
			/* FIXME Should we try openh264 too? */
			video_codec = (AVCodec *)avcodec_find_encoder_by_name("libx264");
		} else if(codec == DEMO_VP8) {
			video_codec = (AVCodec *)avcodec_find_encoder_by_name("libvpx");
		} else if(codec == DEMO_VP9) {
			video_codec = (AVCodec *)avcodec_find_encoder_by_name("libvpx-vp9");
		} else if(codec == DEMO_AV1) {
			video_codec = (AVCodec *)avcodec_find_encoder_by_name("libaom-av1");
		}
		if(video_codec == NULL) {
			IMQUIC_LOG(IMQUIC_LOG_FATAL, "Video codec '%s' not supported in provided libavcodec\n", options.video_codec);
			ret = 1;
			goto done;
		}
		/* Add the video track to the catalog */
		imquic_moq_catalog_track *track = imquic_moq_catalog_create_track(pub_tns, video_tn, "loc", TRUE);
		track->role = g_strdup("video");
		track->render_group = 1;
		track->target_latency = 200;
		if(codec == DEMO_H264_AVCC)
			track->codec = g_strdup("avc1.42001F");
		else if(codec == DEMO_H264_ANNEXB)	/* FIXME */
			track->codec = g_strdup("annexb.42001F");
		else if(codec == DEMO_VP8)
			track->codec = g_strdup("vp8");
		else if(codec == DEMO_VP9)	/* FIXME */
			track->codec = g_strdup("vp9");
		else if(codec == DEMO_AV1)	/* FIXME */
			track->codec = g_strdup("av1");
		track->width = options.width;
		track->height = options.height;
		track->framerate = options.video_framerate;
		track->bitrate = 1000 * 1024;
		imquic_moq_catalog_add_track(catalog, track);
	}

	if(options.publish)
		IMQUIC_LOG(IMQUIC_LOG_INFO, "Will use PUBLISH instead of PUBLISH_NAMESPACE + SUBSCRIBE\n");

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

	/* Initialize the library and create a client */
	if(imquic_init(options.secrets_log) < 0) {
		ret = 1;
		goto done;
	}

	/* Create encoders */
	if(options.audio_track_name != NULL && imquic_demo_create_audio_encoder() < 0) {
		g_atomic_int_set(&stop, 1);
		goto done;
	}
	if(options.video_track_name != NULL && imquic_demo_create_video_encoder() < 0) {
		g_atomic_int_set(&stop, 1);
		goto done;
	}

	/* Create a client endpoint */
	imquic_server *client = imquic_create_moq_client("moq-loc-send",
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
	imquic_set_publish_namespace_accepted_cb(client, imquic_demo_publish_namespace_accepted);
	imquic_set_publish_namespace_error_cb(client, imquic_demo_publish_namespace_error);
	imquic_set_publish_accepted_cb(client, imquic_demo_publish_accepted);
	imquic_set_publish_error_cb(client, imquic_demo_publish_error);
	imquic_set_incoming_subscribe_cb(client, imquic_demo_incoming_subscribe);
	imquic_set_incoming_unsubscribe_cb(client, imquic_demo_incoming_unsubscribe);
	imquic_set_incoming_goaway_cb(client, imquic_demo_incoming_go_away);
	imquic_set_connection_failed_cb(client, imquic_demo_connection_failed);
	imquic_set_moq_connection_gone_cb(client, imquic_demo_connection_gone);
	imquic_start_endpoint(client);

	while(!stop) {
		if(g_atomic_int_compare_and_exchange(&catalog_started, 1, 2)) {
			/* Send the catalog */
			char *json = imquic_moq_catalog_serialize(catalog);
			if(json != NULL) {
				imquic_moq_object object = {
					.request_id = catalog_request_id,
					.track_alias = catalog_track_alias,
					.group_id = 0,	/* FIXME */
					.subgroup_id = 0,
					.object_id = 0,
					.payload = (uint8_t *)json,
					.payload_len = strlen(json),
					.delivery = IMQUIC_MOQ_USE_SUBGROUP,
					.end_of_stream = TRUE
				};
				imquic_moq_send_object(moq_conn, &object);
				g_free(json);
			}
		}
		g_usleep(100000);
	}

	/* We're done, check if we need to send a PUBLISH_DONE and/or an PUBLISH_NAMESPACE_DONE */
	if(g_atomic_int_get(&catalog_started) && !g_atomic_int_get(&catalog_done)) {
		IMQUIC_LOG(IMQUIC_LOG_INFO, "Sending PUBLISH_DONE for catalog\n");
		imquic_moq_publish_done(moq_conn, catalog_request_id, IMQUIC_MOQ_PUBDONE_SUBSCRIPTION_ENDED, "Publisher left");
	}
	if(g_atomic_int_get(&audio_started) && !g_atomic_int_get(&audio_done)) {
		IMQUIC_LOG(IMQUIC_LOG_INFO, "Sending PUBLISH_DONE for audio\n");
		imquic_moq_publish_done(moq_conn, audio_request_id, IMQUIC_MOQ_PUBDONE_SUBSCRIPTION_ENDED, "Publisher left");
	}
	if(g_atomic_int_get(&video_started) && !g_atomic_int_get(&video_done)) {
		IMQUIC_LOG(IMQUIC_LOG_INFO, "Sending PUBLISH_DONE for video\n");
		imquic_moq_publish_done(moq_conn, video_request_id, IMQUIC_MOQ_PUBDONE_SUBSCRIPTION_ENDED, "Publisher left");
	}
	if(!options.publish) {
		IMQUIC_LOG(IMQUIC_LOG_INFO, "Sending PUBLISH_NAMESPACE_DONE\n");
		imquic_moq_publish_namespace_done(moq_conn, moq_tns_request_id);
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
	if(audio_thread != NULL)
		g_thread_join(audio_thread);
	if(video_capture_thread != NULL)
		g_thread_join(video_capture_thread);
	if(video_enc_thread != NULL)
		g_thread_join(video_enc_thread);
	if(latest_frame != NULL) {
		av_freep(&latest_frame->data[0]);
		av_frame_free(&latest_frame);
	}
	avformat_network_deinit();
	imquic_demo_destroy_audio_encoder();
	imquic_demo_destroy_video_encoder();

	/* SDL stuff */
	SDL_Quit();

	/* Done */
	IMQUIC_PRINT("Bye!\n");
	exit(ret);
}
