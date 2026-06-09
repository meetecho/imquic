/*
 * imquic
 *
 * Author:  Lorenzo Miniero <lorenzo@meetecho.com>
 * License: MIT
 *
 * A few helpers and utilities that are helpful in most/all MoQ examples
 *
 */

#ifndef MOQ_UTILS
#define MOQ_UTILS

#include <glib.h>

#include <imquic/imquic.h>
#include <imquic/moq.h>

/* Helper to duplicate an object */
imquic_moq_object *imquic_moq_object_duplicate(imquic_moq_object *object);
/* Helper to destroy a duplicated object */
void imquic_moq_object_cleanup(imquic_moq_object *object);

/* Helper to print a list of properties */
void imquic_moq_properties_print(imquic_moq_version version, int level, GList *properties);
/* Helper to duplicate a list of properties */
GList *imquic_moq_properties_duplicate(GList *properties);
/* Helper to destroy an object property */
void imquic_moq_property_cleanup(imquic_moq_property *property);

/* Helpers to deal with auth info */
int imquic_moq_auth_info_to_bytes(imquic_connection *conn, const char *auth_info, uint8_t *auth, size_t *authlen);
void imquic_moq_print_auth_info(imquic_connection *conn, uint8_t *auth, size_t authlen);
gboolean imquic_moq_check_auth_info(imquic_connection *conn, const char *auth_info, uint8_t *auth, size_t authlen);

/* How to process the payload */
typedef enum imquic_demo_payload_type {
	DEMO_TYPE_NONE = 0,	/* Don't print the object payload */
	DEMO_TYPE_TEXT,		/* Print the object payload as text */
	DEMO_TYPE_HEX,		/* Print the object payload as a hex string */
	DEMO_TYPE_LOC,		/* Parse the object payload as LOC (moq-encoder-player's version) */
	DEMO_TYPE_MP4		/* Save the object payload to an mp4 file (moq-rs's version) */
} imquic_demo_payload_type;
const char *imquic_demo_payload_type_str(imquic_demo_payload_type type);

/* Video codecs */
typedef enum imquic_demo_video_codec {
	DEMO_UNKOWN = 0,	/* Unknown codec */
	DEMO_H264_AVCC,		/* H.264 using AVCC format */
	DEMO_H264_ANNEXB,	/* H.264 using Annex-B format */
	DEMO_VP8,			/* VP8 */
	DEMO_VP9,			/* VP9 */
	DEMO_AV1,			/* AV1 */
} imquic_demo_video_codec;
const char *imquic_demo_video_codec_str(imquic_demo_video_codec codec);
imquic_demo_video_codec imquic_demo_video_codec_from_str(const char *codec);

/* Keyframe detection */
gboolean imquic_demo_h264_is_keyframe(uint8_t *buffer, size_t len);
gboolean imquic_demo_vp8_is_keyframe(uint8_t *buffer, size_t len);
gboolean imquic_demo_vp9_is_keyframe(uint8_t *buffer, size_t len);
gboolean imquic_demo_av1_is_keyframe(uint8_t *buffer, size_t len);

#endif
