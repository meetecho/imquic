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

/* Object/LOC processing type */
typedef enum imquic_demo_payload_type {
	DEMO_TYPE_NONE = 0,	/* Don't print the object payload */
	DEMO_TYPE_TEXT,		/* Print the object payload as text */
	DEMO_TYPE_HEX,		/* Print the object payload as a hex string */
	DEMO_TYPE_LOC,		/* Parse the object payload as LOC (moq-encoder-player's version) */
	DEMO_TYPE_MP4		/* Save the object payload to an mp4 file (moq-rs's version) */
} imquic_demo_payload_type;
const char *imquic_demo_payload_type_str(imquic_demo_payload_type type);

typedef enum imquic_demo_media_type {
	DEMO_MEDIA_NONE = 0xFF,		/* Unknown */
	DEMO_MEDIA_H264 = 0x0,		/* H264/AVCC video */
	DEMO_MEDIA_OPUS = 0x1,		/* Opus audio */
	DEMO_MEDIA_TEXT = 0x2,		/* UTF-8 text */
	DEMO_MEDIA_AAC = 0x3,		/* AAC-LC audio */
} imquic_demo_media_type;
const char *imquic_demo_media_type_str(imquic_demo_media_type type);

typedef enum imquic_demo_loc_property {
	DEMO_LOC_MEDIA_TYPE = 0x0A,		/* Media type header property */
	DEMO_LOC_H264_HEADER = 0x0B,	/* Video H264 in AVCC metadata (TODO change to 0x15) */
	DEMO_LOC_H264_EXTRADATA = 0x0D,	/* Video H264 in AVCC extradata */
	DEMO_LOC_OPUS_HEADER = 0x0F,	/* Audio Opus bitstream data */
	DEMO_LOC_AAC_HEADER = 0x13,		/* Audio AAC-LC in MPEG4 bitstream data */
} imquic_demo_loc_property;
const char *imquic_demo_loc_property_str(imquic_demo_loc_property type);

#endif
