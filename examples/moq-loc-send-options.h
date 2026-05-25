/*
 * imquic
 *
 * Author:  Lorenzo Miniero <lorenzo@meetecho.com>
 * License: MIT
 *
 * Command line options for imquic-moq-loc-send
 *
 */

#ifndef MOQ_LOC_SEND_OPTIONS
#define MOQ_LOC_SEND_OPTIONS

#include <stdint.h>

#include <glib.h>

/*! \brief Struct containing the parsed command line options */
typedef struct demo_options {
	char *moq_version;
	gboolean test_grease;
	const char **track_namespace;
	const char *audio_track_name;
	const char *video_track_name;
	const char *video_format;
	const char *video_device;
	const char *video_resolution;
	int width, height;
	int video_framerate;
	gboolean publish;
	const char *ip;
	int port;
	const char *remote_host;
	int remote_port;
	const char *sni;
	gboolean raw_quic;
	gboolean webtransport;
	const char *path;
	const char *cert_pem;
	const char *cert_key;
	const char *ticket_file;
	const char *secrets_log;
	const char *qlog_path;
	const char **qlog_logging;
	gboolean qlog_sequential;
	gboolean qlog_moq_messages;
	gboolean qlog_moq_objects;
	int debug_level;
	gboolean debug_locks;
	gboolean debug_refcounts;
	gboolean debug_ffmpeg;
} demo_options;

/* Helper method to parse the command line options */
gboolean demo_options_parse(demo_options *opts, int argc, char *argv[]);

/* Helper method to show the application usage */
void demo_options_show_usage(void);

/*! Helper method to get rid of the options parser resources */
void demo_options_destroy(void);

#endif
