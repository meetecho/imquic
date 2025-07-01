/*
 * imquic
 *
 * Author:  Lorenzo Miniero <lorenzo@meetecho.com>
 * License: MIT
 *
 * Command line options for imquic-moq-sub
 *
 */

#ifndef MOQ_SUB_OPTIONS
#define MOQ_SUB_OPTIONS

#include <stdint.h>

#include <glib.h>

/*! \brief Struct containing the parsed command line options */
typedef struct demo_options {
	char *moq_version;
	const char **track_namespace;
	const char **track_name;
	const char *relay_auth_info;
	const char *auth_info;
	gboolean subscribe_announces;
	const char *filter_type;
	uint64_t start_group;
	uint64_t start_object;
	uint64_t end_group;
	uint64_t end_object;
	int update_subscribe;
	const char *fetch;
	int join_offset;
	const char *media_type;
	const char *target_file;
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
	const char *cert_pwd;
	const char *ticket_file;
	const char *secrets_log;
	const char *qlog_path;
	const char **qlog_logging;
	gboolean qlog_sequential;
	int debug_level;
	gboolean debug_locks;
	gboolean debug_refcounts;
} demo_options;

/* Helper method to parse the command line options */
gboolean demo_options_parse(demo_options *opts, int argc, char *argv[]);

/* Helper method to show the application usage */
void demo_options_show_usage(void);

/*! Helper method to get rid of the options parser resources */
void demo_options_destroy(void);

#endif
