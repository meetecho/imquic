/*
 * imquic
 *
 * Author:  Lorenzo Miniero <lorenzo@meetecho.com>
 * License: MIT
 *
 * Command line options for imquic-moq-chat
 *
 */

#ifndef MOQ_CHAT_OPTIONS
#define MOQ_CHAT_OPTIONS

#include <glib.h>

/*! \brief Struct containing the parsed command line options */
typedef struct demo_options {
	char *moq_version;
	char *id;
	char *user_id;
	const char *auth_info;
	//~ const char *fetch;
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
