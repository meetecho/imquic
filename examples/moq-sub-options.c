/*
 * imquic
 *
 * Author:  Lorenzo Miniero <lorenzo@meetecho.com>
 * License: MIT
 *
 * Command line options for imquic-moq-sub
 *
 */

#include "moq-sub-options.h"

static GOptionContext *opts = NULL;

gboolean demo_options_parse(demo_options *options, int argc, char *argv[]) {
	/* Supported command-line arguments */
	GOptionEntry opt_entries[] = {
		{ "moq-draft-version", 'M', 0, G_OPTION_ARG_STRING, &options->moq_version, "MoQ draft version number to negotiate (default=any)", "<number>|any|legacy" },
		{ "track-namespace", 'n', 0, G_OPTION_ARG_STRING_ARRAY, &options->track_namespace, "MoQ track namespace to subscribe to (can be called multiple times to create a tuple; default=none)", "namespace" },
		{ "track-name", 'N', 0, G_OPTION_ARG_STRING_ARRAY, &options->track_name, "MoQ track name to subscribe to (can be called multiple times to subscribe to multiple tracks; default=none)", "name" },
		{ "relay-auth-info", 'A', 0, G_OPTION_ARG_STRING, &options->relay_auth_info, "Auth info required to connect to the relay, if any (default=none)", "string" },
		{ "auth-info", 'a', 0, G_OPTION_ARG_STRING, &options->auth_info, "Auth info to subscribe, if needed (default=none)", "string" },
		{ "subscribe-announces", 'B', 0, G_OPTION_ARG_NONE, &options->subscribe_announces, "If set, will only send a SUBSCRIBE_ANNOUNCES instead of a SUBSCRIBE, and will expect a PUBLISH from the relay (default=no)", "order" },
		{ "filter-type", 'F', 0, G_OPTION_ARG_STRING, &options->filter_type, "Filter type to use for SUBSCRIBE (default=LargestObject)", "LargestObject|NextGroupStart|AbsoluteStart|AbsoluteRange" },
		{ "fetch", 'f', 0, G_OPTION_ARG_STRING, &options->fetch, "Use FETCH instead of SUBSCRIBE/PUBLISH, in the specified order (ascending/descending)", "order" },
		{ "join", 'j', 0, G_OPTION_ARG_INT, &options->join_offset, "When using FETCH, use a Joining Fetch and get the specified number of preceding groups (default=-1, no joining fetch)", "offset" },
		{ "start-group", 'g', 0, G_OPTION_ARG_INT64, &options->start_group, "Group to start from, for Standalone FETCH or when using specific filters in SUBSCRIBE (default=0)", "id" },
		{ "start-object", 'o', 0, G_OPTION_ARG_INT64, &options->start_object, "Object to start from, for Standalone FETCH or when using specific filters in SUBSCRIBE (default=0)", "id" },
		{ "end-group", 'G', 0, G_OPTION_ARG_INT64, &options->end_group, "Group to end at, for Standalone FETCH or when using specific filters in SUBSCRIBE (default=maximum, maximum)", "id" },
		{ "end-object", 'O', 0, G_OPTION_ARG_INT64, &options->end_object, "Object to end at, for Standalone FETCH or when using specific filters in SUBSCRIBE (default=maximum)", "id" },
		{ "update-subscribe", 'u', 0, G_OPTION_ARG_INT, &options->update_subscribe, "When using SUSBCRIBE, disable forwarding at first, and send a SUBSCRIBE_UPDATE after a few seconds (default=-1, get objects right away)", "seconds" },
		{ "media-type", 't', 0, G_OPTION_ARG_STRING, &options->media_type, "Kind of media to subscribe to (default=none)", "none|text|hex|loc|mp4" },
		{ "target-file", 'T', 0, G_OPTION_ARG_STRING, &options->target_file, "File to save MoQ object payloads to (default=none)", "path" },
		{ "bind", 'b', 0, G_OPTION_ARG_STRING, &options->ip, "Local IP address to bind to (default=all interfaces)", "IP" },
		{ "port", 'p', 0, G_OPTION_ARG_INT, &options->port, "Local port to bind to (default=0, random)", "port" },
		{ "remote-host", 'r', 0, G_OPTION_ARG_STRING, &options->remote_host, "QUIC server to connect to (default=none)", "IP" },
		{ "remote-port", 'R', 0, G_OPTION_ARG_INT, &options->remote_port, "Port of the QUIC server (default=none)", "port" },
		{ "sni", 'S', 0, G_OPTION_ARG_STRING, &options->sni, "SNI to use (default=localhost)", "sni" },
		{ "raw-quic", 'q', 0, G_OPTION_ARG_NONE, &options->raw_quic, "Whether raw QUIC should be offered for the MoQ connection or not (default=no)", NULL },
		{ "webtransport", 'w', 0, G_OPTION_ARG_NONE, &options->webtransport, "Whether WebTransport should be offered for the MoQ connection or not (default=no)", NULL },
		{ "path", 'H', 0, G_OPTION_ARG_STRING, &options->path, "In case WebTransport is used, path to use for the HTTP/3 request (default=/)", "HTTP/3 path" },
		{ "cert-pem", 'c', 0, G_OPTION_ARG_STRING, &options->cert_pem, "Certificate to use (default=none)", "path" },
		{ "cert-key", 'k', 0, G_OPTION_ARG_STRING, &options->cert_key, "Certificate key to use (default=none)", "path" },
		{ "cert-pwd", 'P', 0, G_OPTION_ARG_STRING, &options->cert_pwd, "Certificate password to use (default=none)", "string" },
		{ "zero-rtt", '0', 0, G_OPTION_ARG_STRING, &options->ticket_file, "Whether early data via 0-RTT should be supported, and what file to use for writing/reading the session ticket (default=none)", "path" },
		{ "secrets-log", 's', 0, G_OPTION_ARG_STRING, &options->secrets_log, "Save the exchanged secrets to a file compatible with Wireshark (default=none)", "path" },
		{ "qlog-path", 'Q', 0, G_OPTION_ARG_STRING, &options->qlog_path, "Save a QLOG file for this connection (default=none)", "path" },
		{ "qlog-logging", 'l', 0, G_OPTION_ARG_STRING_ARRAY, &options->qlog_logging, "Save these events to QLOG (can be called multiple times to save multiple things; default=none)", "quic|http3|moq" },
		{ "qlog-sequential", 'J', 0, G_OPTION_ARG_NONE, &options->qlog_sequential, "Whether sequential JSON should be used for the QLOG file, instead of regular JSON (default=no)", NULL },
		{ "debug-level", 'd', 0, G_OPTION_ARG_INT, &options->debug_level, "Debug/logging level (0=disable debugging, 7=maximum debug level; default=4)", "1-7" },
		{ "debug-locks", 'L', 0, G_OPTION_ARG_NONE, &options->debug_locks, "Whether to verbosely debug mutex/lock accesses (default=no)", NULL },
		{ "debug-refcounts", 'C', 0, G_OPTION_ARG_NONE, &options->debug_refcounts, "Whether to verbosely debug reference counting (default=no)", NULL },
		{ NULL, 0, 0, 0, NULL, NULL, NULL },
	};

	/* Parse the command-line arguments */
	GError *error = NULL;
	opts = g_option_context_new("");
	g_option_context_set_help_enabled(opts, TRUE);
	g_option_context_add_main_entries(opts, opt_entries, NULL);
	if(!g_option_context_parse(opts, &argc, &argv, &error)) {
		g_print("%s\n", error->message);
		g_error_free(error);
		demo_options_destroy();
		return FALSE;
	}

	/* Done */
	return TRUE;
}

void demo_options_show_usage(void) {
	if(opts == NULL)
		return;
	char *help = g_option_context_get_help(opts, TRUE, NULL);
	g_print("\n%s", help);
	g_free(help);
}

void demo_options_destroy(void) {
	if(opts != NULL)
		g_option_context_free(opts);
	opts = NULL;
}
