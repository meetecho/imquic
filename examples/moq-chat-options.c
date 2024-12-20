/*
 * imquic
 *
 * Author:  Lorenzo Miniero <lorenzo@meetecho.com>
 * License: MIT
 *
 * Command line options for imquic-moq-chat
 *
 */

#include "moq-chat-options.h"

static GOptionContext *opts = NULL;

gboolean demo_options_parse(demo_options *options, int argc, char *argv[]) {
	/* Supported command-line arguments */
	GOptionEntry opt_entries[] = {
		{ "moq-draft-version", 'M', 0, G_OPTION_ARG_STRING, &options->moq_version, "MoQ draft version number to negotiate (default=any)", "<number>|any|legacy" },
		{ "id", 'i', 0, G_OPTION_ARG_STRING, &options->id, "Chat ID (default=none)", "string" },
		{ "user-id", 'u', 0, G_OPTION_ARG_STRING, &options->user_id, "User ID (default=none)", "string" },
		{ "auth-info", 'a', 0, G_OPTION_ARG_STRING, &options->auth_info, "Auth info to subscribe, if needed (default=none)", "string" },
		//~ { "fetch", 'f', 0, G_OPTION_ARG_STRING, &options->fetch, "Use FETCH instead of SUBSCRIBE, in the specified order (ascending/descending)", "order" },
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
