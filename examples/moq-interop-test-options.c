/*
 * imquic
 *
 * Author:  Lorenzo Miniero <lorenzo@meetecho.com>
 * License: MIT
 *
 * Command line options for imquic-moq-interop-test
 *
 */

#include "moq-interop-test-options.h"

static GOptionContext *opts = NULL;

gboolean demo_options_parse(demo_options *options, int argc, char *argv[]) {
	/* Supported command-line arguments */
	GOptionEntry opt_entries[] = {
		{ "relay", 'r', 0, G_OPTION_ARG_STRING, &options->relay, "Relay URL (default: https://localhost:4443)", "<URL>" },
		{ "test", 't', 0, G_OPTION_ARG_STRING, &options->test, "Run specific test (omit to run all)", "<NAME>" },
		{ "list", 'l', 0, G_OPTION_ARG_NONE, &options->list, "List available tests", NULL },
		{ "verbose", 'v', 0, G_OPTION_ARG_NONE, &options->verbose, "Verbose output", NULL },
		{ "tls-disable-verify", 0, 0, G_OPTION_ARG_NONE, &options->no_verify, "Disable TLS certificate verification", NULL },
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
