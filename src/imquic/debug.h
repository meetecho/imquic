/*! \file    debug.h
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright MIT License
 * \brief    Logging and Debugging
 * \details  Implementation of a wrapper on printf (or g_print) to either log or debug.
 *
 * \ingroup API Core
 */

#ifndef IMQUIC_DEBUG_H
#define IMQUIC_DEBUG_H

#include <inttypes.h>

#include <glib.h>
#include <glib/gprintf.h>

extern int imquic_log_level;
extern gboolean imquic_log_timestamps;
extern gboolean imquic_log_colors;

#define IMQUIC_MAX_VARINT (((uint64_t)1 << 62) - 1)

/** @name imquic log colors
 */
///@{
#define IMQUIC_ANSI_COLOR_RED     "\x1b[31m"
#define IMQUIC_ANSI_COLOR_GREEN   "\x1b[32m"
#define IMQUIC_ANSI_COLOR_YELLOW  "\x1b[33m"
#define IMQUIC_ANSI_COLOR_BLUE    "\x1b[34m"
#define IMQUIC_ANSI_COLOR_MAGENTA "\x1b[35m"
#define IMQUIC_ANSI_COLOR_CYAN    "\x1b[36m"
#define IMQUIC_ANSI_COLOR_RESET   "\x1b[0m"
///@}

/** @name imquic log levels
 */
///@{
/*! \brief No debugging */
#define IMQUIC_LOG_NONE     (0)
/*! \brief Fatal error */
#define IMQUIC_LOG_FATAL    (1)
/*! \brief Non-fatal error */
#define IMQUIC_LOG_ERR      (2)
/*! \brief Warning */
#define IMQUIC_LOG_WARN     (3)
/*! \brief Informational message */
#define IMQUIC_LOG_INFO     (4)
/*! \brief Verbose message */
#define IMQUIC_LOG_VERB     (5)
/*! \brief Overly verbose message */
#define IMQUIC_LOG_HUGE     (6)
/*! \brief Debug message (includes .c filename, function and line number) */
#define IMQUIC_LOG_DBG      (7)
/*! \brief Maximum level of debugging */
#define IMQUIC_LOG_MAX IMQUIC_LOG_DBG

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"
/*! \brief Coloured prefixes for errors and warnings logging. */
static const char *imquic_log_prefix[] = {
/* no colors */
	"",
	"[FATAL] ",
	"[ERR] ",
	"[WARN] ",
	"",
	"",
	"",
	"",
/* with colors */
	"",
	IMQUIC_ANSI_COLOR_MAGENTA"[FATAL]"IMQUIC_ANSI_COLOR_RESET" ",
	IMQUIC_ANSI_COLOR_RED"[ERR]"IMQUIC_ANSI_COLOR_RESET" ",
	IMQUIC_ANSI_COLOR_YELLOW"[WARN]"IMQUIC_ANSI_COLOR_RESET" ",
	"",
	"",
	"",
	""
};
///@}
#pragma GCC diagnostic pop

/** @name imquic log wrappers
 */
///@{
/*! \brief Simple wrapper to g_print/printf */
#define IMQUIC_PRINT g_print
/*! \brief Logger based on different levels, which can either be displayed
 * or not according to the configuration of the server.
 * The format must be a string literal. */
#define IMQUIC_LOG(level, format, ...) \
do { \
	if (level > IMQUIC_LOG_NONE && level <= IMQUIC_LOG_MAX && level <= imquic_log_level) { \
		char imquic_log_ts[64] = ""; \
		char imquic_log_src[128] = ""; \
		if (imquic_log_timestamps) { \
			struct tm imquictmresult; \
			time_t imquicltime = time(NULL); \
			localtime_r(&imquicltime, &imquictmresult); \
			strftime(imquic_log_ts, sizeof(imquic_log_ts), \
			         "[%a %b %e %T %Y] ", &imquictmresult); \
		} \
		if (level == IMQUIC_LOG_FATAL || level == IMQUIC_LOG_ERR || level == IMQUIC_LOG_DBG) { \
			snprintf(imquic_log_src, sizeof(imquic_log_src), \
			         "[%s:%s:%d] ", __FILE__, __FUNCTION__, __LINE__); \
		} \
		g_print("%s%s%s" format, \
		        imquic_log_ts, \
		        imquic_log_prefix[level | ((int)imquic_log_colors << 3)], \
		        imquic_log_src, \
		        ##__VA_ARGS__); \
	} \
} while (0)
///@}

#endif
