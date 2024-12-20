/*! \file   error.c
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright MIT License
 * \brief  QUIC errors definitions
 * \details Definitions for QUIC errors, and helper functions to use them.
 *
 * \ingroup Core
 */

#include <stddef.h>

#include "internal/error.h"

const char *imquic_error_code_str(imquic_error_code type) {
	switch(type) {
		case IMQUIC_NO_ERROR:
			return "NO_ERROR";
		case IMQUIC_INTERNAL_ERROR:
			return "INTERNAL_ERROR";
		case IMQUIC_CONNECTION_REFUSED:
			return "CONNECTION_REFUSED";
		case IMQUIC_FLOW_CONTROL_ERROR:
			return "FLOW_CONTROL_ERROR";
		case IMQUIC_STREAM_LIMIT_ERROR:
			return "STREAM_LIMIT_ERROR";
		case IMQUIC_STREAM_STATE_ERROR:
			return "STREAM_STATE_ERROR";
		case IMQUIC_FINAL_SIZE_ERROR:
			return "FINAL_SIZE_ERROR";
		case IMQUIC_FRAME_ENCODING_ERROR:
			return "FRAME_ENCODING_ERROR";
		case IMQUIC_TRANSPORT_PARAMETER_ERROR:
			return "TRANSPORT_PARAMETER_ERROR";
		case IMQUIC_CONNECTION_ID_LIMIT_ERROR:
			return "CONNECTION_ID_LIMIT_ERROR";
		case IMQUIC_PROTOCOL_VIOLATION:
			return "PROTOCOL_VIOLATION";
		case IMQUIC_INVALID_TOKEN:
			return "INVALID_TOKEN";
		case IMQUIC_APPLICATION_ERROR:
			return "APPLICATION_ERROR";
		case IMQUIC_CRYPTO_BUFFER_EXCEEDED:
			return "CRYPTO_BUFFER_EXCEEDED";
		case IMQUIC_KEY_UPDATE_ERROR:
			return "KEY_UPDATE_ERROR";
		case IMQUIC_AEAD_LIMIT_REACHED:
			return "AEAD_LIMIT_REACHED";
		case IMQUIC_NO_VIABLE_PATH:
			return "NO_VIABLE_PATH";
		case IMQUIC_CRYPTO_ERROR:
			return "CRYPTO_ERROR";
		default: break;
	}
	return NULL;
}

