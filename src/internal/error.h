/*! \file   error.h
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright MIT License
 * \brief  QUIC errors definitions (headers)
 * \details Definitions for QUIC errors, and helper functions to use them.
 *
 * \ingroup Core
 */

#ifndef IMQUIC_ERROR_H
#define IMQUIC_ERROR_H

/*! \brief QUIC error codes */
typedef enum imquic_error_code {
	IMQUIC_NO_ERROR = 0x00,
	IMQUIC_INTERNAL_ERROR = 0x01,
	IMQUIC_CONNECTION_REFUSED = 0x02,
	IMQUIC_FLOW_CONTROL_ERROR = 0x03,
	IMQUIC_STREAM_LIMIT_ERROR = 0x04,
	IMQUIC_STREAM_STATE_ERROR = 0x05,
	IMQUIC_FINAL_SIZE_ERROR = 0x06,
	IMQUIC_FRAME_ENCODING_ERROR = 0x07,
	IMQUIC_TRANSPORT_PARAMETER_ERROR = 0x08,
	IMQUIC_CONNECTION_ID_LIMIT_ERROR = 0x09,
	IMQUIC_PROTOCOL_VIOLATION = 0x0A,
	IMQUIC_INVALID_TOKEN = 0x0B,
	IMQUIC_APPLICATION_ERROR = 0x0C,
	IMQUIC_CRYPTO_BUFFER_EXCEEDED = 0x0D,
	IMQUIC_KEY_UPDATE_ERROR = 0x0E,
	IMQUIC_AEAD_LIMIT_REACHED = 0x0F,
	IMQUIC_NO_VIABLE_PATH = 0x10,
	IMQUIC_CRYPTO_ERROR = 0x0100
} imquic_error_code;
/*! \brief Helper function to serialize to string the name of a imquic_error_code value.
 * @param type The imquic_error_code value
 * @returns The code name as a string, if valid, or NULL otherwise */
const char *imquic_error_code_str(imquic_error_code type);

#endif
