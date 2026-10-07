#include "internal/moq.h"

static void test_var_int(void) {
	/* Reading var-int */
	uint8_t length = 0;
	uint8_t num1[] = { 0x25 };
	uint64_t expected1 = 37;
	uint64_t value1 = imquic_read_moqint(IMQUIC_MOQ_VERSION_MAX, num1, sizeof(num1), &length);
	g_assert_true(length != 0);
	g_assert_cmpuint(value1, ==, expected1);
	uint8_t num2[] = { 0x80, 0x25 };
	uint64_t expected2 = 37;
	uint64_t value2 = imquic_read_moqint(IMQUIC_MOQ_VERSION_MAX, num2, sizeof(num2), &length);
	g_assert_true(length != 0);
	g_assert_cmpuint(value2, ==, expected2);
	uint8_t num3[] = { 0xbb, 0xbd };
	uint64_t expected3 = 15293;
	uint64_t value3 = imquic_read_moqint(IMQUIC_MOQ_VERSION_MAX, num3, sizeof(num3), &length);
	g_assert_true(length != 0);
	g_assert_cmpuint(value3, ==, expected3);
	uint8_t num4[] = { 0xed, 0x7f, 0x3e, 0x7d };
	uint64_t expected4 = 226442877;
	uint64_t value4 = imquic_read_moqint(IMQUIC_MOQ_VERSION_MAX, num4, sizeof(num4), &length);
	g_assert_true(length != 0);
	g_assert_cmpuint(value4, ==, expected4);
	uint8_t num5[] = { 0xfa, 0xa1, 0xa0, 0xe4, 0x03, 0xd8 };
	uint64_t expected5 = 2893212287960;
	uint64_t value5 = imquic_read_moqint(IMQUIC_MOQ_VERSION_MAX, num5, sizeof(num5), &length);
	g_assert_true(length != 0);
	g_assert_cmpuint(value5, ==, expected5);
	uint8_t num6[] = { 0xfc, 0x89, 0x98, 0xab, 0xc6, 0x6b, 0xc0 };
	uint64_t expected6 = 151288809941952;
	uint64_t value6 = imquic_read_moqint(IMQUIC_MOQ_VERSION_MAX, num6, sizeof(num6), &length);
	g_assert_true(length != 0);
	g_assert_cmpuint(value6, ==, expected6);

	/* Writing var-int */
	uint8_t bytes[10];
	size_t blen = sizeof(bytes), offset = 0;
	offset = imquic_write_moqint(IMQUIC_MOQ_VERSION_MAX, expected1, bytes, blen);
	g_assert_true(offset != 0);
	g_assert_cmpmem(bytes, offset, num1, sizeof(num1));
	offset = imquic_write_moqint(IMQUIC_MOQ_VERSION_MAX, expected3, bytes, blen);
	g_assert_true(offset != 0);
	g_assert_cmpmem(bytes, offset, num3, sizeof(num3));
	offset = imquic_write_moqint(IMQUIC_MOQ_VERSION_MAX, expected4, bytes, blen);
	g_assert_true(offset != 0);
	g_assert_cmpmem(bytes, offset, num4, sizeof(num4));
	offset = imquic_write_moqint(IMQUIC_MOQ_VERSION_MAX, expected5, bytes, blen);
	g_assert_true(offset != 0);
	g_assert_cmpmem(bytes, offset, num5, sizeof(num5));
	offset = imquic_write_moqint(IMQUIC_MOQ_VERSION_MAX, expected6, bytes, blen);
	g_assert_true(offset != 0);
	g_assert_cmpmem(bytes, offset, num6, sizeof(num6));
}

static void test_location_filter(void) {
	imquic_moq_context moq = { 0 };
	imquic_moq_request_parameters parameters, parsed_parameters;
	uint8_t bytes[100];
	size_t blen = sizeof(blen), encoded = 0, decoded;
	uint8_t params_num = 0, error = 0;
	uint64_t parsed_params_num = 0;

	/* Legacy (pre-v20) */
	{
		moq.version = IMQUIC_MOQ_VERSION_19;
		imquic_moq_request_parameters_init_defaults(&parameters);
		parameters.location_filter_set = TRUE;
		/* Largest Object */
		parameters.location_filter.legacy_type = IMQUIC_MOQ_FILTER_LARGEST_OBJECT;
		encoded = imquic_moq_request_parameters_serialize(&moq, IMQUIC_MOQ_PSEUDO_REQUEST, &parameters, bytes, blen, &params_num);
		g_assert_true(encoded != 0);
		g_assert_cmpuint(params_num, ==, 1);
		decoded = imquic_moq_parse_request_parameters(&moq, bytes, encoded, &parsed_parameters, &parsed_params_num, &error);
		g_assert_true(error == 0);
		g_assert_cmpuint(decoded, ==, encoded);
		g_assert_true(memcmp (&parameters, &parsed_parameters, sizeof(imquic_moq_request_parameters)) == 0);
		/* Next Group Start */
		parameters.location_filter.legacy_type = IMQUIC_MOQ_FILTER_NEXT_GROUP_START;
		encoded = imquic_moq_request_parameters_serialize(&moq, IMQUIC_MOQ_PSEUDO_REQUEST, &parameters, bytes, blen, &params_num);
		g_assert_true(encoded != 0);
		g_assert_cmpuint(params_num, ==, 1);
		decoded = imquic_moq_parse_request_parameters(&moq, bytes, encoded, &parsed_parameters, &parsed_params_num, &error);
		g_assert_true(error == 0);
		g_assert_cmpuint(decoded, ==, encoded);
		g_assert_true(memcmp (&parameters, &parsed_parameters, sizeof(imquic_moq_request_parameters)) == 0);
		/* Absolute Start */
		parameters.location_filter.legacy_type = IMQUIC_MOQ_FILTER_ABSOLUTE_START;
		parameters.location_filter.range.start.group = 1;
		parameters.location_filter.range.start.object = 2;
		encoded = imquic_moq_request_parameters_serialize(&moq, IMQUIC_MOQ_PSEUDO_REQUEST, &parameters, bytes, blen, &params_num);
		g_assert_true(encoded != 0);
		g_assert_cmpuint(params_num, ==, 1);
		decoded = imquic_moq_parse_request_parameters(&moq, bytes, encoded, &parsed_parameters, &parsed_params_num, &error);
		g_assert_true(error == 0);
		g_assert_cmpuint(decoded, ==, encoded);
		g_assert_true(memcmp (&parameters, &parsed_parameters, sizeof(imquic_moq_request_parameters)) == 0);
		/* Absolute Range */
		parameters.location_filter.legacy_type = IMQUIC_MOQ_FILTER_ABSOLUTE_RANGE;
		parameters.location_filter.range.end.group = 3;
		encoded = imquic_moq_request_parameters_serialize(&moq, IMQUIC_MOQ_PSEUDO_REQUEST, &parameters, bytes, blen, &params_num);
		g_assert_true(encoded != 0);
		g_assert_cmpuint(params_num, ==, 1);
		decoded = imquic_moq_parse_request_parameters(&moq, bytes, encoded, &parsed_parameters, &parsed_params_num, &error);
		g_assert_true(error == 0);
		g_assert_cmpuint(decoded, ==, encoded);
		g_assert_true(memcmp (&parameters, &parsed_parameters, sizeof(imquic_moq_request_parameters)) == 0);
	}

	/* v20/21 */
	{
		moq.version = IMQUIC_MOQ_VERSION_21;
		imquic_moq_request_parameters_init_defaults(&parameters);
		parameters.location_filter_set = TRUE;
		/* No Filter */
		parameters.location_filter.type = IMQUIC_MOQ_LOCATION_FILTER_NONE;
		encoded = imquic_moq_request_parameters_serialize(&moq, IMQUIC_MOQ_PSEUDO_REQUEST, &parameters, bytes, blen, &params_num);
		g_assert_true(encoded != 0);
		g_assert_cmpuint(params_num, ==, 1);
		decoded = imquic_moq_parse_request_parameters(&moq, bytes, encoded, &parsed_parameters, &parsed_params_num, &error);
		g_assert_true(error == 0);
		g_assert_cmpuint(decoded, ==, encoded);
		g_assert_true(memcmp (&parameters, &parsed_parameters, sizeof(imquic_moq_request_parameters)) == 0);
		/* Next Object */
		parameters.location_filter.type = IMQUIC_MOQ_LOCATION_FILTER_NEXT_OBJECT;
		encoded = imquic_moq_request_parameters_serialize(&moq, IMQUIC_MOQ_PSEUDO_REQUEST, &parameters, bytes, blen, &params_num);
		g_assert_true(encoded != 0);
		g_assert_cmpuint(params_num, ==, 1);
		decoded = imquic_moq_parse_request_parameters(&moq, bytes, encoded, &parsed_parameters, &parsed_params_num, &error);
		g_assert_true(error == 0);
		g_assert_cmpuint(decoded, ==, encoded);
		g_assert_true(memcmp (&parameters, &parsed_parameters, sizeof(imquic_moq_request_parameters)) == 0);
		/* Relative Start */
		parameters.location_filter.type = IMQUIC_MOQ_LOCATION_FILTER_RELATIVE_START;
		parameters.location_filter.range.start.group = 1;
		encoded = imquic_moq_request_parameters_serialize(&moq, IMQUIC_MOQ_PSEUDO_REQUEST, &parameters, bytes, blen, &params_num);
		g_assert_true(encoded != 0);
		g_assert_cmpuint(params_num, ==, 1);
		decoded = imquic_moq_parse_request_parameters(&moq, bytes, encoded, &parsed_parameters, &parsed_params_num, &error);
		g_assert_true(error == 0);
		g_assert_cmpuint(decoded, ==, encoded);
		g_assert_true(memcmp (&parameters, &parsed_parameters, sizeof(imquic_moq_request_parameters)) == 0);
		/* Absolute Start */
		parameters.location_filter.type = IMQUIC_MOQ_LOCATION_FILTER_ABSOLUTE_START;
		parameters.location_filter.range.start.object = 2;
		encoded = imquic_moq_request_parameters_serialize(&moq, IMQUIC_MOQ_PSEUDO_REQUEST, &parameters, bytes, blen, &params_num);
		g_assert_true(encoded != 0);
		g_assert_cmpuint(params_num, ==, 1);
		decoded = imquic_moq_parse_request_parameters(&moq, bytes, encoded, &parsed_parameters, &parsed_params_num, &error);
		g_assert_true(error == 0);
		g_assert_cmpuint(decoded, ==, encoded);
		g_assert_true(memcmp (&parameters, &parsed_parameters, sizeof(imquic_moq_request_parameters)) == 0);
		/* Absolute Start, Group End */
		parameters.location_filter.type = IMQUIC_MOQ_LOCATION_FILTER_GROUP_END;
		parameters.location_filter.range.end.group = 3;
		encoded = imquic_moq_request_parameters_serialize(&moq, IMQUIC_MOQ_PSEUDO_REQUEST, &parameters, bytes, blen, &params_num);
		g_assert_true(encoded != 0);
		g_assert_cmpuint(params_num, ==, 1);
		decoded = imquic_moq_parse_request_parameters(&moq, bytes, encoded, &parsed_parameters, &parsed_params_num, &error);
		g_assert_true(error == 0);
		g_assert_cmpuint(decoded, ==, encoded);
		g_assert_true(memcmp (&parameters, &parsed_parameters, sizeof(imquic_moq_request_parameters)) == 0);
		/* Absolute Range */
		parameters.location_filter.type = IMQUIC_MOQ_LOCATION_FILTER_ABSOLUTE_RANGE;
		parameters.location_filter.range.end.object = 4;
		encoded = imquic_moq_request_parameters_serialize(&moq, IMQUIC_MOQ_PSEUDO_REQUEST, &parameters, bytes, blen, &params_num);
		g_assert_true(encoded != 0);
		g_assert_cmpuint(params_num, ==, 1);
		decoded = imquic_moq_parse_request_parameters(&moq, bytes, encoded, &parsed_parameters, &parsed_params_num, &error);
		g_assert_true(error == 0);
		g_assert_cmpuint(decoded, ==, encoded);
		g_assert_true(memcmp (&parameters, &parsed_parameters, sizeof(imquic_moq_request_parameters)) == 0);
	}

	/* Latest */
	{
		moq.version = IMQUIC_MOQ_VERSION_MAX;
		imquic_moq_request_parameters_init_defaults(&parameters);
		parameters.location_filter_set = TRUE;
		/* No Filter */
		parameters.location_filter.type = IMQUIC_MOQ_LOCATION_FILTER_NONE;
		encoded = imquic_moq_request_parameters_serialize(&moq, IMQUIC_MOQ_PSEUDO_REQUEST, &parameters, bytes, blen, &params_num);
		g_assert_true(encoded != 0);
		g_assert_cmpuint(params_num, ==, 1);
		decoded = imquic_moq_parse_request_parameters(&moq, bytes, encoded, &parsed_parameters, &parsed_params_num, &error);
		g_assert_true(error == 0);
		g_assert_cmpuint(decoded, ==, encoded);
		g_assert_true(memcmp (&parameters, &parsed_parameters, sizeof(imquic_moq_request_parameters)) == 0);
		/* Next Object */
		parameters.location_filter.type = IMQUIC_MOQ_LOCATION_FILTER_NEXT_OBJECT;
		encoded = imquic_moq_request_parameters_serialize(&moq, IMQUIC_MOQ_PSEUDO_REQUEST, &parameters, bytes, blen, &params_num);
		g_assert_true(encoded != 0);
		g_assert_cmpuint(params_num, ==, 1);
		decoded = imquic_moq_parse_request_parameters(&moq, bytes, encoded, &parsed_parameters, &parsed_params_num, &error);
		g_assert_true(error == 0);
		g_assert_cmpuint(decoded, ==, encoded);
		g_assert_true(memcmp (&parameters, &parsed_parameters, sizeof(imquic_moq_request_parameters)) == 0);
		/* Relative Start */
		parameters.location_filter.type = IMQUIC_MOQ_LOCATION_FILTER_RELATIVE_START;
		parameters.location_filter.range.start.group = 1;
		encoded = imquic_moq_request_parameters_serialize(&moq, IMQUIC_MOQ_PSEUDO_REQUEST, &parameters, bytes, blen, &params_num);
		g_assert_true(encoded != 0);
		g_assert_cmpuint(params_num, ==, 1);
		decoded = imquic_moq_parse_request_parameters(&moq, bytes, encoded, &parsed_parameters, &parsed_params_num, &error);
		g_assert_true(error == 0);
		g_assert_cmpuint(decoded, ==, encoded);
		g_assert_true(memcmp (&parameters, &parsed_parameters, sizeof(imquic_moq_request_parameters)) == 0);
		/* Absolute Start */
		parameters.location_filter.type = IMQUIC_MOQ_LOCATION_FILTER_ABSOLUTE_START;
		parameters.location_filter.range.start.object = 2;
		encoded = imquic_moq_request_parameters_serialize(&moq, IMQUIC_MOQ_PSEUDO_REQUEST, &parameters, bytes, blen, &params_num);
		g_assert_true(encoded != 0);
		g_assert_cmpuint(params_num, ==, 1);
		decoded = imquic_moq_parse_request_parameters(&moq, bytes, encoded, &parsed_parameters, &parsed_params_num, &error);
		g_assert_true(error == 0);
		g_assert_cmpuint(decoded, ==, encoded);
		g_assert_true(memcmp (&parameters, &parsed_parameters, sizeof(imquic_moq_request_parameters)) == 0);
		/* Absolute Start, Group End */
		parameters.location_filter.type = IMQUIC_MOQ_LOCATION_FILTER_GROUP_END;
		parameters.location_filter.range.end.group = 3;
		encoded = imquic_moq_request_parameters_serialize(&moq, IMQUIC_MOQ_PSEUDO_REQUEST, &parameters, bytes, blen, &params_num);
		g_assert_true(encoded != 0);
		g_assert_cmpuint(params_num, ==, 1);
		decoded = imquic_moq_parse_request_parameters(&moq, bytes, encoded, &parsed_parameters, &parsed_params_num, &error);
		g_assert_true(error == 0);
		g_assert_cmpuint(decoded, ==, encoded);
		g_assert_true(memcmp (&parameters, &parsed_parameters, sizeof(imquic_moq_request_parameters)) == 0);
		/* Absolute Range */
		parameters.location_filter.type = IMQUIC_MOQ_LOCATION_FILTER_ABSOLUTE_RANGE;
		parameters.location_filter.range.end.object = 4;
		encoded = imquic_moq_request_parameters_serialize(&moq, IMQUIC_MOQ_PSEUDO_REQUEST, &parameters, bytes, blen, &params_num);
		g_assert_true(encoded != 0);
		g_assert_cmpuint(params_num, ==, 1);
		decoded = imquic_moq_parse_request_parameters(&moq, bytes, encoded, &parsed_parameters, &parsed_params_num, &error);
		g_assert_true(error == 0);
		g_assert_cmpuint(decoded, ==, encoded);
		g_assert_true(memcmp (&parameters, &parsed_parameters, sizeof(imquic_moq_request_parameters)) == 0);
	}
}

int main(int argc, char *argv[]) {
	g_test_init(&argc, &argv, NULL);
	imquic_set_log_level(0);
	g_test_add_func("/moq/var-int", test_var_int);
	g_test_add_func("/moq/location-filter", test_location_filter);
	return g_test_run();
}
