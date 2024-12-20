/*! \file   huffman.h
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright MIT License
 * \brief  Huffman tables (QPACK only) (headers)
 * \details Naive implementation of Huffman tables, used for quick
 * encoding and decoding by the QPACK part of our basic HTTP/3 stack.
 *
 * The decoder works by processing the incoming bitstream 8 bits at a time,
 * and so in bytes. This is inspired by different blog posts, most importantly
 * <a href="https://tia.mat.br/posts/2022/03/27/huffman-decoder-for-hpack.html">this
 * one</a> explaining the reasoning behind LWAN's decoder implementation.
 * Using a bitstream reader, we can peek 8 bits at a time, and then look for
 * the related \ref imquic_huffman_table instance in the root table: if
 * we get a symbol right away, we return that and consume its size in bits
 * from the bitstream: if we're redirected to another table, because the
 * Huffman code uses more than 8 bits, we read 8 more bits and try to
 * find a match in the related table; and so on and so forth. Redirecting
 * to a different table is done by using negative values in the \c num_bits
 * property, which removing the sign act as keys to our transitions map
 * in \ref imquic_huffman_transitions.
 *
 * Encoding uses a single table, instead, where we look for the
 * \ref imquic_huffman_bits instance mapped to the ascii symbol we want
 * to encode. That instance contains both a hex representation of the
 * Huffman code, and how many bits we should actually write, which we can
 * then pass to a bitstream writer for the purpose. The last byte is
 * padded with a sequence of up to 7 \c 1 to act as an EOS.
 *
 * \ingroup Core
 */

#ifndef IMQUIC_HUFFMAN_H
#define IMQUIC_HUFFMAN_H

#include <stdint.h>

#include <glib.h>

/** @name Huffman decoding
 */
///@{
/*! \brief Ascii symbol and its length in bits as Huffman code, relatively to the current level */
typedef struct imquic_huffman_table {
	/*! \brief Ascii symbol */
	uint8_t symbol;
	/*! \brief Length in bits in Huffman code (current level only) */
	int8_t num_bits;
} imquic_huffman_table;

/*! \brief Root level of parsing (first byte) */
imquic_huffman_table level0_root[256] = {
	[0 ... 7] = { 48, 5},
	[8 ... 15] = { 49, 5},
	[16 ... 23] = { 50, 5},
	[24 ... 31] = { 97, 5},
	[32 ... 39] = { 99, 5},
	[40 ... 47] = { 101, 5},
	[48 ... 55] = { 105, 5},
	[56 ... 63] = { 111, 5},
	[64 ... 71] = { 115, 5},
	[72 ... 79] = { 116, 5},
	[80 ... 83] = { 32, 6},
	[84 ... 87] = { 37, 6},
	[88 ... 91] = { 45, 6},
	[92 ... 95] = { 46, 6},
	[96 ... 99] = { 47, 6},
	[100 ... 103] = { 51, 6},
	[104 ... 107] = { 52, 6},
	[108 ... 111] = { 53, 6},
	[112 ... 115] = { 54, 6},
	[116 ... 119] = { 55, 6},
	[120 ... 123] = { 56, 6},
	[124 ... 127] = { 57, 6},
	[128 ... 131] = { 61, 6},
	[132 ... 135] = { 65, 6},
	[136 ... 139] = { 95, 6},
	[140 ... 143] = { 98, 6},
	[144 ... 147] = { 100, 6},
	[148 ... 151] = { 102, 6},
	[152 ... 155] = { 103, 6},
	[156 ... 159] = { 104, 6},
	[160 ... 163] = { 108, 6},
	[164 ... 167] = { 109, 6},
	[168 ... 171] = { 110, 6},
	[172 ... 175] = { 112, 6},
	[176 ... 179] = { 114, 6},
	[180 ... 183] = { 117, 6},
	[184 ... 185] = { 58, 7},
	[186 ... 187] = { 66, 7},
	[188 ... 189] = { 67, 7},
	[190 ... 191] = { 68, 7},
	[192 ... 193] = { 69, 7},
	[194 ... 195] = { 70, 7},
	[196 ... 197] = { 71, 7},
	[198 ... 199] = { 72, 7},
	[200 ... 201] = { 73, 7},
	[202 ... 203] = { 74, 7},
	[204 ... 205] = { 75, 7},
	[206 ... 207] = { 76, 7},
	[208 ... 209] = { 77, 7},
	[210 ... 211] = { 78, 7},
	[212 ... 213] = { 79, 7},
	[214 ... 215] = { 80, 7},
	[216 ... 217] = { 81, 7},
	[218 ... 219] = { 82, 7},
	[220 ... 221] = { 83, 7},
	[222 ... 223] = { 84, 7},
	[224 ... 225] = { 85, 7},
	[226 ... 227] = { 86, 7},
	[228 ... 229] = { 87, 7},
	[230 ... 231] = { 89, 7},
	[232 ... 233] = { 106, 7},
	[234 ... 235] = { 107, 7},
	[236 ... 237] = { 113, 7},
	[238 ... 239] = { 118, 7},
	[240 ... 241] = { 119, 7},
	[242 ... 243] = { 120, 7},
	[244 ... 245] = { 121, 7},
	[246 ... 247] = { 122, 7},
	[248] = { 38, 8},
	[249] = { 42, 8},
	[250] = { 44, 8},
	[251] = { 59, 8},
	[252] = { 88, 8},
	[253] = { 90, 8},
	/*! \brief Move to level0_11111110 as our next step */
	[254] = { 0, -1},
	/*! \brief Move to level0_11111111 as our next step */
	[255] = { 0, -2},
};

/*! \brief Second level of parsing (second byte), if the first byte was 11111110 */
imquic_huffman_table level0_11111110[256] = {
	[0 ... 63] = { 33, 2},
	[64 ... 127] = { 34, 2},
	[128 ... 191] = { 40, 2},
	[192 ... 255] = { 41, 2},
};

/*! \brief Second level of parsing (second byte), if the first byte was 11111111 */
imquic_huffman_table level0_11111111[256] = {
	[0 ... 63] = { 63, 2},
	[64 ... 95] = { 39, 3},
	[96 ... 127] = { 43, 3},
	[128 ... 159] = { 124, 3},
	[160 ... 175] = { 35, 4},
	[176 ... 191] = { 62, 4},
	[192 ... 199] = { 0, 5},
	[200 ... 207] = { 36, 5},
	[208 ... 215] = { 64, 5},
	[216 ... 223] = { 91, 5},
	[224 ... 231] = { 93, 5},
	[232 ... 239] = { 126, 5},
	[240 ... 243] = { 94, 6},
	[244 ... 247] = { 125, 6},
	[248 ... 249] = { 60, 7},
	[250 ... 251] = { 96, 7},
	[252 ... 253] = { 123, 7},
	/*! \brief Move to level0_11111111_11111110 as our next step */
	[254] = { 0, -3},
	/*! \brief Move to level0_11111111_11111111 as our next step */
	[255] = { 0, -4},
};

/*! \brief Third level of parsing (third byte), if the second byte was 11111110 */
imquic_huffman_table level0_11111111_11111110[256] = {
	[0 ... 31] = { 92, 3},
	[32 ... 63] = { 195, 3},
	[64 ... 95] = { 208, 3},
	[96 ... 111] = { 128, 4},
	[112 ... 127] = { 130, 4},
	[128 ... 143] = { 131, 4},
	[144 ... 159] = { 162, 4},
	[160 ... 175] = { 184, 4},
	[176 ... 191] = { 194, 4},
	[192 ... 207] = { 224, 4},
	[208 ... 223] = { 226, 4},
	[224 ... 231] = { 153, 5},
	[232 ... 239] = { 161, 5},
	[240 ... 247] = { 167, 5},
	[248 ... 255] = { 172, 5},
};

/*! \brief Third level of parsing (third byte), if the second byte was 11111111 */
imquic_huffman_table level0_11111111_11111111[256] = {
	[0 ... 7] = { 176, 5},
	[8 ... 15] = { 177, 5},
	[16 ... 23] = { 179, 5},
	[24 ... 31] = { 209, 5},
	[32 ... 39] = { 216, 5},
	[40 ... 47] = { 217, 5},
	[48 ... 55] = { 227, 5},
	[56 ... 63] = { 229, 5},
	[64 ... 71] = { 230, 5},
	[72 ... 75] = { 129, 6},
	[76 ... 79] = { 132, 6},
	[80 ... 83] = { 133, 6},
	[84 ... 87] = { 134, 6},
	[88 ... 91] = { 136, 6},
	[92 ... 95] = { 146, 6},
	[96 ... 99] = { 154, 6},
	[100 ... 103] = { 156, 6},
	[104 ... 107] = { 160, 6},
	[108 ... 111] = { 163, 6},
	[112 ... 115] = { 164, 6},
	[116 ... 119] = { 169, 6},
	[120 ... 123] = { 170, 6},
	[124 ... 127] = { 173, 6},
	[128 ... 131] = { 178, 6},
	[132 ... 135] = { 181, 6},
	[136 ... 139] = { 185, 6},
	[140 ... 143] = { 186, 6},
	[144 ... 147] = { 187, 6},
	[148 ... 151] = { 189, 6},
	[152 ... 155] = { 190, 6},
	[156 ... 159] = { 196, 6},
	[160 ... 163] = { 198, 6},
	[164 ... 167] = { 228, 6},
	[168 ... 171] = { 232, 6},
	[172 ... 175] = { 233, 6},
	[176 ... 177] = { 1, 7},
	[178 ... 179] = { 135, 7},
	[180 ... 181] = { 137, 7},
	[182 ... 183] = { 138, 7},
	[184 ... 185] = { 139, 7},
	[186 ... 187] = { 140, 7},
	[188 ... 189] = { 141, 7},
	[190 ... 191] = { 143, 7},
	[192 ... 193] = { 147, 7},
	[194 ... 195] = { 149, 7},
	[196 ... 197] = { 150, 7},
	[198 ... 199] = { 151, 7},
	[200 ... 201] = { 152, 7},
	[202 ... 203] = { 155, 7},
	[204 ... 205] = { 157, 7},
	[206 ... 207] = { 158, 7},
	[208 ... 209] = { 165, 7},
	[210 ... 211] = { 166, 7},
	[212 ... 213] = { 168, 7},
	[214 ... 215] = { 174, 7},
	[216 ... 217] = { 175, 7},
	[218 ... 219] = { 180, 7},
	[220 ... 221] = { 182, 7},
	[222 ... 223] = { 183, 7},
	[224 ... 225] = { 188, 7},
	[226 ... 227] = { 191, 7},
	[228 ... 229] = { 197, 7},
	[230 ... 231] = { 231, 7},
	[232 ... 233] = { 239, 7},
	[234] = { 9, 8},
	[235] = { 142, 8},
	[236] = { 144, 8},
	[237] = { 145, 8},
	[238] = { 148, 8},
	[239] = { 159, 8},
	[240] = { 171, 8},
	[241] = { 206, 8},
	[242] = { 215, 8},
	[243] = { 225, 8},
	[244] = { 236, 8},
	[245] = { 237, 8},
	/*! \brief Move to level0_11111111_11111111_11110110 as our next step */
	[246] = { 0, -5},
	/*! \brief Move to level0_11111111_11111111_11110111 as our next step */
	[247] = { 0, -6},
	/*! \brief Move to level0_11111111_11111111_11110111 as our next step */
	[248] = { 0, -7},
	/*! \brief Move to level0_11111111_11111111_11111000 as our next step */
	[249] = { 0, -8},
	/*! \brief Move to level0_11111111_11111111_11111001 as our next step */
	[250] = { 0, -9},
	/*! \brief Move to level0_11111111_11111111_11111010 as our next step */
	[251] = { 0, -10},
	/*! \brief Move to level0_11111111_11111111_11111011 as our next step */
	[252] = { 0, -11},
	/*! \brief Move to level0_11111111_11111111_11111100 as our next step */
	[253] = { 0, -12},
	/*! \brief Move to level0_11111111_11111111_11111101 as our next step */
	[254] = { 0, -13},
	/*! \brief Move to level0_11111111_11111111_11111111 as our next step */
	[255] = { 0, -14},

};

/*! \brief Fourth level of parsing (fourth byte), if the third byte was 11110110 */
imquic_huffman_table level0_11111111_11111111_11110110[256] = {
	[0 ... 127] = { 199, 1},
	[128 ... 255] = { 207, 1},
};

/*! \brief Fourth level of parsing (fourth byte), if the third byte was 11110111 */
imquic_huffman_table level0_11111111_11111111_11110111[256] = {
	[0 ... 127] = { 234, 1},
	[128 ... 255] = { 235, 1},
};

/*! \brief Fourth level of parsing (fourth byte), if the third byte was 11111000 */
imquic_huffman_table level0_11111111_11111111_11111000[256] = {
	[0 ... 63] = { 192, 2},
	[64 ... 127] = { 193, 2},
	[128 ... 191] = { 200, 2},
	[192 ... 255] = { 201, 2},
};

/*! \brief Fourth level of parsing (fourth byte), if the third byte was 11111001 */
imquic_huffman_table level0_11111111_11111111_11111001[256] = {
	[0 ... 63] = { 202, 2},
	[64 ... 127] = { 205, 2},
	[128 ... 191] = { 210, 2},
	[192 ... 255] = { 213, 2},
};

/*! \brief Fourth level of parsing (fourth byte), if the third byte was 11111010 */
imquic_huffman_table level0_11111111_11111111_11111010[256] = {
	[0 ... 63] = { 218, 2},
	[64 ... 127] = { 219, 2},
	[128 ... 191] = { 238, 2},
	[192 ... 255] = { 240, 2},
};

/*! \brief Fourth level of parsing (fourth byte), if the third byte was 11111011 */
imquic_huffman_table level0_11111111_11111111_11111011[256] = {
	[0 ... 63] = { 242, 2},
	[64 ... 127] = { 243, 2},
	[128 ... 191] = { 255, 2},
	[192 ... 223] = { 203, 3},
	[224 ... 255] = { 204, 3},
};

/*! \brief Fourth level of parsing (fourth byte), if the third byte was 11111100 */
imquic_huffman_table level0_11111111_11111111_11111100[256] = {
	[0 ... 31] = { 211, 3},
	[32 ... 63] = { 212, 3},
	[64 ... 95] = { 214, 3},
	[96 ... 127] = { 221, 3},
	[128 ... 159] = { 222, 3},
	[160 ... 191] = { 223, 3},
	[192 ... 223] = { 241, 3},
	[224 ... 255] = { 244, 3},
};

/*! \brief Fourth level of parsing (fourth byte), if the third byte was 11111101 */
imquic_huffman_table level0_11111111_11111111_11111101[256] = {
	[0 ... 31] = { 245, 3},
	[32 ... 63] = { 246, 3},
	[64 ... 95] = { 247, 3},
	[96 ... 127] = { 248, 3},
	[128 ... 159] = { 250, 3},
	[160 ... 191] = { 251, 3},
	[192 ... 223] = { 252, 3},
	[224 ... 255] = { 253, 3},
};

/*! \brief Fourth level of parsing (fourth byte), if the third byte was 11111110 */
imquic_huffman_table level0_11111111_11111111_11111110[256] = {
	[0 ... 31] = { 254, 3},
	[32 ... 47] = { 2, 4},
	[48 ... 63] = { 3, 4},
	[64 ... 79] = { 4, 4},
	[80 ... 95] = { 5, 4},
	[96 ... 111] = { 6, 4},
	[112 ... 127] = { 7, 4},
	[128 ... 143] = { 8, 4},
	[144 ... 159] = { 11, 4},
	[160 ... 175] = { 12, 4},
	[176 ... 191] = { 14, 4},
	[192 ... 207] = { 15, 4},
	[208 ... 223] = { 16, 4},
	[224 ... 239] = { 17, 4},
	[240 ... 255] = { 18, 4},
};

/*! \brief Fourth level of parsing (fourth byte), if the third byte was 11111111 */
imquic_huffman_table level0_11111111_11111111_11111111[256] = {
	[0 ... 15] = { 19, 4},
	[16 ... 31] = { 20, 4},
	[32 ... 47] = { 21, 4},
	[48 ... 63] = { 23, 4},
	[64 ... 79] = { 24, 4},
	[80 ... 95] = { 25, 4},
	[96 ... 111] = { 26, 4},
	[112 ... 127] = { 27, 4},
	[128 ... 143] = { 28, 4},
	[144 ... 159] = { 29, 4},
	[160 ... 175] = { 30, 4},
	[176 ... 191] = { 31, 4},
	[192 ... 207] = { 127, 4},
	[208 ... 223] = { 220, 4},
	[224 ... 239] = { 249, 4},
	[240 ... 243] = { 10, 6},
	[244 ... 247] = { 13, 6},
	[248 ... 251] = { 22, 6},
	/*! \brief EOS, point to a NULL table */
	[252 ... 255] = { 0, -15},
};

/*! \brief Map of transitions, to allow moving from one table to another at different levels */
imquic_huffman_table *imquic_huffman_transitions[16] = {
	/* Root */
	[0] = level0_root,
	/* First byte is 11111110 */
	[1] = level0_11111110,
	/* First byte is 11111111 */
	[2] = level0_11111111,
	/* First byte is 11111111, second byte is 11111110 */
	[3] = level0_11111111_11111110,
	/* First byte is 11111111, second byte is 11111111 */
	[4] = level0_11111111_11111111,
	/* First byte is 11111111, second byte is 11111111, third byte is 11110110 */
	[5] = level0_11111111_11111111_11110110,
	/* First byte is 11111111, second byte is 11111111, third byte is 11110111 */
	[6] = level0_11111111_11111111_11110111,
	/* First byte is 11111111, second byte is 11111111, third byte is 11111000 */
	[7] = level0_11111111_11111111_11111000,
	/* First byte is 11111111, second byte is 11111111, third byte is 11111001 */
	[8] = level0_11111111_11111111_11111001,
	/* First byte is 11111111, second byte is 11111111, third byte is 11111010 */
	[9] = level0_11111111_11111111_11111010,
	/* First byte is 11111111, second byte is 11111111, third byte is 11111011 */
	[10] = level0_11111111_11111111_11111011,
	/* First byte is 11111111, second byte is 11111111, third byte is 11111100 */
	[11] = level0_11111111_11111111_11111100,
	/* First byte is 11111111, second byte is 11111111, third byte is 11111101 */
	[12] = level0_11111111_11111111_11111101,
	/* First byte is 11111111, second byte is 11111111, third byte is 11111110 */
	[13] = level0_11111111_11111111_11111110,
	/* First byte is 11111111, second byte is 11111111, third byte is 11111111 */
	[14] = level0_11111111_11111111_11111111,
	/* EOS */
	[15] = NULL
};
///@}

/** @name Huffman encoding
 */
///@{
/*! \brief Huffman code and its length in bits as Huffman code, mapped to the related ascii code */
typedef struct imquic_huffman_bits {
	/*! \brief Length in bits of the Huffman encoding */
	uint8_t len;
	/*! \brief Hex representation of the Huffman encoding */
	uint32_t value;
} imquic_huffman_bits;

/*! \brief Table mapping each ascii code to its Huffman code representation */
imquic_huffman_bits table[] = {
	/*! \brief [0], 1111111111000 */
	{ 13, 0x1ff8 },
	/*! \brief [1], 11111111111111111011000 */
	{ 23, 0x7fffd8 },
	/*! \brief [2], 1111111111111111111111100010 */
	{ 28, 0xfffffe2 },
	/*! \brief [3], 1111111111111111111111100011 */
	{ 28, 0xfffffe3 },
	/*! \brief [4], 1111111111111111111111100100 */
	{ 28, 0xfffffe4 },
	/*! \brief [5], 1111111111111111111111100101 */
	{ 28, 0xfffffe5 },
	/*! \brief [6], 1111111111111111111111100110 */
	{ 28, 0xfffffe6 },
	/*! \brief [7], 1111111111111111111111100111 */
	{ 28, 0xfffffe7 },
	/*! \brief [8], 1111111111111111111111101000 */
	{ 28, 0xfffffe8 },
	/*! \brief [9], 111111111111111111101010 */
	{ 24, 0xffffea },
	/*! \brief [10], 111111111111111111111111111100 */
	{ 30, 0x3ffffffc },
	/*! \brief [11], 1111111111111111111111101001 */
	{ 28, 0xfffffe9 },
	/*! \brief [12], 1111111111111111111111101010 */
	{ 28, 0xfffffea },
	/*! \brief [13], 111111111111111111111111111101 */
	{ 30, 0x3ffffffd },
	/*! \brief [14], 1111111111111111111111101011 */
	{ 28, 0xfffffeb },
	/*! \brief [15], 1111111111111111111111101100 */
	{ 28, 0xfffffec },
	/*! \brief [16], 1111111111111111111111101101 */
	{ 28, 0xfffffed },
	/*! \brief [17], 1111111111111111111111101110 */
	{ 28, 0xfffffee },
	/*! \brief [18], 1111111111111111111111101111 */
	{ 28, 0xfffffef },
	/*! \brief [19], 1111111111111111111111110000 */
	{ 28, 0xffffff0 },
	/*! \brief [20], 1111111111111111111111110001 */
	{ 28, 0xffffff1 },
	/*! \brief [21], 1111111111111111111111110010 */
	{ 28, 0xffffff2 },
	/*! \brief [22], 111111111111111111111111111110 */
	{ 30, 0x3ffffffe },
	/*! \brief [23], 1111111111111111111111110011 */
	{ 28, 0xffffff3 },
	/*! \brief [24], 1111111111111111111111110100 */
	{ 28, 0xffffff4 },
	/*! \brief [25], 1111111111111111111111110101 */
	{ 28, 0xffffff5 },
	/*! \brief [26], 1111111111111111111111110110 */
	{ 28, 0xffffff6 },
	/*! \brief [27], 1111111111111111111111110111 */
	{ 28, 0xffffff7 },
	/*! \brief [28], 1111111111111111111111111000 */
	{ 28, 0xffffff8 },
	/*! \brief [29], 1111111111111111111111111001 */
	{ 28, 0xffffff9 },
	/*! \brief [30], 1111111111111111111111111010 */
	{ 28, 0xffffffa },
	/*! \brief [31], 1111111111111111111111111011 */
	{ 28, 0xffffffb },
	/*! \brief [32], ' ', 010100 */
	{ 6, 0x14 },
	/*! \brief [33], '!', 1111111000 */
	{ 10, 0x3f8 },
	/*! \brief [34], '"', 1111111001 */
	{ 10, 0x3f9 },
	/*! \brief [35], '#', 111111111010 */
	{ 12, 0xffa },
	/*! \brief [36], '$', 1111111111001 */
	{ 13, 0x1ff9 },
	/*! \brief [37], '%', 010101 */
	{ 6, 0x15 },
	/*! \brief [38], '&', 11111000 */
	{ 8, 0xf8 },
	/*! \brief [39], 11111111010 */
	{ 11, 0x7fa },
	/*! \brief [40], '(', 1111111010 */
	{ 10, 0x3fa },
	/*! \brief [41], ')', 1111111011 */
	{ 10, 0x3fb },
	/*! \brief [42], '*', 11111001 */
	{ 8, 0xf9 },
	/*! \brief [43], '+', 11111111011 */
	{ 11, 0x7fb },
	/*! \brief [44], ',', 11111010 */
	{ 8, 0xfa },
	/*! \brief [45], '-', 010110 */
	{ 6, 0x16 },
	/*! \brief [46], '.', 010111 */
	{ 6, 0x17 },
	/*! \brief [47], '/', 011000 */
	{ 6, 0x18 },
	/*! \brief [48], '0', 00000 */
	{ 5, 0x0 },
	/*! \brief [49], '1', 00001 */
	{ 5, 0x1 },
	/*! \brief [50], '2', 00010 */
	{ 5, 0x2 },
	/*! \brief [51], '3', 011001 */
	{ 6, 0x19 },
	/*! \brief [52], '4', 011010 */
	{ 6, 0x1a },
	/*! \brief [53], '5', 011011 */
	{ 6, 0x1b },
	/*! \brief [54], '6', 011100 */
	{ 6, 0x1c },
	/*! \brief [55], '7', 011101 */
	{ 6, 0x1d },
	/*! \brief [56], '8', 011110 */
	{ 6, 0x1e },
	/*! \brief [57], '9', 011111 */
	{ 6, 0x1f },
	/*! \brief [58], ':', 1011100 */
	{ 7, 0x5c },
	/*! \brief [59], ';', 11111011 */
	{ 8, 0xfb },
	/*! \brief [60], '<', 111111111111100 */
	{ 15, 0x7ffc },
	/*! \brief [61], '=', 100000 */
	{ 6, 0x20 },
	/*! \brief [62], '>', 111111111011 */
	{ 12, 0xffb },
	/*! \brief [63], '?', 1111111100 */
	{ 10, 0x3fc },
	/*! \brief [64], '@', 1111111111010 */
	{ 13, 0x1ffa },
	/*! \brief [65], 'A', 100001 */
	{ 6, 0x21 },
	/*! \brief [66], 'B', 1011101 */
	{ 7, 0x5d },
	/*! \brief [67], 'C', 1011110 */
	{ 7, 0x5e },
	/*! \brief [68], 'D', 1011111 */
	{ 7, 0x5f },
	/*! \brief [69], 'E', 1100000 */
	{ 7, 0x60 },
	/*! \brief [70], 'F', 1100001 */
	{ 7, 0x61 },
	/*! \brief [71], 'G', 1100010 */
	{ 7, 0x62 },
	/*! \brief [72], 'H', 1100011 */
	{ 7, 0x63 },
	/*! \brief [73], 'I', 1100100 */
	{ 7, 0x64 },
	/*! \brief [74], 'J', 1100101 */
	{ 7, 0x65 },
	/*! \brief [75], 'K', 1100110 */
	{ 7, 0x66 },
	/*! \brief [76], 'L', 1100111 */
	{ 7, 0x67 },
	/*! \brief [77], 'M', 1101000 */
	{ 7, 0x68 },
	/*! \brief [78], 'N', 1101001 */
	{ 7, 0x69 },
	/*! \brief [79], 'O', 1101010 */
	{ 7, 0x6a },
	/*! \brief [80], 'P', 1101011 */
	{ 7, 0x6b },
	/*! \brief [81], 'Q', 1101100 */
	{ 7, 0x6c },
	/*! \brief [82], 'R', 1101101 */
	{ 7, 0x6d },
	/*! \brief [83], 'S', 1101110 */
	{ 7, 0x6e },
	/*! \brief [84], 'T', 1101111 */
	{ 7, 0x6f },
	/*! \brief [85], 'U', 1110000 */
	{ 7, 0x70 },
	/*! \brief [86], 'V', 1110001 */
	{ 7, 0x71 },
	/*! \brief [87], 'W', 1110010 */
	{ 7, 0x72 },
	/*! \brief [88], 'X', 11111100 */
	{ 8, 0xfc },
	/*! \brief [89], 'Y', 1110011 */
	{ 7, 0x73 },
	/*! \brief [90], 'Z', 11111101 */
	{ 8, 0xfd },
	/*! \brief [91], '[', 1111111111011 */
	{ 13, 0x1ffb },
	/*! \brief [92], 1111111111111110000 */
	{ 19, 0x7fff0 },
	/*! \brief [93], ']', 1111111111100 */
	{ 13, 0x1ffc },
	/*! \brief [94], '^', 11111111111100 */
	{ 14, 0x3ffc },
	/*! \brief [95], '_', 100010 */
	{ 6, 0x22 },
	/*! \brief [96], '`', 111111111111101 */
	{ 15, 0x7ffd },
	/*! \brief [97], 'a', 00011 */
	{ 5, 0x3 },
	/*! \brief [98], 'b', 100011 */
	{ 6, 0x23 },
	/*! \brief [99], 'c', 00100 */
	{ 5, 0x4 },
	/*! \brief [100], 'd', 100100 */
	{ 6, 0x24 },
	/*! \brief [101], 'e', 00101 */
	{ 5, 0x5 },
	/*! \brief [102], 'f', 100101 */
	{ 6, 0x25 },
	/*! \brief [103], 'g', 100110 */
	{ 6, 0x26 },
	/*! \brief [104], 'h', 100111 */
	{ 6, 0x27 },
	/*! \brief [105], 'i', 00110 */
	{ 5, 0x6 },
	/*! \brief [106], 'j', 1110100 */
	{ 7, 0x74 },
	/*! \brief [107], 'k', 1110101 */
	{ 7, 0x75 },
	/*! \brief [108], 'l', 101000 */
	{ 6, 0x28 },
	/*! \brief [109], 'm', 101001 */
	{ 6, 0x29 },
	/*! \brief [110], 'n', 101010 */
	{ 6, 0x2a },
	/*! \brief [111], 'o', 00111 */
	{ 5, 0x7 },
	/*! \brief [112], 'p', 101011 */
	{ 6, 0x2b },
	/*! \brief [113], 'q', 1110110 */
	{ 7, 0x76 },
	/*! \brief [114], 'r', 101100 */
	{ 6, 0x2c },
	/*! \brief [115], 's', 01000 */
	{ 5, 0x8 },
	/*! \brief [116], 't', 01001 */
	{ 5, 0x9 },
	/*! \brief [117], 'u', 101101 */
	{ 6, 0x2d },
	/*! \brief [118], 'v', 1110111 */
	{ 7, 0x77 },
	/*! \brief [119], 'w', 1111000 */
	{ 7, 0x78 },
	/*! \brief [120], 'x', 1111001 */
	{ 7, 0x79 },
	/*! \brief [121], 'y', 1111010 */
	{ 7, 0x7a },
	/*! \brief [122], 'z', 1111011 */
	{ 7, 0x7b },
	/*! \brief [123], '{', 111111111111110 */
	{ 15, 0x7ffe },
	/*! \brief [124], '|', 11111111100 */
	{ 11, 0x7fc },
	/*! \brief [125], '}', 11111111111101 */
	{ 14, 0x3ffd },
	/*! \brief [126], '~', 1111111111101 */
	{ 13, 0x1ffd },
	/*! \brief [127], 1111111111111111111111111100 */
	{ 28, 0xffffffc },
	/*! \brief [128], 11111111111111100110 */
	{ 20, 0xfffe6 },
	/*! \brief [129], 1111111111111111010010 */
	{ 22, 0x3fffd2 },
	/*! \brief [130], 11111111111111100111 */
	{ 20, 0xfffe7 },
	/*! \brief [131], 11111111111111101000 */
	{ 20, 0xfffe8 },
	/*! \brief [132], 1111111111111111010011 */
	{ 22, 0x3fffd3 },
	/*! \brief [133], 1111111111111111010100 */
	{ 22, 0x3fffd4 },
	/*! \brief [134], 1111111111111111010101 */
	{ 22, 0x3fffd5 },
	/*! \brief [135], 11111111111111111011001 */
	{ 23, 0x7fffd9 },
	/*! \brief [136], 1111111111111111010110 */
	{ 22, 0x3fffd6 },
	/*! \brief [137], 11111111111111111011010 */
	{ 23, 0x7fffda },
	/*! \brief [138], 11111111111111111011011 */
	{ 23, 0x7fffdb },
	/*! \brief [139], 11111111111111111011100 */
	{ 23, 0x7fffdc },
	/*! \brief [140], 11111111111111111011101 */
	{ 23, 0x7fffdd },
	/*! \brief [141], 11111111111111111011110 */
	{ 23, 0x7fffde },
	/*! \brief [142], 111111111111111111101011 */
	{ 24, 0xffffeb },
	/*! \brief [143], 11111111111111111011111 */
	{ 23, 0x7fffdf },
	/*! \brief [144], 111111111111111111101100 */
	{ 24, 0xffffec },
	/*! \brief [145], 111111111111111111101101 */
	{ 24, 0xffffed },
	/*! \brief [146], 1111111111111111010111 */
	{ 22, 0x3fffd7 },
	/*! \brief [147], 11111111111111111100000 */
	{ 23, 0x7fffe0 },
	/*! \brief [148], 111111111111111111101110 */
	{ 24, 0xffffee },
	/*! \brief [149], 11111111111111111100001 */
	{ 23, 0x7fffe1 },
	/*! \brief [150], 11111111111111111100010 */
	{ 23, 0x7fffe2 },
	/*! \brief [151], 11111111111111111100011 */
	{ 23, 0x7fffe3 },
	/*! \brief [152], 11111111111111111100100 */
	{ 23, 0x7fffe4 },
	/*! \brief [153], 111111111111111011100 */
	{ 21, 0x1fffdc },
	/*! \brief [154], 1111111111111111011000 */
	{ 22, 0x3fffd8 },
	/*! \brief [155], 11111111111111111100101 */
	{ 23, 0x7fffe5 },
	/*! \brief [156], 1111111111111111011001 */
	{ 22, 0x3fffd9 },
	/*! \brief [157], 11111111111111111100110 */
	{ 23, 0x7fffe6 },
	/*! \brief [158], 11111111111111111100111 */
	{ 23, 0x7fffe7 },
	/*! \brief [159], 111111111111111111101111 */
	{ 24, 0xffffef },
	/*! \brief [160], 1111111111111111011010 */
	{ 22, 0x3fffda },
	/*! \brief [161], 111111111111111011101 */
	{ 21, 0x1fffdd },
	/*! \brief [162], 11111111111111101001 */
	{ 20, 0xfffe9 },
	/*! \brief [163], 1111111111111111011011 */
	{ 22, 0x3fffdb },
	/*! \brief [164], 1111111111111111011100 */
	{ 22, 0x3fffdc },
	/*! \brief [165], 11111111111111111101000 */
	{ 23, 0x7fffe8 },
	/*! \brief [166], 11111111111111111101001 */
	{ 23, 0x7fffe9 },
	/*! \brief [167], 111111111111111011110 */
	{ 21, 0x1fffde },
	/*! \brief [168], 11111111111111111101010 */
	{ 23, 0x7fffea },
	/*! \brief [169], 1111111111111111011101 */
	{ 22, 0x3fffdd },
	/*! \brief [170], 1111111111111111011110 */
	{ 22, 0x3fffde },
	/*! \brief [171], 111111111111111111110000 */
	{ 24, 0xfffff0 },
	/*! \brief [172], 111111111111111011111 */
	{ 21, 0x1fffdf },
	/*! \brief [173], 1111111111111111011111 */
	{ 22, 0x3fffdf },
	/*! \brief [174], 11111111111111111101011 */
	{ 23, 0x7fffeb },
	/*! \brief [175], 11111111111111111101100 */
	{ 23, 0x7fffec },
	/*! \brief [176], 111111111111111100000 */
	{ 21, 0x1fffe0 },
	/*! \brief [177], 111111111111111100001 */
	{ 21, 0x1fffe1 },
	/*! \brief [178], 1111111111111111100000 */
	{ 22, 0x3fffe0 },
	/*! \brief [179], 111111111111111100010 */
	{ 21, 0x1fffe2 },
	/*! \brief [180], 11111111111111111101101 */
	{ 23, 0x7fffed },
	/*! \brief [181], 1111111111111111100001 */
	{ 22, 0x3fffe1 },
	/*! \brief [182], 11111111111111111101110 */
	{ 23, 0x7fffee },
	/*! \brief [183], 11111111111111111101111 */
	{ 23, 0x7fffef },
	/*! \brief [184], 11111111111111101010 */
	{ 20, 0xfffea },
	/*! \brief [185], 1111111111111111100010 */
	{ 22, 0x3fffe2 },
	/*! \brief [186], 1111111111111111100011 */
	{ 22, 0x3fffe3 },
	/*! \brief [187], 1111111111111111100100 */
	{ 22, 0x3fffe4 },
	/*! \brief [188], 11111111111111111110000 */
	{ 23, 0x7ffff0 },
	/*! \brief [189], 1111111111111111100101 */
	{ 22, 0x3fffe5 },
	/*! \brief [190], 1111111111111111100110 */
	{ 22, 0x3fffe6 },
	/*! \brief [191], 11111111111111111110001 */
	{ 23, 0x7ffff1 },
	/*! \brief [192], 11111111111111111111100000 */
	{ 26, 0x3ffffe0 },
	/*! \brief [193], 11111111111111111111100001 */
	{ 26, 0x3ffffe1 },
	/*! \brief [194], 11111111111111101011 */
	{ 20, 0xfffeb },
	/*! \brief [195], 1111111111111110001 */
	{ 19, 0x7fff1 },
	/*! \brief [196], 1111111111111111100111 */
	{ 22, 0x3fffe7 },
	/*! \brief [197], 11111111111111111110010 */
	{ 23, 0x7ffff2 },
	/*! \brief [198], 1111111111111111101000 */
	{ 22, 0x3fffe8 },
	/*! \brief [199], 1111111111111111111101100 */
	{ 25, 0x1ffffec },
	/*! \brief [200], 11111111111111111111100010 */
	{ 26, 0x3ffffe2 },
	/*! \brief [201], 11111111111111111111100011 */
	{ 26, 0x3ffffe3 },
	/*! \brief [202], 11111111111111111111100100 */
	{ 26, 0x3ffffe4 },
	/*! \brief [203], 111111111111111111111011110 */
	{ 27, 0x7ffffde },
	/*! \brief [204], 111111111111111111111011111 */
	{ 27, 0x7ffffdf },
	/*! \brief [205], 11111111111111111111100101 */
	{ 26, 0x3ffffe5 },
	/*! \brief [206], 111111111111111111110001 */
	{ 24, 0xfffff1 },
	/*! \brief [207], 1111111111111111111101101 */
	{ 25, 0x1ffffed },
	/*! \brief [208], 1111111111111110010 */
	{ 19, 0x7fff2 },
	/*! \brief [209], 111111111111111100011 */
	{ 21, 0x1fffe3 },
	/*! \brief [210], 11111111111111111111100110 */
	{ 26, 0x3ffffe6 },
	/*! \brief [211], 111111111111111111111100000 */
	{ 27, 0x7ffffe0 },
	/*! \brief [212], 111111111111111111111100001 */
	{ 27, 0x7ffffe1 },
	/*! \brief [213], 11111111111111111111100111 */
	{ 26, 0x3ffffe7 },
	/*! \brief [214], 111111111111111111111100010 */
	{ 27, 0x7ffffe2 },
	/*! \brief [215], 111111111111111111110010 */
	{ 24, 0xfffff2 },
	/*! \brief [216], 111111111111111100100 */
	{ 21, 0x1fffe4 },
	/*! \brief [217], 111111111111111100101 */
	{ 21, 0x1fffe5 },
	/*! \brief [218], 11111111111111111111101000 */
	{ 26, 0x3ffffe8 },
	/*! \brief [219], 11111111111111111111101001 */
	{ 26, 0x3ffffe9 },
	/*! \brief [220], 1111111111111111111111111101 */
	{ 28, 0xffffffd },
	/*! \brief [221], 111111111111111111111100011 */
	{ 27, 0x7ffffe3 },
	/*! \brief [222], 111111111111111111111100100 */
	{ 27, 0x7ffffe4 },
	/*! \brief [223], 111111111111111111111100101 */
	{ 27, 0x7ffffe5 },
	/*! \brief [224], 11111111111111101100 */
	{ 20, 0xfffec },
	/*! \brief [225], 111111111111111111110011 */
	{ 24, 0xfffff3 },
	/*! \brief [226], 11111111111111101101 */
	{ 20, 0xfffed },
	/*! \brief [227], 111111111111111100110 */
	{ 21, 0x1fffe6 },
	/*! \brief [228], 1111111111111111101001 */
	{ 22, 0x3fffe9 },
	/*! \brief [229], 111111111111111100111 */
	{ 21, 0x1fffe7 },
	/*! \brief [230], 111111111111111101000 */
	{ 21, 0x1fffe8 },
	/*! \brief [231], 11111111111111111110011 */
	{ 23, 0x7ffff3 },
	/*! \brief [232], 1111111111111111101010 */
	{ 22, 0x3fffea },
	/*! \brief [233], 1111111111111111101011 */
	{ 22, 0x3fffeb },
	/*! \brief [234], 1111111111111111111101110 */
	{ 25, 0x1ffffee },
	/*! \brief [235], 1111111111111111111101111 */
	{ 25, 0x1ffffef },
	/*! \brief [236], 111111111111111111110100 */
	{ 24, 0xfffff4 },
	/*! \brief [237], 111111111111111111110101 */
	{ 24, 0xfffff5 },
	/*! \brief [238], 11111111111111111111101010 */
	{ 26, 0x3ffffea },
	/*! \brief [239], 11111111111111111110100 */
	{ 23, 0x7ffff4 },
	/*! \brief [240], 11111111111111111111101011 */
	{ 26, 0x3ffffeb },
	/*! \brief [241], 111111111111111111111100110 */
	{ 27, 0x7ffffe6 },
	/*! \brief [242], 11111111111111111111101100 */
	{ 26, 0x3ffffec },
	/*! \brief [243], 11111111111111111111101101 */
	{ 26, 0x3ffffed },
	/*! \brief [244], 111111111111111111111100111 */
	{ 27, 0x7ffffe7 },
	/*! \brief [245], 111111111111111111111101000 */
	{ 27, 0x7ffffe8 },
	/*! \brief [246], 111111111111111111111101001 */
	{ 27, 0x7ffffe9 },
	/*! \brief [247], 111111111111111111111101010 */
	{ 27, 0x7ffffea },
	/*! \brief [248], 111111111111111111111101011 */
	{ 27, 0x7ffffeb },
	/*! \brief [249], 1111111111111111111111111110 */
	{ 28, 0xffffffe },
	/*! \brief [250], 111111111111111111111101100 */
	{ 27, 0x7ffffec },
	/*! \brief [251], 111111111111111111111101101 */
	{ 27, 0x7ffffed },
	/*! \brief [252], 111111111111111111111101110 */
	{ 27, 0x7ffffee },
	/*! \brief [253], 111111111111111111111101111 */
	{ 27, 0x7ffffef },
	/*! \brief [254], 111111111111111111111110000 */
	{ 27, 0x7fffff0 },
	/*! \brief [255], 11111111111111111111101110 */
	{ 26, 0x3ffffee },
	/*! \brief [256], EOS, 111111111111111111111111111111 */
	{ 30, 0x3fffffff },
};
///@}

#endif