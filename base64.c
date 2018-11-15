/*!
	\file
	\author Krzysztof Dynowski
	\brief Base64 implementation
*/
#include "base64.h"

#define BASE64_PAD '='
static const char *BASE64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static int base64_pos(char x) {
	const char *c = BASE64;
	for (int i = 0;  i  < 64; ++i) {
		if (c[i] == x) return i;
	}
	return -1;
}

int base64_encode(unsigned char *data, size_t len, char *str, size_t *slen) {
	int c = 0, cbits = 0, j = 0;
	for (int i = 0; i < len; ++i) {
		c = (c<<8) | (data[i]&0xff); // 8 bits read
		cbits += 8;
		while (cbits >= 6) {
			cbits -= 6;
			int y = (c >> cbits) & 0x3f;
			c &= (1 << cbits) - 1;
			if (str && j < *slen) str[j] = BASE64[y];
			++j;
		}
	}
	if (cbits > 0) {
		c <<= 6 - cbits;
		int y = c & 0x3f;
		if (str && j < *slen) str[j++] = BASE64[y];
	}
	if ((j&3) > 0) {
		for (int i = j&3; i < 4; ++i) {
			if (str && j < *slen) str[j] = BASE64_PAD;
			++j;
		}
	}
	if (str && j < *slen) str[j] = 0;
	++j;
	if (*slen < j) {
		*slen = j;
		return 1;
	}
	*slen = j;
	return 0;
}

int base64_decode(const char *str, size_t slen, unsigned char *data, size_t *len) {
	int c = 0, cbits =0, j = 0;
	for (int i = 0; i < slen; ++i) {
		char ch = str[i];
		int x = base64_pos(ch);
		if (x == -1) {
			if (ch == BASE64_PAD) break;
			continue;
		}
		c = (c<<6) | x; // 6 bits read
		cbits += 6;
		while (cbits >= 8) {
			cbits -= 8;
			int y = (c >> cbits) & 0xff;
			c &= (1 << cbits) - 1;
			if (data && j < *len) data[j] = y;
			++j;
		}
	}
	if (*len < j) {
		*len = j;
		return 1;
	}
	*len = j;
	return 0;
}
