#ifndef __COMMON_BASE64_H__
#define __COMMON_BASE64_H__
/*!
	\file
	\author Krzysztof Dynowski
	\brief Base64 implementation
*/

#include <sys/types.h>

int base64_encode(unsigned char *data, size_t len, char *str, size_t *slen);
int base64_decode(const char *str, size_t slen, unsigned char *data, size_t *len);

#endif
