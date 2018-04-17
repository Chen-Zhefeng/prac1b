#ifndef __TRANSCODE_H__
#define __TRANSCODE_H__

#include <string.h>
#include <stdio.h>
#include <openssl/evp.h>
#include <ctype.h>
#include <openssl/x509v3.h>
unsigned char *Byte2Hex (const unsigned char* input, int inlen, bool with_new_line);

//Note: piolen is a input&output para
unsigned char *Hex2Byte (const unsigned char* input, int *piolen, bool with_new_line);

unsigned char * Base64Encode(const unsigned char * input, int length, bool with_new_line);
//Note: piolen is a input&output para
unsigned char* Base64Decode(const unsigned char *input, int* piolen, bool with_new_line);


#endif //~__TRANSCODE_H__
