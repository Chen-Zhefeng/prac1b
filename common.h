/*  Put some common header files and preprocess statements here!
 *
 */
#ifndef __COMMON_H__
#define __COMMON_H__

#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <algorithm>
#include <exception>
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/x509v3.h>
#include "transcode.h"

//typedef unsigned char  BYTE;
//typedef unsigned char *LPBYTE;
//typedef const unsigned char CBYTE;
//typedef const unsigned char *LPCBYTE;
//typedef char  *LPSTR;
//typedef const char CSTR;
//typedef const char *LPCSTR;


#ifndef FALSE
#define FALSE     0
#endif

#ifndef TRUE
#define TRUE      1
#endif

enum {
  Binary,
  Hex,
  Base64
} MODE;

const int BufferSize = 2048;
const int MaxBlockSize = 256;

extern int errno;



#endif //~__COMMON_H__
