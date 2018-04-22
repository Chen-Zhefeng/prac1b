#ifndef __CIPHER_H__
#define __CIPHER_H__

#include <algorithm>
#include <exception>
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/x509v3.h>
#include "transcode.h"
#include <string.h>
#include <exception>
#include <sstream>
#include <iostream>


const int BufferSize = 2048;
const int MaxBlockSize = 256;


class CCipher
{
private:

  //if (offsetData == NULL), then it's the last round
  void Cleanup();
protected:
  EVP_CIPHER_CTX *m_ctx;
  const EVP_CIPHER *m_cipher;
public:
  CCipher(const char* ciphername = "aes-128-cbc");
   ~CCipher();
  CCipher(const CCipher&);
  CCipher &operator= (const CCipher&);
  int Encrypt(const char* inFile, const char* outFile, const unsigned char* aKey, const unsigned char* iVec, 
      const char* format = "binary", ENGINE *impl = NULL, bool with_new_line = true);
  int Decrypt(const char* inFile, const char* outFile, const unsigned char* aKey, const unsigned char* iVec, 
      const char* format = "binary", ENGINE *impl = NULL, bool with_new_line = true);
  void Reset(const char* ciphername);
  void Swap(CCipher& ci);
  friend void swap(CCipher& a, CCipher& b)
  {
    a.Swap(b);
  }
 
};


#endif //~__CIPHER_H__
