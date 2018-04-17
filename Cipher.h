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

const int BufferSize = 2048;
const int MaxBlockSize = 256;

typedef enum Mode{
  Binary = 0,
  Hex,
  Base64
} MODE;

class CCipher
{
private:
  char m_szErr[BufferSize];
  FILE *m_fpin, *m_fpout;
  //if (offsetData == NULL), then it's the last round
  unsigned char* TransCode(unsigned char* input, int *plen, MODE mode, bool isEncode, unsigned char* offsetData, int* offset);
protected:
  EVP_CIPHER_CTX *m_ctx;
  const EVP_CIPHER *m_cipher;
public:
  CCipher(const char* ciphername);
  virtual ~CCipher();
  CCipher(const CCipher&);
  CCipher &operator= (const CCipher&);
  int Encrypt(const char* inFile, const char* outFile, const unsigned char* aKey, const unsigned char* iVec, const char* format = "binary", ENGINE *impl = NULL);
  int Decrypt(const char* inFile, const char* outFile, const unsigned char* aKey, const unsigned char* iVec, const char* format = "binary", ENGINE *impl = NULL);
  void Reset(const char* ciphername);
  void Swap(CCipher& ci);
  void Cleanup();
  
};


#endif //~__CIPHER_H__
