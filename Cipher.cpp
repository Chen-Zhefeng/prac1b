#include "Cipher.h"

int CCipher::Encrypt(const char* inFile, const char* outFile, const unsigned char* aKey, const unsigned char* iVec, const char* format, ENGINE *impl)
{
  int n = 0;
  unsigned char* transData = NULL;
  unsigned char inbuf[BufferSize];
  unsigned char outbuf[BufferSize + MaxBlockSize + 2];
  unsigned char offsetData[2];
  int offset = 0;
  int readlen = 0;
  int writelen = 0;
  int cryptlen = 0;
  int formatedlen = 0;
  MODE mode = Binary;
  if(!strcmp(format, "binary"))
    mode = Binary;
  else if(!strcmp(format, "hex"))
    mode = Hex;
  else if(!strcmp(format, "base64"))
    mode = Base64;
  else
  {
    sprintf(m_szErr, "CCipher::Encrypt: Unknown format (%s)!\n", format);
    Cleanup();
    throw m_szErr;
  }
  
  unsigned char* keybin = NULL;
  unsigned char* ivbin = NULL;
  if(aKey)
  {
    int keylen =  strlen((const char*)aKey);
    keybin = Hex2Byte(aKey, &keylen, 0);
  }
  if(iVec)
  {
    int ivlen =  strlen((const char*)iVec);
    ivbin = Hex2Byte(iVec, &ivlen, 0);
  }
  /*
   * 初始化算法：设置算法密钥，IV，以及加解密标志位dir
   * 如果使用Engine，此时会调用其实现的EVP_CIPHER->init回调函数
   */
  if (!EVP_CipherInit_ex(m_ctx, m_cipher, impl, keybin, ivbin, 1))  //最后一个参数，1表示加密，0表示解密
  {
    n = ERR_get_error();
    char errmsg[1024];
    ERR_error_string(n, errmsg);
    sprintf(m_szErr, "CCipher::Encrypt: EVP_CipherInit_ex failed: \nopenssl return %d, %s\n", n, errmsg);
    Cleanup();
    throw m_szErr;
  }

  if (!(m_fpin = fopen(inFile, "rb")))
  {
    char errmsg[1024];
    char* msg = strerror_r(errno, errmsg, 1024);
    sprintf(m_szErr, "CCipher::Encrypt: file(%s) open failed!\nerrno=%d, ErrMess:%s\n", inFile, errno, msg);
    Cleanup();
    throw m_szErr;
  }
  if (!(m_fpout = fopen(outFile, "wt")))
  {
    char errmsg[1024];
    char* msg = strerror_r(errno, errmsg, 1024);
    sprintf(m_szErr, "CCipher::Encrypt: file(%s) open failed!\nerrno=%d, ErrMess:%s\n", outFile, errno, msg);
    Cleanup();
    throw m_szErr;
  }
  while(readlen = fread(inbuf, 1, BufferSize, m_fpin))
  {
   /*  
    * 对数据进行加/解密(如果使用Engine，此时会调用其实现的EVP_CIPHER->do_cipher回调函数)
    * 对于连续数据流，CipherUpdate一般会被调用多次
    */
    if (!EVP_CipherUpdate(m_ctx, outbuf + offset, &cryptlen, inbuf, readlen))
    {
      n = ERR_get_error();
      char errmsg[1024];
      ERR_error_string(n, errmsg);
      sprintf(m_szErr, "CCipher::Encrypt: EVP_CipherUpdate failed!\nopenssl return %d, %s\n", n, errmsg);
      Cleanup();
      throw m_szErr;
    }
    if(mode)
    {
      transData = TransCode(outbuf, &cryptlen, mode,1, offsetData, &offset);
      formatedlen = strlen((const char*)transData);
    }
    else
    {
      transData = outbuf;
      formatedlen = cryptlen;
    }
    if (!(writelen = fwrite(transData, 1, formatedlen, m_fpout)))
    {
      char errmsg[1024];
      char* msg = strerror_r(errno, errmsg, 1024);
      sprintf(m_szErr, "CCipher::Encrypt: file(%s) write failed!\nerrno=%d, ErrMess:%s\n", outFile, errno, msg);
      if(mode)
        free(transData);
      transData = NULL;
      Cleanup();
      throw m_szErr;
    }
    if(mode)
      free(transData);
    transData = NULL;
  }

  if ( feof(m_fpin) )
  {
   /**
  *输出最后一块数据（块加密时，数据将被padding到block长度的整数倍，因此会产生额外的最后一段数据）
  *注意：如果使用Engine，此时会触发其实现的EVP_CIPHER->do_cipher，而不是EVP_CIPHER->cleanup
  *这点上与EVP_DigestFinal/EVP_SignFinal/EVP_VerifyFinal是完全不同的
  */
    if (!EVP_CipherFinal(m_ctx, outbuf + offset, &cryptlen)) 
    {
      n  = ERR_get_error();
      char errmsg[1024];
      ERR_error_string( n, errmsg );
      sprintf( m_szErr, "CCipher::Encrypt  EVP_CipherFinalfailed: \nopenssl return %d, %s\n", n, errmsg );
      Cleanup();
      throw m_szErr;
    }
    if(mode) 
    {
      transData = TransCode(outbuf, &cryptlen, mode,1, NULL, &offset);
      formatedlen = strlen((const char*)transData);
    }
    else
    {
      transData = outbuf;
      formatedlen = cryptlen;
    }
    if(formatedlen != 0)
    {
      if (!(writelen = fwrite(transData, 1, formatedlen, m_fpout)))
      {
        char errmsg[1024];
        char* msg = strerror_r(errno, errmsg, 1024);
        sprintf(m_szErr, "CCipher::Encrypt: file(%s) write failed!\nerrno=%d, ErrMess:%s\n", outFile, errno, msg);
        if(mode)
          free(transData);
        transData = NULL;
        Cleanup();
        throw m_szErr;
      }
      if(mode)
        free(transData);
      transData = NULL;   
    }
  }
  else
  {
    char errmsg[1024];
    char* msg = strerror_r(errno, errmsg, 1024);
    sprintf(m_szErr, "CCipher::Encrypt: file(%s) read failed!\nerrno=%d, ErrMess:%s\n", outFile, errno, msg);
    Cleanup();
    throw m_szErr;
  }
  return 0;
}

int CCipher::Decrypt(const char* inFile, const char* outFile, const unsigned char* aKey, const unsigned char* iVec, const char* format, ENGINE *impl)
{
  return 0;
}


CCipher::CCipher(const char* ciphername): m_fpin(NULL), m_fpout(NULL)
{
    OpenSSL_add_all_algorithms();
    m_ctx = EVP_CIPHER_CTX_new();
    if(!m_ctx)
    {
      sprintf(m_szErr, "CCipher construct fail: EVP_CIPHER_CTX_new failed\n",ciphername);
      Cleanup();
      throw m_szErr;
    }
    m_cipher = EVP_get_cipherbyname(ciphername);
    if (NULL == m_cipher) {
      sprintf(m_szErr, "CCipher construct fail: Cipher for %s is NULL\n",ciphername);
      Cleanup();
      throw m_szErr;
    }
}

CCipher::~CCipher()
{
  Cleanup();
}

void CCipher::Reset(const char* ciphername)
{

  CCipher tmp(ciphername);
  Swap(tmp);
}

void CCipher::Swap(CCipher& other)
{
  using std::swap;
  swap(m_cipher, other.m_cipher);
  swap(m_ctx, other.m_ctx);//passing temporary object, try bind to a non-const lval 
}


void CCipher::Cleanup()
{
  if(m_fpin)
  {  
    fclose(m_fpin);
    m_fpin = NULL;
  }
  if(m_fpout)
  {
    fclose(m_fpout);
    m_fpout = NULL;
  }
  EVP_CIPHER_CTX_cleanup(m_ctx);
  EVP_CIPHER_CTX_free(m_ctx);
  EVP_cleanup();
}

//if (offsetData == NULL), then it's the last round
unsigned char* CCipher::TransCode(unsigned char* input, int* plen, MODE mode, bool isEncode,  unsigned char* offsetData, int* offset)
{
  unsigned char* transData = NULL;   

  if(!input)
  {
    sprintf(m_szErr, "CCipher::TransCode: input null pointer!");
    Cleanup();
    throw m_szErr;
  }
  if(isEncode) 
  {
    if(Hex ==  mode)
    {
      if (!(transData = Byte2Hex(input, *plen, 0)))
      {
        sprintf(m_szErr, "CCipher::TransCode: unsigned char2Hex transform failed!");
        Cleanup();
        throw m_szErr;
      }
    }
    else if(Base64 == mode)
    { 
      *plen += *offset;
      if(offsetData) 
      { 
        *offset =  *plen % 3;
        if(*offset != 0)
        {
          memcpy(offsetData, input + *plen - *offset, *offset);
          *plen -= *offset;
        }
      }
      if (!(transData = Base64Encode(input,*plen , 0)))   
      {
        sprintf(m_szErr, "CCipher::TransCode: Base64Encode transform failed!");
        Cleanup();
        throw m_szErr;
      }
      if(offsetData && *offset != 0)
      { 
        memcpy(input, offsetData, *offset);
      }
    }
    else
    {
      sprintf(m_szErr, "CCipher::TransCode:  Only Hex and Base64 are supported so far, sorry!");
      Cleanup();
      throw m_szErr;
    }
  }
  //Decode
  else
  {
    if(Hex ==  mode)
    {
      if (!(transData = Hex2Byte(input, plen, 0)))
      {
        sprintf(m_szErr, "CCipher::TransCode: Hex2unsigned char transform failed!");
        Cleanup();
        throw m_szErr;
      }
    }
    else if(Base64 == mode)
    { 
      *plen += *offset;
      if(offsetData)
      { 
        *offset = *plen % 4;
        if(*offset != 0)
        {
          memcpy(offsetData, input + *plen - *offset, *offset);
          *plen -= *offset;
        }
      }
 
      if (!(transData = Base64Decode(input, plen , 0)))   
      {
        sprintf(m_szErr, "CCipher::TransCode: Base64Decode transform failed!");
        Cleanup();
        throw m_szErr;
      }
      if(offsetData && *offset != 0)
      { 
        memcpy(input, offsetData, *offset);
      }
   
    }
    else
    {
      sprintf(m_szErr, "CCipher::TransCode:  Only Hex and Base64 are supported so far, sorry!");
      Cleanup();
      throw m_szErr;
    }
 
  }
  return transData;
}

namespace std {
  template<>
  void swap<CCipher> (CCipher& a, CCipher& b)
  {
    a.Swap(b);
  }
  
}


