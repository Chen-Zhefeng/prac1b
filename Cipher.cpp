#include "Cipher.h"
#include "ScopeGuard.h"
#include <utility>
#include "error.h"

using namespace std;
int CCipher::Encrypt(const char* inFile, const char* outFile, const unsigned char* aKey, const unsigned char* iVec, 
    const char* format, ENGINE *impl, bool with_new_line)
{
  FILE* fp_in = NULL, *fp_out = NULL;
  std::vector<unsigned char> transvec;
  unsigned char inbuf[BufferSize];
  unsigned char outbuf[BufferSize + MaxBlockSize + 48];
  unsigned char offsetData[48];
  unsigned char* transData = NULL;
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
    std::stringstream oss;
    oss << "CCipher::Encrypt: Unknown format " << format;
    throw Error(oss.str());
  }
  
  std::vector<unsigned char> keyvec;
  std::vector<unsigned char> ivvec;
  if(aKey)
  {
    int keylen =  strlen((const char*)aKey);
    size_t outlen = 0;
    Hex2Byte(back_inserter(keyvec), aKey, aKey + keylen, outlen, 0);
  }
 
  if(iVec)
  {
    int ivlen =  strlen((const char*)iVec);
    size_t outlen = 0;
    Hex2Byte(back_inserter(ivvec), iVec, iVec + ivlen, outlen, 0);
  }
 
  /*
   * 初始化算法：设置算法密钥，IV，以及加解密标志位dir
   * 如果使用Engine，此时会调用其实现的EVP_CIPHER->init回调函数
   */
  if (!EVP_CipherInit_ex(m_ctx, m_cipher, impl, &(keyvec.front()), &(ivvec.front()), 1))  //最后一个参数，1表示加密，0表示解密
  {
    std::string str("CCipher::Encrypt: EVP_CipherInit_ex failed!");
    throw SSLError(str);
  }

  if (!(fp_in = fopen(inFile, "rb")))
  {
    char errmsg[1024];
    char* msg = strerror_r(errno, errmsg, 1024);
    std::stringstream oss;
    oss <<  "CCipher::Encrypt: file" << inFile << " open failed!\nerrno=" << errno << ", ErrMess:" << msg  << endl;
    throw Error(oss.str());
  }
  file_close fp_in_close(fp_in);
  ScopeGuard fp_in_gd(fp_in_close);

  if (!(fp_out = fopen(outFile, "wb")))
  {
    char errmsg[1024];
    char* msg = strerror_r(errno, errmsg, 1024);
    std::stringstream oss;
    oss << "CCipher::Encrypt: file(" << outFile <<") open failed!\nerrno=" << errno <<", ErrMess:" << msg << endl;
    throw Error(oss.str());
  }
  file_close fp_out_close(fp_out);
  ScopeGuard fp_out_gd(fp_out_close);

  while(readlen = fread(inbuf, 1, BufferSize, fp_in))
  {
   /*  
    * 对数据进行加/解密(如果使用Engine，此时会调用其实现的EVP_CIPHER->do_cipher回调函数)
    * 对于连续数据流，CipherUpdate一般会被调用多次
    */
    if (!EVP_CipherUpdate(m_ctx, outbuf + offset, &cryptlen, inbuf, readlen))
    {
      std::string str("CCipher::Encrypt: EVP_CipherUpdate failed!");
      throw SSLError(str);
    }
    if(mode)
    { 
      size_t outcount = 0;
      transvec.clear();
      TransCode (back_inserter(transvec), (unsigned char*)outbuf, cryptlen + offset, outcount, mode , 1,  offsetData, offset, with_new_line, 0);
      transData = &transvec.front();
      formatedlen = outcount;
    }
    else
    {
      transData = outbuf;
      formatedlen = cryptlen;
    }

    if (!(writelen = fwrite(transData, 1, formatedlen, fp_out)))
    {
      char errmsg[1024];
      char* msg = strerror_r(errno, errmsg, 1024);
      std::stringstream oss;
      oss << "Cipher::Encrypt: file" << outFile << "write failed!\nerrno=" << errno <<", ErrMess:" << msg << endl;
      throw Error(oss.str());
    }
  }

  if ( feof(fp_in) )
  {
   /**
  *输出最后一块数据（块加密时，数据将被padding到block长度的整数倍，因此会产生额外的最后一段数据）
  *注意：如果使用Engine，此时会触发其实现的EVP_CIPHER->do_cipher，而不是EVP_CIPHER->cleanup
  *这点上与EVP_DigestFinal/EVP_SignFinal/EVP_VerifyFinal是完全不同的
  */
    size_t outcount = 0;

    if (!EVP_CipherFinal(m_ctx, outbuf + offset, &cryptlen)) 
    {
      std::string str("CCipher::Encrypt  EVP_CipherFinalfailed!");
      throw SSLError(str);
    }
    if(mode) 
    {
      transvec.clear();
      TransCode(back_inserter(transvec),outbuf, cryptlen + offset, outcount,  mode, 1, NULL, offset, with_new_line, 0);
      transData = &transvec.front();
      formatedlen = outcount;
    }
    else
    {
      transData = outbuf;
      formatedlen = cryptlen;
    }

    if(formatedlen != 0)
    {
      if (!(writelen = fwrite(transData, 1, formatedlen, fp_out)))
      {
        char errmsg[1024];
        char* msg = strerror_r(errno, errmsg, 1024);
        std::stringstream oss;
        oss << "CCipher::Encrypt: file(" << outFile <<") write failed!\nerrno=" << errno <<", ErrMess:" << msg << endl;
        throw Error(oss.str());
      }
    }
  }
  else
  {
    char errmsg[1024];
    char* msg = strerror_r(errno, errmsg, 1024);
    std::stringstream oss;
    oss << "CCipher::Encrypt: file(" << inFile << ") read failed!\nerrno=" << errno << ", ErrMess:" << msg <<endl;
    throw Error(oss.str());
  }
  return 0;
}

int CCipher::Decrypt(const char* inFile, const char* outFile, const unsigned char* aKey, const unsigned char* iVec, 
    const char* format, ENGINE *impl, bool with_new_line)
{
  FILE* fp_in = NULL, *fp_out = NULL;
  unsigned char* transData = NULL;
  unsigned char inbuf[BufferSize + 65];
  unsigned char outbuf[BufferSize + 65];
  unsigned char offsetData[65];
  std::vector<unsigned char> transvec;
  size_t oldsize = 0;
  size_t newsize = 0;
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
    std::stringstream oss;
    oss << "CCipher::Decrypt: Unknown format " << format;
    throw Error(oss.str());
  }
  
  std::vector<unsigned char> keyvec;
  std::vector<unsigned char> ivvec;
  if(aKey)
  {
    int keylen =  strlen((const char*)aKey);
    size_t outlen = 0;
    Hex2Byte(back_inserter(keyvec), aKey, aKey + keylen, outlen, 0);
  }
 
  if(iVec)
  {
    int ivlen =  strlen((const char*)iVec);
    size_t outlen = 0;
    Hex2Byte(back_inserter(ivvec), iVec, iVec + ivlen, outlen, 0);
  }

   /*
   * 初始化算法：设置算法密钥，IV，以及加解密标志位dir
   * 如果使用Engine，此时会调用其实现的EVP_CIPHER->init回调函数
   */
  if (!EVP_CipherInit_ex(m_ctx, m_cipher, impl, &(keyvec.front()), &(ivvec.front()), 0))  //最后一个参数，1表示加密，0表示解密
  {
    std::string str("CCipher::Decrypt: EVP_CipherInit_ex failed!");
    throw SSLError(str);
  }

  if (!(fp_in = fopen(inFile, "rb")))
  {
    char errmsg[1024];
    char* msg = strerror_r(errno, errmsg, 1024);
    std::stringstream oss;
    oss <<  "CCipher::Decrypt: file" << inFile << " open failed!\nerrno=" << errno << ", ErrMess:" << msg  << endl;
    throw Error(oss.str());
  }
  file_close fp_in_close(fp_in);
  ScopeGuard fp_in_gd(fp_in_close);

  if (!(fp_out = fopen(outFile, "wb")))
  {
    char errmsg[1024];
    char* msg = strerror_r(errno, errmsg, 1024);
    std::stringstream oss;
    oss << "CCipher::Decrypt: file(" << outFile <<") open failed!\nerrno=" << errno <<", ErrMess:" << msg << endl;
    throw Error(oss.str());
  }
  file_close fp_out_close(fp_out);
  ScopeGuard fp_out_gd(fp_out_close);

  while(readlen = fread(inbuf + offset, 1, BufferSize, fp_in))
  {
    if(mode)
    {
      size_t incount = 0;
      transvec.clear();
      TransCode (back_inserter(transvec), inbuf, readlen + offset, incount, mode , 0,  offsetData, offset, with_new_line, 0);
      transData = &transvec.front();
      formatedlen = transvec.size();
    }
    else
    {
      transData = inbuf;
      formatedlen = readlen;
    }
    /*  
    * 对数据进行加/解密(如果使用Engine，此时会调用其实现的EVP_CIPHER->do_cipher回调函数)
    * 对于连续数据流，CipherUpdate一般会被调用多次
    */
    if (!EVP_CipherUpdate(m_ctx, outbuf, &cryptlen, transData, formatedlen))
    {
      std::string str("CCipher::Decrypt: EVP_CipherUpdate failed!");
      throw SSLError(str);
    }

   if (!(writelen = fwrite(outbuf, 1, cryptlen, fp_out)))
    {
      char errmsg[1024];
      char* msg = strerror_r(errno, errmsg, 1024);
      std::stringstream oss;
      oss << "Cipher::Decrypt: file" << outFile << "write failed!\nerrno=" << errno <<", ErrMess:" << msg << endl;
      throw Error(oss.str());
    }
  }
  if ( feof(fp_in) )
  {
    //remaining part 
    if(mode && offset)
    {
      size_t incount = 0;
      transvec.clear();
      TransCode (back_inserter(transvec), inbuf, offset, incount, mode , 0,  NULL, offset, with_new_line, 0);
      transData = &transvec.front();
      formatedlen = transvec.size();

      if (!EVP_CipherUpdate(m_ctx, outbuf, &cryptlen, transData, formatedlen))
      {
        std::string str("CCipher::Decrypt: EVP_CipherUpdate failed!");
        throw SSLError(str);
      }
      if(cryptlen)
      {
        if (!(writelen = fwrite(outbuf, 1, cryptlen, fp_out)))
        {
          char errmsg[1024];
          char* msg = strerror_r(errno, errmsg, 1024);
          std::stringstream oss;
          oss << "Cipher::Decrypt: file" << outFile << " write failed!\nerrno=" << errno <<", ErrMess:" << msg << endl;
          throw Error(oss.str());
        
        }
      }
    }
   /**
  *输出最后一块数据（块加密时，数据将被padding到block长度的整数倍，因此会产生额外的最后一段数据）
  *注意：如果使用Engine，此时会触发其实现的EVP_CIPHER->do_cipher，而不是EVP_CIPHER->cleanup
  *这点上与EVP_DigestFinal/EVP_SignFinal/EVP_VerifyFinal是完全不同的
  */
    if (!EVP_CipherFinal(m_ctx, outbuf, &cryptlen)) 
    {
      std::string str( "CCipher::Decrypt  EVP_CipherFinalfailed!");
      throw SSLError(str);
    }
    if(cryptlen != 0)
    {
      if (!(writelen = fwrite(outbuf, 1, cryptlen, fp_out)))
      {
        char errmsg[1024];
        char* msg = strerror_r(errno, errmsg, 1024);
        std::stringstream oss;
        oss << "CCipher::Decrypt: file(" << outFile <<") write failed!\nerrno=" << errno <<", ErrMess:" << msg << endl;
        throw Error(oss.str());
      }
    }
  }
  else
  {
    char errmsg[1024];
    char* msg = strerror_r(errno, errmsg, 1024);
    std::stringstream oss;
    oss << "CCipher::Decrypt: file(" << inFile << ") read failed!\nerrno=" << errno << ", ErrMess:" << msg <<endl;
    throw Error(oss.str());
  }

  return 0;
}


CCipher::CCipher(const char* ciphername)
{
  
  m_ctx = EVP_CIPHER_CTX_new();
  if(!m_ctx)
  {
    std::string str("CCipher construct fail: EVP_CIPHER_CTX_new failed");
    Cleanup();
    throw SSLError(str);
  }
  
  m_cipher = EVP_get_cipherbyname(ciphername);
  if (NULL == m_cipher) 
  {
    std::stringstream oss;
    oss << "CCipher construct fail: Cipher for " << ciphername <<" is NULL\n";
    Cleanup();
    throw SSLError(oss.str());
  }
}

CCipher::CCipher(const CCipher& other)
{
  if (!EVP_CIPHER_CTX_copy(m_ctx, other.m_ctx))
  {
    std::string str("CCipher copy construct fail!");
    Cleanup();
    throw SSLError(str);
  }
  m_cipher  = other.m_cipher;
  
}

CCipher &CCipher::operator=(const CCipher& other)
{
  CCipher tmp(other);
  this->Swap(tmp);
  return *this;
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
  EVP_CIPHER_CTX_cleanup(m_ctx);
  EVP_CIPHER_CTX_free(m_ctx);
  
}
/*
namespace std {
  template<>
  void swap<CCipher> (CCipher& a, CCipher& b)
  {
    a.Swap(b);
  }
  
}
*/

