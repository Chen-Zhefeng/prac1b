#ifndef __TRANSCODE_H__
#define __TRANSCODE_H__

#include <string.h>
#include <stdio.h>
#include <openssl/evp.h>
#include <ctype.h>
#include <openssl/x509v3.h>
#include <type_traits>
#include "error.h"
#include <functional>
#include "Cipher.h"
#include <iostream>


typedef enum Mode{
  Binary = 0,
  Hex,
  Base64
} MODE;


template <typename InIterator, typename OutIterator>
OutIterator Byte2Hex (OutIterator out, InIterator first,  InIterator last, size_t& outcount,
    bool with_new_line = true,  size_t total = 0)
{
   unsigned char tmp = 0, tmpin = 0, tmpout = 0;
   size_t cnt = total;
   if ((false ==  std::is_same<typename std::iterator_traits<InIterator>::value_type, unsigned char>::value 
      && false ==  std::is_same<typename std::iterator_traits<InIterator>::value_type,char>::value 
      && false ==  std::is_same<typename std::iterator_traits<InIterator>::value_type, const unsigned char>::value
      && false ==  std::is_same<typename std::iterator_traits<InIterator>::value_type, const char>::value)
      || ( false == std::is_same<typename std::iterator_traits<OutIterator>::value_type, unsigned char>::value
      &&  false == std::is_same<typename std::iterator_traits<OutIterator>::value_type, char>::value
      && false == std::is_same<typename std::iterator_traits<OutIterator>::value_type, void>::value))
  {
    std::string str("Byte2Hex: value type of iterator error!");
    throw Error(str); 
  }
/*  if (outlen - 1 < inlen * 2)
  {
    fprintf(stderr, "Byte2Hex: output length(%d) is to short!", outlen);
    rv = -1;
    goto err;
  }
*/
/*  if (!input)
  {
    ostringstream oss;
    oss << "Byte2Hex: input null pointer!";
    throw Error(oss.str());
  }
  if (!with_new_line)
    outlen = inlen * 2 + 1;
  else
    outlen = inlen * 2 + inlen / 32 + 1 + ((inlen * 2 ) % 64 != 0); 
*/

/*  if (!(output = (unsigned char*)malloc(outlen)))
  {
    fprintf(stderr, "Byte2Hex: function malloc fail");
    goto err;
  }
*/
  while (first != last)
  { tmpin = *first++;
    tmp = (tmpin & 0xF0) >> 4;
    if(tmp < 10) 
     *(out++) = tmp + '0';
    else
      *(out++) = tmp - 0x0A + 'A';
    ++cnt;       

    tmp = (tmpin & 0x0F);
    if(tmp < 10) 
      *(out++) = tmp + '0';
    else
      *(out++) = tmp - 0x0A + 'A';
    ++cnt;

    if (with_new_line)
    {
      if (0 == (cnt+1) % 65)    //every 64-character, new line
      {
        *(out++) = '\n';
        ++cnt;
      }
    }
  }
  //the last '\n'
  if (with_new_line && (cnt % 65 != 0))
  { 
    *(out++) = '\n';
    ++cnt;
  }
  outcount = cnt;
  return out;
}

template <typename InIterator, typename OutIterator>
OutIterator Hex2Byte (OutIterator out,InIterator first, InIterator last,  size_t& incount, bool with_new_line =1)
{
  if ((false ==  std::is_same<typename std::iterator_traits<InIterator>::value_type, unsigned char>::value 
      && false ==  std::is_same<typename std::iterator_traits<InIterator>::value_type,char>::value 
      && false ==  std::is_same<typename std::iterator_traits<InIterator>::value_type, const unsigned char>::value
      && false ==  std::is_same<typename std::iterator_traits<InIterator>::value_type, const char>::value)
      || ( false == std::is_same<typename std::iterator_traits<OutIterator>::value_type, unsigned char>::value
      && false == std::is_same<typename std::iterator_traits<OutIterator>::value_type, void>::value))
  {
    std::string str( "Hex2Byte: value type of iterator error!");
    throw Error(str); 
  }
  unsigned char tmp = 0, tmpin = 0, tmpout = 0;
  size_t cnt = 0;
/*  int outlen = 0;
  int reallen = *piolen - *piolen / 65 - (*piolen % 65 != 0);
  if (!input)
  {
    fprintf(stderr, "Hex2Byte: input null pointer!");
    goto err;
  }
    if (!with_new_line)
  {
    if (*piolen % 2 == 1)
    {
      fprintf(stderr, "Hex2Byte: intput length error!");
      goto err;
    }
  }
  else
  {
    if (reallen % 2 == 1)
    {
      fprintf(stderr, "Hex2Byte: intput length error!");
      goto err;
    }
  }
  if (outlen - 1  < inlen / 2)
  {
    fprintf(stderr, "Hex2Byte: output length(%d) is to short!", outlen);
    rv = -1;
    goto err;
   }

  if (!with_new_line)
    outlen = *piolen / 2;
  else
    outlen = reallen / 2;

  if (!(output = (unsigned char*)malloc(outlen)))
  {
    fprintf(stderr, "Hex2Byte: function malloc fail");
    goto err;
  }
  if (with_new_line && *piolen % 65 != 0)  //ignore the last ‘\n’
    --(*piolen);
*/

  while (first != last)
  {
    tmpin = *first++;
    ++cnt;
    if(with_new_line && tmpin == '\n')
    {
      if(first == last)
        break;
      tmpin = *first++;
      ++cnt;
    }
    if (tmpin >= '0' && tmpin <= '9')
    {
      tmpin -= '0';
    }
    else if (tmpin >= 'a' && tmpin <='z' || tmpin >= 'A' && tmpin <= 'Z')
    {
      tmpin = (unsigned char)toupper((int)tmpin) - 'A' + 0x0A;
    }
    else
    {
      std::string str("Hex2Byte: input element out of range!");
      throw Error(str); 
    }
    tmpout = (tmpin << 4);

    if(first == last)
    {
      std::string str("Hex2Byte: input length error!");
      throw Error(str); 
    }
    tmpin = *first++;
    ++cnt;
    if(with_new_line && tmpin == '\n')
    {
      if(first == last)
      {
        std::string str("Hex2Byte: input length error!");
        throw Error(str); 
      }
      tmpin = *first++;
  
      ++cnt;
    }
    if (tmpin >= '0' && tmpin <= '9')
    {
      tmpin -= '0';
    }
    else if (tmpin >= 'a' && tmpin <='z' || tmpin >= 'A' && tmpin <= 'Z')
    {
      tmpin = (unsigned char)toupper((int)tmpin) - 'A' + 0x0A;
    }
    else
    {
      std::string str("Hex2Byte: input element out of range!");
      throw Error(str); 
    }
    tmpout |= tmpin;
    *(out++) = tmpout;

  }
incount = cnt;
//dont need anymore
//  output[j] = '\0';

  return out;
}

struct BIO_Guard
{
  BIO* bio;
  ~BIO_Guard ( )
  {
    if(bio)
    {
      BIO_free(bio);
    }
  }
};
/*struct BIO_Chain_Guard
{
  BIO* bio;
  ~BIO_Chain_Guard()
  {
    if(bio)
      BIO_free_all(bio);
  }
};
*/
template <typename InIterator, typename OutIterator>
OutIterator Base64Encode (OutIterator out, InIterator first,  InIterator last, size_t& outcount,
    bool with_new_line = true, size_t total = 0)
{
  BIO * bmem = NULL;
  BIO * b64 = NULL;
  BUF_MEM * bptr = NULL;
  size_t cnt = total;
  if ((false ==  std::is_same<typename std::iterator_traits<InIterator>::value_type, unsigned char>::value 
      && false ==  std::is_same<typename std::iterator_traits<InIterator>::value_type,char>::value 
      && false ==  std::is_same<typename std::iterator_traits<InIterator>::value_type, const unsigned char>::value
      && false ==  std::is_same<typename std::iterator_traits<InIterator>::value_type, const char>::value)
      || ( false == std::is_same<typename std::iterator_traits<OutIterator>::value_type, unsigned char>::value
      &&  false == std::is_same<typename std::iterator_traits<OutIterator>::value_type, char>::value
      && false == std::is_same<typename std::iterator_traits<OutIterator>::value_type, void>::value))
  {
    std::string str("Base64Encode: value type of iterator error!");
    throw Error(str); 
  }
  
  b64 = BIO_new(BIO_f_base64());
  BIO_Guard b64_gd = {b64};

  if (!with_new_line)
  {
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  }
  bmem = BIO_new(BIO_s_mem());
  BIO_Guard bmem_gd = {bmem};

  b64 = BIO_push(b64, bmem);  //形成BIO链

  size_t len = 0;
  std::string str;
  if (typeid(typename std::iterator_traits<InIterator>::iterator_category) != typeid(std::random_access_iterator_tag))
  {
    while(first != last)
    {
      str += *first++;
      ++len;
    }
    BIO_write(b64, (const void*)&str.front(), len);
  }
  else
  {
    len = last -first;
    BIO_write(b64, (const void*)first, len);//len byte from buffer
  }
  BIO_flush(b64);
  BIO_get_mem_ptr(b64, &bptr);
  outcount = bptr->length;
  auto dataptr = bptr->data;
  for(int i=0; i < outcount; ++i)
    *out++ = *dataptr++;
  
  return out;
}

template <typename InIterator, typename OutIterator>
OutIterator Base64Decodeold (OutIterator out,InIterator first, InIterator last, size_t& incount, bool with_new_line = true)
{
  BIO *b64 = NULL;
  BIO *bmem =NULL;
  size_t cnt = 0;
  if ((false ==  std::is_same<typename std::iterator_traits<InIterator>::value_type, unsigned char>::value 
      && false ==  std::is_same<typename std::iterator_traits<InIterator>::value_type,char>::value 
      && false ==  std::is_same<typename std::iterator_traits<InIterator>::value_type, const unsigned char>::value
      && false ==  std::is_same<typename std::iterator_traits<InIterator>::value_type, const char>::value)
      || ( false == std::is_same<typename std::iterator_traits<OutIterator>::value_type, unsigned char>::value
      && false == std::is_same<typename std::iterator_traits<OutIterator>::value_type, void>::value))
  {
    std::string str("Base64Decode: value type of iterator error!");
    throw Error(str); 
  }

/*  int outlen = 0;
  unsigned char *buffer = NULL;
  int reallen = *piolen - *piolen / 65 - (*piolen % 65 != 0);
  if(!input)
  {
    fprintf(stderr, "Base64Decode: input null pointer!");
    goto err;
  }
  if (!with_new_line)
  {
    if (*piolen % 4 != 0)
    {
      fprintf(stderr, "Base64Decode: intput length error!");
      goto err;
    }
  }
  else
  {
    if (reallen  % 4 != 0)
    {
      fprintf(stderr, "Base64Decode: intput length error!");
      goto err;
    }
  }

  if (!with_new_line)
  {
    outlen = *piolen / 4 * 3;
    if ('=' == input[*piolen -1])
    {
      --outlen;
      if ('=' == input[*piolen - 2])
        --outlen;
    }
  }
  else
  {
    outlen = reallen / 4 * 3;
    if ('\n' == input[*piolen -1])
    {
      if ('=' == input[*piolen -2])
      {
        --outlen;
        if('=' == input[*piolen - 3])
          --outlen;
      }
    }
    else if ('=' == input[*piolen -1])
    {
      --outlen;
      if('=' == input[*piolen - 2])
        --outlen;
    }
  }
         //malloc size can not be too small
  if(!(buffer =(unsigned char*) malloc(outlen)))
  {
    fprintf(stderr, "Base64Decode: function malloc fail");
    goto err;
  }
  memset(buffer, 0, outlen);
*/
  b64 = BIO_new(BIO_f_base64());
  BIO_Guard b64_gd = {b64};
  if (!with_new_line)
  {
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  }
  size_t len = 0;
  std::string str;
  if (typeid(typename std::iterator_traits<InIterator>::iterator_category) != typeid(std::random_access_iterator_tag))
  {
    while(first != last)
    {
      str += *first++;
      ++len;
    }
    bmem = BIO_new_mem_buf((void*)&str.front(),len);
  }
  else
  {
    len = last -first;
    bmem = BIO_new_mem_buf((void*)first, len);
  }
  BIO_Guard bmem_gd = {bmem};

  b64 = BIO_push(b64, bmem);  //

  //之前由于把最后一个空格干掉了，导致b64转换错误
  std::string strout;
  strout.resize(len);
  size_t rdlen = BIO_read(b64, reinterpret_cast<void*>(&strout.front()), len);//len byte from bio
  auto it = strout.cbegin();
  auto end = strout.cend();
  while(it!= end)
   * out++ = * it++;
  return out;
}

template <typename InIterator, typename OutIterator>
OutIterator Base64Decode (OutIterator out,InIterator first, InIterator last, size_t& incount, bool with_new_line = true)
{
  BIO *b64 = NULL;
  BIO *bmem =NULL;
  size_t cnt = 0;
  if ((false ==  std::is_same<typename std::iterator_traits<InIterator>::value_type, unsigned char>::value 
      && false ==  std::is_same<typename std::iterator_traits<InIterator>::value_type,char>::value 
      && false ==  std::is_same<typename std::iterator_traits<InIterator>::value_type, const unsigned char>::value
      && false ==  std::is_same<typename std::iterator_traits<InIterator>::value_type, const char>::value)
      || ( false == std::is_same<typename std::iterator_traits<OutIterator>::value_type, unsigned char>::value
      && false == std::is_same<typename std::iterator_traits<OutIterator>::value_type, void>::value))
  {
    std::string str("Base64Decode: value type of iterator error!");
    throw Error(str); 
  }
  b64 = BIO_new(BIO_f_base64());
  BIO_Guard b64_gd = {b64};
  if (!with_new_line)
  {
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  }
  size_t len = 0;
  std::string str;
  if (typeid(typename std::iterator_traits<InIterator>::iterator_category) != typeid(std::random_access_iterator_tag))
  {
    while(first != last)
    {
      str += *first++;
      ++len;
    }
    bmem = BIO_new_mem_buf((void*)&str.front(),len);
  }
  else
  {
    len = last -first;
    bmem = BIO_new_mem_buf((void*)first, len);
  }
  BIO_Guard bmem_gd = {bmem};

  b64 = BIO_push(b64, bmem);  //

  //之前由于把最后一个空格干掉了，导致b64转换错误
  std::string strout;
  strout.resize(len); //如n小于当前size，抛弃后面的元素；如大于size，后面会填充元素(如没有指定初始化值，则进行值初始化)
  size_t rdlen = BIO_read(b64, reinterpret_cast<void*>(&strout.front()), len);//len byte from bio
 // strout.shrink_to_fit();
  strout.resize(rdlen);
  auto it = strout.cbegin();
  auto end = strout.cend();
  while(it!= end)
   * out++ = * it++;
  return out;
}



//InIterator shoule should be random access iterator
//offsetData == null means the last round
template <typename InIterator, typename OutIterator>
OutIterator TransCode (OutIterator out, InIterator input,  int len, size_t&count, 
    MODE mode, bool isEncode,  unsigned char* offsetData, int& offset,
     bool with_new_line = true,  size_t total = 0)
{
  OutIterator finish = out;
  if (typeid(typename std::iterator_traits<InIterator>::iterator_category) != typeid(std::random_access_iterator_tag))
//  if (false == std::is_same<typename std::iterator_traits<InIterator>::iterator_category(), std::random_access_iterator_tag>::value)
  {
    std::string str("TransCode: InIterator should be random_access_iterator!");
    throw Error(str);
  }
  if(!input)
  {
    std::string str("TransCode: input null pointer!");
    throw Error(str);
  }
  if(isEncode) 
  {
    if(Hex ==  mode)
    {
      if(with_new_line && offsetData)
      {
        offset = len % 32;
        if(offset)
        {
          memcpy(offsetData, input + len - offset, offset);
          len -= offset;
        }
      }
      finish =  Byte2Hex(out, input, input + len, count, with_new_line, total);
      if(with_new_line && offsetData && offset)
      {
        memcpy(input, offsetData, offset);
      }
    }
    else if(Base64 == mode)
    { 
    
      if(offsetData) 
      { 
        int mod = 48;
        if(!with_new_line)
          mod = 3;
        offset =  len % mod;
        if(offset != 0)
        {
          memcpy(offsetData, input + len - offset, offset);
          len -= offset;
        }
      }
      finish = Base64Encode(out, input, input + len , count, with_new_line, total);
     
      if(offsetData && offset != 0)
      { 
        memcpy(input, offsetData, offset);
      }
    }
    else
    { 
      std::string str("TransCode:  Only Hex and Base64 are supported so far, sorry!");
      throw Error(str);
    }
  }
  //Decode
  else
  {
    if(Hex ==  mode)
    {
      if(offsetData)
      {
        int mod = 65;
        if(!with_new_line)
          mod = 2;
        offset = len % mod;
        if(offset != 0)
        {
          memcpy(offsetData, input + len - offset, offset);
          len -= offset;
        }
      }
      finish = Hex2Byte(out, input, input + len, count, with_new_line);
     
      if(offsetData && offset != 0)
      { 
        memcpy(input, offsetData, offset);
      }
   
    }
    else if(Base64 == mode)
    { 
      if(offsetData)
      {
        int mod =65;
        if(!with_new_line)
          mod = 4;
        offset = len % mod;
        if(offset != 0)
        {
          memcpy(offsetData, input + len - offset, offset);
          len -= offset;
        }
      }
 
      finish = Base64Decode(out, input, input + len ,count, with_new_line); 
      
      if(offsetData && offset != 0)
      { 
        memcpy(input, offsetData, offset);
      }
   
    }
    else
    {
      std::string str("TransCode:  Only Hex and Base64 are supported so far, sorry!");
      throw Error(str);
    }
 
  }
  return finish;
}

#endif //~__TRANSCODE_H__
