#include "transcode.h"

unsigned char *Byte2Hex (const unsigned char* input, int inlen, bool with_new_line)
{
  int rv = 0;
  int i = 0, j = 0;
  unsigned char tmp = 0;
  unsigned char *output = NULL;
  int outlen = 0;
/*  if (outlen - 1 < inlen * 2)
  {
    fprintf(stderr, "Byte2Hex: output length(%d) is to short!", outlen);
    rv = -1;
    goto err;
  }
*/
  if (!input)
  {
    fprintf(stderr, "Byte2Hex: input null pointer!");
    goto err;
  }
  if (!with_new_line)
    outlen = inlen * 2 + 1;
  else
    outlen = inlen * 2 + inlen / 32 + 1 + ((inlen * 2 ) % 64 != 0); 


  if (!(output = (unsigned char*)malloc(outlen)))
  {
    fprintf(stderr, "Byte2Hex: function malloc fail");
    goto err;
  }
  for (; i < inlen; ++i)
  {
    tmp = (input[i] & 0xF0) >> 4;
    if(tmp < 10) 
      output[j++] = tmp + '0';
    else
      output[j++] = tmp - 0x0A + 'A';

    tmp = (input[i] & 0x0F);
    if(tmp < 10) 
      output[j++] = tmp + '0';
    else
      output[j++] = tmp - 0x0A + 'A';
    if (with_new_line)
    {
      if (0 == (j+1) % 65)    //every 64-character, new line
      output[j++] = '\n';
    }
  }
  if (with_new_line && j % 65 != 0)
    output[j++] = '\n';
  output[j] = '\0';

err:
    return output;
}

//Note: piolen is a input&output para
unsigned char *Hex2Byte (const unsigned char* input, int *piolen, bool with_new_line)
{
  int i = 0, j = 0;
  unsigned char tmp = 0;
  unsigned char *output = NULL;
  int outlen = 0;
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
/*  if (outlen - 1  < inlen / 2)
  {
    fprintf(stderr, "Hex2Byte: output length(%d) is to short!", outlen);
    rv = -1;
    goto err;
   }
*/
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
  for (; i < *piolen; i += 2, ++j)
  {
    tmp = input[i];
    if (tmp >= '0' && tmp <= '9')
    {
      tmp -= '0';
    }
    else if (tmp >= 'a' && tmp <='z' || tmp >= 'A' && tmp <= 'Z')
    {
      tmp = (unsigned char)toupper((int)tmp) - 'A' + 0x0A;
    }
    else
    {
      fprintf(stderr, "Hex2Byte: input format error!");
      free(output);
      output = NULL;
      goto err;
    }
    output[j] = (tmp << 4);

    tmp = input[i+1];
    if (tmp >= '0' && tmp <= '9')
    {
      tmp -= '0';
    }
    else if (tmp >= 'a' && tmp <='z' || tmp >= 'A' && tmp <= 'Z')
    {
      tmp = (unsigned char)toupper((int)tmp) - 'A' + 0x0A;
    }
    else
    {
      fprintf(stderr, "Hex2Byte: input format error!");
      free(output);
      output = NULL;
      goto err;
    }
    output[j] |= tmp;

    if(with_new_line)    //skip '\n'
    {
      if (0 == (i + 3) % 65)
        ++i;
    }
  }
  *piolen = outlen;
//dont need anymore
//  output[j] = '\0';

err:
  return output;
}

unsigned char * Base64Encode(const unsigned char * input, int length, bool with_new_line)
{
  BIO * bmem = NULL;
  BIO * b64 = NULL;
  BUF_MEM * bptr = NULL;
  unsigned char *buff = NULL;
  if(!input)
  {
    fprintf(stderr, "Base64Encode: input is null pointer!");
    goto err;
  }

  b64 = BIO_new(BIO_f_base64());
  if (!with_new_line)
  {
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  }
  bmem = BIO_new(BIO_s_mem());
  b64 = BIO_push(b64, bmem);  //形成BIO链
  BIO_write(b64, input, length);
  BIO_flush(b64);
  BIO_get_mem_ptr(b64, &bptr);

  if (!(buff = (unsigned char *)malloc(bptr->length + 1)))
  {
    fprintf(stderr, "Hex2Byte: function malloc fail");
    BIO_free_all(b64);
    goto err;
  }
  memcpy(buff, bptr->data, bptr->length);
  buff[bptr->length] = 0;

  BIO_free_all(b64);
err:
  return buff;
}

//Note: piolen is a input&output para
unsigned char* Base64Decode(const unsigned char *input, int* piolen, bool with_new_line)
{
  BIO *b64 = NULL;
  BIO *bmem =NULL;
  int outlen = 0;
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

  b64 = BIO_new(BIO_f_base64());
  if (!with_new_line)
  {
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  }
  bmem = BIO_new_mem_buf((void*)input, *piolen);
  b64 = BIO_push(b64, bmem);  //
  //之前由于把最后一个空格干掉了，导致b64转换错误
  BIO_read(b64, buffer, outlen);

  BIO_free_all(b64);
  *piolen = outlen;
err:
  return buffer;
}

