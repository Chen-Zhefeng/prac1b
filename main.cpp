#include "Cipher.h"
#include <getopt.h>
#include <string.h>
#include <stdio.h>

using namespace std;

void ShowHelpInfo()
{
  printf("Usage: simplessl [option]...\n\n");
  printf("-m/--mode (calculate mode) you can input [encrypt|decrypt|digest|hmac]\n");
  printf("-a/--algorithom (algorithom used) you can input rc4, aes-128-cbc, md5, sha1 .etc]\n");
  printf("-k/--key (key value in HEX format) for example 0F0E0D0C0B0A0908 means a 8-byte key\n");
  printf("-v/--iv (initial vercter in HEX format)\n");
  printf("-i/--input (input file) for example in.txt\n");
  printf("-o/--output (output file) for example out.b64\n");
  printf("-f/--format (output/input format) [binary|hex|base64], binary as default\n");
  printf("-h/--help (show the help info)\n");
  printf("\n");
}

int main(int argc , char * argv[])
{

  int ret = 0;
  int c = 0;
  int option_index = 0;
  const char *mode = NULL;
  const char *algor = NULL;
  const unsigned char *key = NULL;
  const unsigned char *iv = NULL;
  const char *input = NULL;
  const char *output = NULL;
  const char *format = NULL;
  /**     
   *  定义命令行参数列表，option结构的含义如下（详见 man 3 getopt）：
   *  struct option {
   *      const char *name;      //参数的完整名称，对应命令中的 --xxx
   *      int  has_arg;   //该参数是否带有一个值，如 –config xxx.conf
   *      int *flag;      //一般设置为NULL
   *      int  val;       //解析到该参数后getopt_long函数的返回值，为了方便维护，一般对应getopt_long调用时第三个参数
   *  };
   */
  unsigned char isSet = 0;
  static struct option arg_options[] =
  {
    {"mode", 1, NULL, 'm'},
    {"algorithom", 1, NULL, 'a'},
    {"key", 1, NULL, 'k'},
    {"iv", 1, NULL, 'v'},
    {"input", 1, NULL, 'i'},
    {"output", 1, NULL, 'o'},
    {"format", 1, NULL, 'f'},
    {"help", 0, NULL, 'h'},
    {NULL, 0, NULL, 0}
  };

  /**
   *  注意：传递给getopt_long的第三个参数对应了命令行参数的缩写形式，如-h, -v, -c等，
   *  如果字符后面带有冒号，则说明该参数后跟一个值，如-c xxxxxx             
   */
  while ((c = getopt_long(argc, argv, ":m:a:k:v:i:o:f:h", arg_options, &option_index)) != -1) 
  {
    switch (c) 
    {
    case 'h':
      ShowHelpInfo();
      fprintf(stdout,"option is -%c, optarv is %s\n", c, optarg);
      return 0;
    case 'm':
      fprintf(stdout,"option is -%c, optarv is %s\n", c, optarg);
      mode = optarg;
      isSet |= 1;
      break;
    case 'a':
      fprintf(stdout,"option is -%c, optarv is %s\n", c, optarg);
      algor = optarg;
      isSet |= 2;
      break;
    case 'k':
      fprintf(stdout,"option is -%c, optarv is %s\n", c, optarg);
      key = (const unsigned char*)optarg;
      isSet |= 4;
      break;
    case 'v':
      fprintf(stdout,"option is -%c, optarv is %s\n", c, optarg);
      iv = (const unsigned char*)optarg;
      isSet |= 8;
      break;
    case 'i':
      fprintf(stdout,"option is -%c, optarv is %s\n", c, optarg);
      input = optarg;
      isSet |= 16;
      break;
    case 'o':
      fprintf(stdout,"option is -%c, optarv is %s\n", c, optarg);
      output = optarg;
      isSet |= 32;
      break;
    case 'f':
      fprintf(stdout,"option is -%c, optarv is %s\n", c, optarg);
        format = optarg;
      break;
    case '?':
      fprintf (stderr, "Unknown option -%c\n", optopt);
      ShowHelpInfo();
      return -1;
    case ':':
      fprintf (stderr, "Option -%c requires an argument\n", optopt);
      ShowHelpInfo();
      return -1;
    default:
      abort();  
    }
  }
  if(isSet & 1 == 0)
  {
    fprintf (stderr, "lack of mode!\n");
    ShowHelpInfo();
    return -1;
  }  
  if(isSet &  16 == 0)
  {
    fprintf (stderr, "lack of input file!\n");
    ShowHelpInfo();
    return -1;
  }
//default para
  if(key == NULL)
  {
    fprintf (stdout, "No key is inputed, default key(empty string) is used!\n");
    //key = (const unsigned char*)"";
  }
  if(iv == NULL)
  {
    fprintf (stdout, "No initial vector is inputed, default iv(empty string) is used!\n");
    //iv = (const unsigned char*)"";
  }
  if(format == NULL)
  { fprintf (stdout, "default format(binary) is used!\n");
    format = "binary";
  }

  OpenSSL_add_all_algorithms();
  try
  {
    if(!strcmp("encrypt", mode))  
    {
      if(algor == NULL)
      {  
        fprintf (stdout, "default algorithom(aes-128-cbc) is used!\n");
        algor = "aes-128-cbc";
      }
      CCipher ci(algor);
      if( output == NULL)
      {
        char tmp[20] ;
        sprintf(tmp, "newfile.%s.enc", format);
        output = tmp;
        printf("a new file \"%s\" is created!", output);
      }
      if(strcmp(format, "binary") && strcmp(format, "hex") && strcmp(format, "base64"))
      {
        fprintf (stderr, "Unknown formate: %s!\n", format);
        ShowHelpInfo();
        return -1;
      }
      if (!(ci.Encrypt(input, output, key, iv, format, NULL)))
        return -1;
      
    }
    else if(!strcmp("decrypt", mode)) 
    {
      if(algor == NULL)
      {  
        fprintf (stdout, "default algorithom(aes-128-cbc) is used!\n");
        algor = "aes-128-cbc";
      }
      CCipher ci(algor);
      if( output == NULL)
      {
        char tmp[20] ;
        sprintf(tmp, "newfile.%s.dec", format);
        output = tmp;
        printf("a new file \"%s\" is created!", output);
      }
      if(strcmp(format, "binary") && strcmp(format, "hex") && strcmp(format, "base64"))
      {
        fprintf (stderr, "Unknown format: %s!\n", format);
        ShowHelpInfo();
        return -1;
      }
      if (!(ci.Decrypt(input, output, key, iv, format, NULL)))
        return -1;
       
    }
    else if(!strcmp("digest", mode))
    {
    }
    else if(!strcmp("hmac", mode))
    {
    }
    else
    {
      fprintf (stderr, "Known mode \"%s\"!\n", mode);
      ShowHelpInfo();
      return -1;
    }
  }
  catch (string str)
  {
    cout << str;
  }

  EVP_cleanup();
  return 0;
}


