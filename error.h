#ifndef __ERROR_H__
#define __ERROR_H__

#include <exception>
#include <string>
#include <iostream>
#include <sstream>

class Error : public std::exception
{
public:
  Error(const std::string& msg): msg_(msg) {}
  virtual ~Error() noexcept {}
  virtual const char* what() const noexcept
  {
    return msg_.c_str();
  }
private:
  std::string msg_;

};


class SSLError : public std::exception
{
public:
  SSLError(const std::string& msg) : err_ (ERR_get_error())
  {
    std::ostringstream oss(msg + "\n");
    ERR_print_errors_cb(reinterpret_cast<int (*) (const char* str, size_t, void*)> (get_ssl_errmsg),
        reinterpret_cast<void*> (&oss));
    msg_ = oss.str();
  }
  virtual ~SSLError() noexcept {}
  virtual const char* what() const noexcept {return msg_.c_str();}
  size_t errcode() const {return err_;}
  
private:
  size_t err_;
  std::string msg_;
  static int get_ssl_errmsg(const char* str, size_t, std::ostringstream* oss)
  {
  *oss << str;
  return 0;
  }
};


#endif //~__ERROR_H__
