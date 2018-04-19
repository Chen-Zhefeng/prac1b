#include <functional>
#include <utility>
using namespace std;

class ScopeGuard {
private:
    typedef std::function<void()> destructor_type;

    destructor_type destructor_;
    bool dismissed_;

public:
    ScopeGuard(destructor_type destructor ) : destructor_(destructor), dismissed_(false) {}

    ~ScopeGuard()
    {
        if (!dismissed_) {
            destructor_();
        }
    }

    void dismiss() { dismissed_ = true; }

    ScopeGuard(ScopeGuard const&) = delete;
    ScopeGuard& operator=(ScopeGuard const&) = delete;
};

template <typename T>
class malloc_free 
{
private:
  T* ptr_;
public:
  malloc_free(T*& ptr) : ptr_(ptr) {}
  void operator() () 
  { if(ptr_) 
      free(ptr_); 
    ptr_ = NULL;
  }
  
  malloc_free(const malloc_free&);
  malloc_free& operator=(malloc_free const&);
  malloc_free(malloc_free&& s) noexcept :  ptr_(move(s.ptr_))
  {
      s.ptr_ = NULL;  
  }
  malloc_free&  operator=(malloc_free&& s) noexcept 
  {
    if(this!=&s)
    {
     ptr_ = move(s.ptr_);
     s.ptr_ = NULL;
    }
    return *this;
  }
};


template <typename T>
class new_delete
{
private:
  T* ptr_;
public:
  new_delete(T*& ptr) : ptr_(ptr) {}
  void operator() () 
  { 
    if (ptr_)
      delete ptr_;
    ptr_ = NULL; 
  }
  new_delete(new_delete const&) ;
  new_delete& operator=(new_delete const&) ;
  new_delete(new_delete&& s) noexcept :  ptr_(move(s.ptr_))
  {
      s.ptr_ = NULL;  
  }
  new_delete&  operator=(new_delete&& s) noexcept 
  {
    if(this!=&s)
    {
     ptr_ = move(s.ptr_);
     s.ptr_ = NULL;
    }
    return *this;
  } 
};

template <typename T>
class news_delete
{
private:
  T* ptr_;
public:
  news_delete(T*& ptr) : ptr_(ptr) {}
  void operator() () 
  { 
    if (ptr_)
      delete[] ptr_;
    ptr_ = NULL; 
  }
  news_delete(news_delete const&) ;
  news_delete& operator=(news_delete const&) ;
  news_delete(news_delete&& s) noexcept :  ptr_(move(s.ptr_))
  {
      s.ptr_ = NULL;  
  }
  news_delete&  operator=(news_delete&& s) noexcept 
  {
    if(this!=&s)
    {
     ptr_ = move(s.ptr_);
     s.ptr_ = NULL;
    }
    return *this;
  } 
};

class file_close 
{
private:
  FILE* fp_;
public:
  file_close(FILE*& fp) : fp_(fp) {}
  void operator() () 
  { if (fp_)
      fclose(fp_); 
    fp_ = NULL; 
  }
  file_close(file_close const&) ;
  file_close& operator=(file_close const&);
  file_close(file_close&& s) noexcept : fp_(move(s.fp_))
  {
    s.fp_ = NULL;
  }
  file_close& operator= (file_close&& s) noexcept
  {
    file_close tmp(move(s));
    using std::swap;
    swap(tmp, *this);
    return *this;
  }

};





