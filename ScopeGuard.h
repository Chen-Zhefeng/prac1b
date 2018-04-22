#include <functional>
#include <utility>
using namespace std;

class ScopeGuard {
private:
    typedef std::function<void()> destructor_type;

    destructor_type destructor_;
    bool dismissed_;

public:
    ScopeGuard(const destructor_type& destructor) : destructor_(destructor), dismissed_(false) {}
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

};





