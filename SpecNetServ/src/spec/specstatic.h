/*
 * This is the source code of SpecNet project
 * It is licensed under MIT License.
 *
 * Copyright (c) Dmitriy Bondarenko
 * feel free to contact me: specnet.messenger@gmail.com
 */

#ifndef SPECSTATIC_H
#define SPECSTATIC_H

#include <limits.h>
#include <stdint.h>
#include <cstddef>

/* SpecNet const: */
#define GUID_LEN 19
#define SMAX_GROUPS 100
#define SMAX_PATH 300
#define MIN_GUID 1000000000000000000
#define MAX_SelectRows 50

//uint32                  4294967295
//max                     2147483647
#define SERV_TYPE 1923082018
#define CLI_TYPE    1924082018

/* default times in ms: */
#define DEADLOCK_TIME 5000
#define WAIT_TIME 100
constexpr int64_t DAY_MILLISEC = 24*60*60*1000;

/* default array sizes in bytes: */
#define  EPOLL_WAIT_POOL 21
#define  BUF_SIZE 4096




/* aka SSL codes */
//#define ISSL_ERROR_NONE 0
//#define ISSL_ERROR_SSL 1
//#define ISSL_ERROR_WANT_READ 2
//#define ISSL_ERROR_WANT_WRITE 3
//#define ISSL_ERROR_WANT_X509_LOOKUP 4
//#define ISSL_ERROR_SYSCALL 5
//#define ISSL_ERROR_ZERO_RETURN 6
//#define ISSL_ERROR_WANT_CONNECT 7
//#define ISSL_ERROR_WANT_ACCEPT 8
//#define ISSL_ERROR_WANT_CHANNEL_ID_LOOKUP 9
//#define ISSL_ERROR_PENDING_SESSION 11
//#define ISSL_ERROR_PENDING_CERTIFICATE 12
//#define ISSL_ERROR_WANT_PRIVATE_KEY_OPERATION 13
//#define ISSL_ERROR_PENDING_TICKET 14
//#define ISSL_ERROR_EARLY_DATA_REJECTED 15
//#define ISSL_ERROR_WANT_CERTIFICATE_VERIFY 16
//#define ISSL_ERROR_HANDOFF 17
//#define ISSL_ERROR_HANDBACK 18

//#define TO12(x) ((((x)>>5)%12))
//until about the month counter % 12:
#define TO12(x) ((((x)>>31)%12))

/*  Converts string to number
  first  -  poiner to the first character
  len - expected length, its OK if string ends earlier
 */
inline  int64_t  stoll(const char  *first,  int  len)  {
  if (len  >  GUID_LEN)  {
    len  =  GUID_LEN;
  }
  const char  *last  =  first  +  len;
  uint64_t  re  = 0ULL; //  18 446 744 073 709 551 615 = 20
  for (const char *ch  =  first;  *ch  &&  ch<last;  ++ch)  {
    if  (*ch<'0'  ||  *ch>'9')  {  break;  }
      re  =  10 * re  +  *ch  -  '0';
    }
    return  (re  >  LLONG_MAX)?  LLONG_MAX  :  re;
}

/* Prints chars to the string buffer.
  Used for quickly build strings.
  str - chars to be printed
  start - string buffer
  end - end of the string buffer, must be valid for change
*/
inline char  *  printString(const char  *str,  char  *start,  char  *end){
  while  (*str  &&  start < end)  {
    *start  =  *str;
    ++start;
    ++str;
  }
    //if (start<end) { *start =0; }
  *start  =  0;  //  *end must be valid for change
  return start;
}

/* Prints uint64_t to the string buffer.
  Used for quickly build strings.
  n - uint64_t to be printed
  start - string buffer
  end - end of the string buffer, must be valid for change
*/
inline char  *  printULong(uint64_t  n,  char  *start,  char  *end)  {
  if (0==n)  {
    *start ='0';
    ++start;
  }  else  {
    char  buf[24];
    char  *ch  =  buf;
    uint64_t  n1  =  n;
    while  (0!=n1)  {
      *ch  =  n1%10  +  '0';
      ++ch;
      n1  =  n1/10;
    }
    --ch;
    while  (ch>=buf  &&  start<end)  {
      *start  =  *ch;
      ++start;
      --ch;
    }
  }
    //if (start<end) { *start =0; }
  *start  =  0;  //  *end must be valid for change
  return start;
}

/* Constexpr exception free string class.
  Used for static const strings.
*/
class  ConstString  {
 public:
  template<std::size_t N>
  constexpr ConstString(const char (&str)[N])
    :  c_str(str),  size(N - 1) {
  }

  constexpr char operator[](std::size_t  n) {
    return  (n < size)?  c_str[n]  :  '\0';
  }

  char const  *const  c_str;
  //const std::size_t size;
  const int  size; //SQLite wants int
};

#define CONCATE_(X,Y) X##Y
#define CONCATE(X,Y) CONCATE_(X,Y)
#define UNIQUE(NAME) CONCATE(NAME, __LINE__)

struct Static_
{
  template<typename T> Static_ (T lambda) { lambda(); }
  ~Static_ () {}  // to counter unused variable warning
};

#define STATIC static Static_ UNIQUE(block) = [&]() -> void

#endif // SPECSTATIC_H
