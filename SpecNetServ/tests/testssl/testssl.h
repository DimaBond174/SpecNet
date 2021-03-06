#ifndef TestSSL_H
#define TestSSL_H

#include <string>
#include "i/ilib.h"
#include "i/ipack.h"

class TestSSL  :  public ILib  {
 public:
  TestSSL() {  }
  virtual ~TestSSL(){  }
  //std::string  getTAG()  {  return std::string(TAG);  }

  virtual bool  sslConnect(const char  *host,  const char  *port,  int  idleConnLife) = 0;
  virtual void  stop()  =  0;
  virtual int  getJobResults()  =  0;
  virtual bool  putPackToSend(IPack  *ptr)  =  0;
  virtual IPack * readPack()  =  0;
  virtual time_t  getLastActTime()  =  0;
  virtual bool  setPKEY(const char  *pkey,  int  len)  =  0;
  virtual bool  sign_it(const void  *msg,  int  msglen,  void  *sig,  int  *slen)  =  0;
  virtual bool  setX509(const char  *x509str,  int  len)  =  0;
  virtual bool  set_group_X509(uint64_t  groupID,  const char  *x509str,  int  len)  =  0;
  virtual bool  checkAvaSign(const void  *msg,  size_t  mlen,  const void  *sig,  size_t  slen)  =  0;
  virtual long long  getGUID09()  =  0;
  virtual bool  checkX509(uint64_t  groupID,  uint64_t  avatarID,
        const char  *strX509,  int  strX509len)  =  0;
//private:
//    const char * const TAG = "TestSSL";
};



#endif // TestSSL_H
