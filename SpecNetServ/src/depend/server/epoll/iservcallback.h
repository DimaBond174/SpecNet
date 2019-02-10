/*
 * This is the source code of SpecNet project
 * It is licensed under MIT License.
 *
 * Copyright (c) Dmitriy Bondarenko
 * feel free to contact me: specnet.messenger@gmail.com
 */

#ifndef ISERVCALLBACK_H
#define ISERVCALLBACK_H

#include <string>
#include "epolsocket.h"

class  IServCallback  {
 public:
  virtual const char * getMessagesPath()  =  0;
  virtual const char * getAvaCertsPath()  =  0;
  virtual const char * getAvaPicPath()  =  0;
  virtual std::string  getServPassword()  =  0;
  virtual EpolSocket * getStackSockNeedWorker()  =  0;
  virtual void  returnSocketToWork(EpolSocket  *sock)  =  0;
  virtual void  returnSocketToFree(EpolSocket  *sock)  =  0;
  virtual void  workerGoneDown(void  *worker)  =  0;
};

#endif // ISERVCALLBACK_H
