/*
 * This is the source code of SpecNet project
 * It is licensed under MIT License.
 *
 * Copyright (c) Dmitriy Bondarenko
 * feel free to contact me: specnet.messenger@gmail.com
 */

#ifndef ISYSTEM_H
#define ISYSTEM_H

#include <memory>
#include "ilib.h"

typedef bool (*TWaitFunc)(void  *ptr);

class  ISystem  {
 public:
  virtual ~ISystem()  { }
  virtual std::string  getExePath()  =  0;
  virtual std::string  execCmd(const char  *cmd)  =  0;
  virtual std::string  getSockPath(const char  *serviceName)  =  0;
  virtual std::string  sendCmd(const char  *serviceName,  const char  *cmd)  =  0;
  virtual bool  waitForSUCCESS(TWaitFunc  f,  void  *ptr,
    int msRepeat,  int msTimeout)  =  0;
  virtual std::shared_ptr<ILib>  openSharedLib(const char  *libPath)  =  0;
  virtual void  closeSharedLib(const std::shared_ptr<ILib>  &iLib)  =  0;
};

#endif // ISYSTEM_H
