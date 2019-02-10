/*
 * This is the source code of SpecNet project
 * It is licensed under MIT License.
 *
 * Copyright (c) Dmitriy Bondarenko
 * feel free to contact me: specnet.messenger@gmail.com
 */

#ifndef ICONFIG_H
#define ICONFIG_H

#include <string>

class  IConfig  {
 public:
  virtual ~IConfig()  {  }
  virtual bool  loadConfig()  =  0;
  virtual long long  getLongValue(const std::string  &key)  =  0;
  virtual std::string  getStringValue(const std::string  &key)  =  0;
};
#endif // ICONFIG_H
