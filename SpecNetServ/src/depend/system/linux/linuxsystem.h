/*
 * This is the source code of SpecNet project
 * It is licensed under MIT License.
 *
 * Copyright (c) Dmitriy Bondarenko
 * feel free to contact me: specnet.messenger@gmail.com
 */

#ifndef LINUXSYSTEM_H
#define LINUXSYSTEM_H

#include <string>
#include "i/isystem.h"

class LinuxSystem  :  public ISystem  {
 public:
  LinuxSystem();

  std::string  getExePath()  override;
  std::string  execCmd(const char  *cmd)  override;
  std::string  sendCmd(const char  *serviceName,  const char  *cmd)  override;
  std::string  getSockPath(const char  *serviceName)  override;
  bool  waitForSUCCESS(TWaitFunc  f,  void  *ptr,
    int  msRepeat,  int  msTimeout)  override;
  std::shared_ptr<ILib>  openSharedLib(const char  *libPath)  override;
  void  closeSharedLib(const std::shared_ptr<ILib>  &iLib)  override;

    /* static direct calls from system related classes: */
  static std::string  getExePathS();
  static std::string  getExeS();
  static std::string  execCmdS(const char  *cmd);
  static std::string  sendCmdS(const char  *serviceName,  const char  *cmd);
  static std::string  getSockPathS(const char  *serviceName);
  static std::shared_ptr<ILib>  openSharedLibS(const char  *libPath);
  static void  closeSharedLibS(const std::shared_ptr<ILib>  &iLib);
};

#endif // LINUXSYSTEM_H
