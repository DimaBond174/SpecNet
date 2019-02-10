/*
 * This is the source code of SpecNet project
 * It is licensed under MIT License.
 *
 * Copyright (c) Dmitriy Bondarenko
 * feel free to contact me: specnet.messenger@gmail.com
 */

#ifndef ILIBCLASS_H
#define ILIBCLASS_H

#include <memory>
#include "isystem.h"
#include "ilib.h"

/* Shared lib as SINGLE class instance */
template <class T>
class  ILibClass  {
 public:
  /* instance of the class from shared lib: */
  T  *i  =  nullptr;

  ILibClass(const std::shared_ptr<ISystem>  &iSystem,
      const char  *libPath)  :  _iSystem(iSystem)  {
    _iLib  =  iSystem.get()->openSharedLib(libPath);
    if  (_iLib)  {
      i  =  reinterpret_cast<T *>(_iLib.get()->createInstance());
    }
  }

  virtual  ~ILibClass()  {
    if  (_iLib)  {
      if  (i)  {
        _iLib.get()->deleteInstance(i);
        i  =  nullptr;
      }
      _iSystem.get()->closeSharedLib(_iLib);
    }
  }

 private:
  std::shared_ptr<ILib>  _iLib;
  std::shared_ptr<ISystem>  _iSystem;
};


#endif // ILIBCLASS_H
