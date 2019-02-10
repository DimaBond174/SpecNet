/*
 * This is the source code of SpecNet project
 * It is licensed under MIT License.
 *
 * Copyright (c) Dmitriy Bondarenko
 * feel free to contact me: specnet.messenger@gmail.com
 */

#ifndef ILIB_H
#define ILIB_H

/* Common interface of the any shared lib */
// must have extern "C" createInstance like that:
typedef void * (*TCreateFunc)();
// must have extern "C" deleteInstance like that:
typedef void (*TDeleteFunc)(void  *ptr);

class  ILib  {
 public:
  virtual ~ILib()  {  }
  TCreateFunc  createInstance  =  nullptr;
  TDeleteFunc  deleteInstance  =  nullptr;
  void  *lib_handle  =  nullptr;
};

#endif // ILIB_H
