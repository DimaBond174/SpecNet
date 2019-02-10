/*
 * This is the source code of SpecNet project
 * It is licensed under MIT License.
 *
 * Copyright (c) Dmitriy Bondarenko
 * feel free to contact me: specnet.messenger@gmail.com
 */

#ifndef ISERVER_H
#define ISERVER_H

class  IServer  {
 public:
  virtual  ~IServer()  {  }
    //Working
  virtual bool  start()  =  0;
  virtual void  stop()  =  0;
};

#endif // ISERVER_H
