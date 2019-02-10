/*
 * This is the source code of SpecNet project
 * It is licensed under MIT License.
 *
 * Copyright (c) Dmitriy Bondarenko
 * feel free to contact me: specnet.messenger@gmail.com
 */

#ifndef SPECSTACK_H
#define SPECSTACK_H

#include <atomic>

class  IStack  {
 public:
  IStack  *nextIStack;
};

template  <typename  T  =  IStack>
class  SpecStack  {
 public:
  bool not_empty()  {
    if  (head)  {  return true;  }
    return false;
  }

  void  push(T * node)  {
    node->nextIStack  =  head;
    head  =  node;
  }

  T * pop()  {
    if  (head)  {
      T  *re  =  head;
      head  =  re->nextIStack;
      return re;
    }
    return nullptr;
  }

  void  swap(SpecStack  &other) {
    T  *re  =  head;
    head  =  other.head;
    other.head  =  re;
    return;
  }

  T * swap(T  *newHead)  {
    T  *re  =  head;
    head  =  newHead;
    return  re;
  }

 private:
  T  *head  {  nullptr  };
};

template <typename T = IStack>
class SpecSafeStack {
    std::atomic<T*> head {nullptr};
public:
    void push(T * node)  {
        node->nextIStack=head.load();
        while(!head.compare_exchange_weak(node->nextIStack, node)){}
    }

    T * getStack(){
        return head.exchange(nullptr, std::memory_order_acq_rel);
    }

    T * swap(T * newHead){
        return head.exchange(newHead, std::memory_order_acq_rel);
    }
};

#endif // SPECSTACK_H
