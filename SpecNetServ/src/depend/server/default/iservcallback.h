#ifndef ISERVCALLBACK_H
#define ISERVCALLBACK_H


class IServCallback {
public:
    virtual void  smartSocketDown(void * ptr)  = 0;
};


#endif // ISERVCALLBACK_H
