#ifndef ISERVCALLBACK_H
#define ISERVCALLBACK_H

#include <string>

class IServCallback {
public:
//    virtual void  onSocketEvent()  = 0;
    virtual const char * getMessagesPath() = 0;
    virtual const char * getAvaCertsPath() = 0;
    virtual std::string getServPassword() = 0;
};


#endif // ISERVCALLBACK_H
