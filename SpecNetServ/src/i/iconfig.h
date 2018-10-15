#ifndef ICONFIG_H
#define ICONFIG_H

#include <string>

class IConfig {
public:
    virtual ~IConfig() {}
    virtual bool         loadConfig()    = 0;    
    virtual long long    getLongValue(const std::string & key)   = 0;
    virtual std::string  getStringValue(const std::string & key) = 0;
};
#endif // ICONFIG_H
