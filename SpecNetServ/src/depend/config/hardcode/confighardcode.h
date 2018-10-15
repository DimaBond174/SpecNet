#ifndef CONFIGHARDCODE_H
#define CONFIGHARDCODE_H

#include "i/iconfig.h"

class ConfigHardCode : IConfig {
public:
    ConfigHardCode();
    bool         loadConfig() override;    
    long long    getLongValue(const std::string & key)   override;
    std::string  getStringValue(const std::string & key) override;

};

#endif // CONFIGHARDCODE_H
