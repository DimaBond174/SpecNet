#ifndef CONFIGJSON_H
#define CONFIGJSON_H

#include <map>
#include "i/iconfig.h"
#include "depend/config/hardcode/confighardcode.h"
#include "depend/tools/specjson.h"

class ConfigJson : public IConfig {
public:
    ConfigJson();
    bool         loadConfig() override;    
    long long    getLongValue(const std::string & key)   override;
    std::string  getStringValue(const std::string & key) override;

private:    
    ConfigHardCode defConfig;
    std::map<std::string, std::string> mapConfig;

    void traverse(TNode * node);
};

#endif // CONFIGJSON_H
