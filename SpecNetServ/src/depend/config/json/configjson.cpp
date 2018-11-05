#include <iostream>
#include "configjson.h"
#include "spec/speccontext.h"
#include "spec/specstatic.h"


ConfigJson::ConfigJson(){

}


bool  ConfigJson::loadConfig() {
    bool re = false;
    mapConfig.clear();
    const std::string &json = SpecContext::instance().iFileAdapter.get()
            ->loadFileR("/assets/settings.json");
    int length = json.length();
    if (length > 0) {
		SpecJson specJson(json.c_str(), length, false);
		if (specJson.parse()) {
			traverse(specJson.getFirstNodeOfObject(nullptr));
			re = true;
		}      
    }//if (length > 0)

    for (std::map<std::string,std::string>::const_iterator it = mapConfig.begin();
            it!=mapConfig.end(); ++it) {
        std::cout << it->first << " : " << it->second << std::endl;
    };

    return re;
}


std::string  ConfigJson::getStringValue(const std::string & key) {
    std::map<std::string, std::string>::const_iterator it_exists
            = mapConfig.find(key);
    if (it_exists != mapConfig.end()) {
        return it_exists->second;
    } else {
        return defConfig.getStringValue(key);
    }
}

long long ConfigJson::getLongValue(const std::string & key) {
    const std::string & strVal = getStringValue(key);
    long long re = 0;
    int len = strVal.length();
    if (len > 0) {
        re = stoll(strVal.c_str(), len);
    }
    return re;
}

void ConfigJson::traverse(TNode * node) {
	TNode * cur = node;
	while (cur) {
		switch (cur->type) {
		case 's':
		case 'd':
			if (cur->lenKey>0 && cur->lenData>0) {
				mapConfig.insert(std::make_pair(
					std::string(cur->pKey, cur->lenKey),
					std::string((const char *)cur->pData, cur->lenData)));
			}
		break;
		case 'o':
			traverse(cur);
			break;
		default:
			std::cerr << "Error: ConfigJson::TNode->type=" << cur->type << std::endl;
			break;
		}
		cur = cur->nextNode;
	}
}


