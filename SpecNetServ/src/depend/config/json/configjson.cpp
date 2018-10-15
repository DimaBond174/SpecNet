#include <iostream>
#include "configjson.h"
#include "spec/speccontext.h"


ConfigJson::ConfigJson(){

}


bool  ConfigJson::loadConfig() {
    bool re = false;
    mapConfig.clear();
    std::string json = SpecContext::instance().iFileAdapter.get()
            ->loadFileR("/assets/settings.json");
    int length = json.length();
    if (length > 0) {
        try {
            const sajson::document &document =
                sajson::parse(sajson::dynamic_allocation(),
                          sajson::string(json.c_str(), length));
            if (document.is_valid()) {
                std::string str;
                traverse(str, document.get_root());
            } //if (document.is_valid()
            re = true;
        } catch (int err_id)  {
            std::cerr << "Error: ConfigJson::loadConfig:err_id:" << err_id << std::endl;
        } catch(...) {
            std::cerr << "Error: ConfigJson::loadConfig:err_id:" << std::endl;
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


void ConfigJson::traverse(const std::string & key, const sajson::value& node) {
    using namespace sajson;
    std::string str;
    switch (node.get_type()) {
//        case TYPE_NULL:
//            ++stats.null_count;
//            break;

//        case TYPE_FALSE:
//            ++stats.false_count;
//            break;

//        case TYPE_TRUE:
//            ++stats.true_count;
//            break;

        case TYPE_ARRAY: {
            //++stats.array_count;
            auto length = node.get_length();
            //stats.total_array_length += length;
            for (size_t i = 0; i < length; ++i) {
                traverse(str, node.get_array_element(i));
            }
            break;
        }

        case TYPE_OBJECT: {
            //++stats.object_count;
            auto length = node.get_length();
            //stats.total_object_length += length;
            for (auto i = 0u; i < length; ++i) {
                traverse(node.get_object_key(i).as_string(), node.get_object_value(i));
            }
            break;
        }

        case TYPE_STRING:
            //++stats.string_count;
            //stats.total_string_length += node.get_string_length();
            if (!key.empty()) {
                mapConfig.insert(std::make_pair(key, node.as_string()));
            }

            break;

//        case TYPE_DOUBLE:
//        case TYPE_INTEGER:
//            ++stats.number_count;
//            stats.total_number_value += node.get_number_value();
//            break;

        default:
            assert(false && "unknown node type");
    }
}
