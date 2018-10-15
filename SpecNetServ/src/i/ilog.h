#ifndef ILOG_H
#define ILOG_H

#include <string>
#include <cstdio>
#if defined(Windows)
#define snprintf sprintf_s
#endif


class ILog {
public:
    virtual ~ILog() {}
    virtual bool start() = 0;
    virtual void stop()  = 0;    
    virtual void rawLog(const char * lvl, const std::string &str) = 0;

    /*
     * log works as fprintf
     * lvl = "i"/"w"/"e" == "info", "warn", "error"
     * tag = where
     * fmt + args = what
    */
    template<typename ... Args>
    void log(const char * lvl, const char * fmt, Args ... args) {
        auto szData = std::snprintf(nullptr, 0, fmt, args...);
        if (szData > 0) {
            ++szData; //include \0
            std::string strData;
            strData.reserve(szData);
            strData.resize(szData-1);
            std::snprintf(&strData.front(), szData, fmt, args...);            
            rawLog(lvl, strData);
        }
    }
};

#endif // ILOG_H
