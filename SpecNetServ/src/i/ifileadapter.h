#ifndef IFILEADAPTER_H
#define IFILEADAPTER_H

#include <string>

class IFileAdapter {
public:
    virtual ~IFileAdapter() {}
    /* Text file saveTFile = 1==OK, -1==Exists, -2==Can't */
    virtual int saveTFile(const char * path, const char * data, uint32_t len) = 0;
    /* Full path */
    virtual std::string loadFileF(const char * path)       = 0;
    /* path Relative to the executable */
    virtual std::string loadFileR(const char * path)       = 0;

    virtual std::string toFullPath(const char * path)      = 0;
    virtual void mkdirs(const std::string& filePath)        = 0;
    virtual std::string getDir(const std::string& filePath) = 0;
    virtual void delOld(const std::string& dir, unsigned int keepCount) = 0;

    virtual std::string getExePath()                  = 0;
    virtual bool setExePath(const std::string& path)  = 0;
    virtual uint64_t removeAll(const char * path)     = 0;

};

#endif // IFILEADAPTER_H
