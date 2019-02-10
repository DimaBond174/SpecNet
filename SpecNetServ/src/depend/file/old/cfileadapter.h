#ifndef CFILEADAPTER_H
#define CFILEADAPTER_H

#include "i/ifileadapter.h"

class CFileAdapter: public IFileAdapter
{
public:
    CFileAdapter();

/* interface methods */
    int saveTFile(const char * path, const char * data, uint32_t len) override;
    std::string getExePath()                      override;
    bool setExePath(const std::string& path)      override;
    std::string loadFileF(const char * path)       override;
    std::string loadFileR(const char * path)       override;
    std::string toFullPath(const char * path)     override;
    void mkdirs(const std::string& filePath)      override;
    std::string getDir (const std::string& filePath) override;
    void delOld(const std::string& dir, unsigned int keepCount) override;
    uint64_t removeAll(const char * path) override;
    bool file_exists(const char * path) override;

/* static members */
    std::string loadFileS(const char * filePath);
    static void mkdirsS(const std::string& filePath)     ;
    static std::string getDirS (const std::string& filePath);
    static void delOldS(const std::string& dir, unsigned int keepCount);
    //static bool file_exists(const char * path);
    static bool file_existsS(const char * path);
    static bool saveTFileS(const char * filePath, const char * data, unsigned long len);

    static uint64_t removeAllS(const char * path);    

private:
    std::string _exePath;

    static bool mkdir_p(const char * filePath);
};

#endif // CFILEADAPTER_H
