#include "cfileadapter.h"
#include <fstream>
#include <streambuf>
#include <sys/types.h>

#include <stdio.h>

#include <string.h>
#include <limits.h>     /* PATH_MAX */
#include <sys/stat.h>   /* mkdir(2) */
#include <errno.h>
#include <algorithm>
#include <vector>

#include "spec/specstatic.h"
#include <iostream>
#if defined(Windows)
#include <direct.h>
#ifndef PATH_MAX 
#define PATH_MAX _MAX_PATH
#endif // !
#endif

CFileAdapter::CFileAdapter()
{

}


bool CFileAdapter::setExePath(const std::string& path) {
    _exePath = path;
    if (_exePath.empty()) {
        return false;
    }
    return true;
}

std::string CFileAdapter::getExePath() {
    return _exePath;
}

std::string CFileAdapter::toFullPath(const char * path) {
    std::string re;
    if (path) {
        if('.'==path[0] && '/'==path[1]) {
            re.append(_exePath)
              .append((path+1));
        } else {
            re.append(path);
        }
    }
    return re;
}

std::string CFileAdapter::loadFileF(const char * path) {
    return loadFileS(path);
}

std::string CFileAdapter::loadFileR(const char * path) {
    std::string re (_exePath);
    re.append(path);
    return loadFileS(re.c_str());
}



std::string CFileAdapter::loadFileS(const char * filePath) {
    std::string str;
    if (file_exists(filePath)) {
        std::ifstream t(filePath);
        t.seekg(0, std::ios::end);
        str.reserve(t.tellg());
        t.seekg(0, std::ios::beg);

        str.assign((std::istreambuf_iterator<char>(t)),
                   std::istreambuf_iterator<char>());
    }
    return str;
}




void CFileAdapter::mkdirs(const std::string& filePath) {
    CFileAdapter::mkdirsS(filePath);
}

void CFileAdapter::mkdirsS(const std::string& filePath) {
    /* Adapted from http://stackoverflow.com/a/2336245/119527 */
    //const size_t len = strlen(path);
    const size_t len = filePath.length();
    char _path[PATH_MAX];
    char *p;

    errno = 0;

    if (len > sizeof(_path)-1) {
        errno = ENAMETOOLONG;
        return;
    }
    //strcpy(_path, path);
    strcpy(_path, filePath.c_str());

    /* Iterate the string */
    for (p = _path + 1; *p; p++) {
        if (*p == '/' || *p == '\\') {
            /* Temporarily truncate */
            *p = '\0';

#if defined(Windows)
			if (_mkdir(_path) != 0) {
#else
			if (mkdir(_path, S_IRWXU) != 0) {
#endif
                if (errno != EEXIST)
                    return;
            }

            *p = '/';
        }
    }

#if defined(Windows)
	if (_mkdir(_path) != 0) {
#else
	if (mkdir(_path, S_IRWXU) != 0) {
#endif
        if (errno != EEXIST)
            return;
    }

    return;
}

std::string CFileAdapter::getDir (const std::string& filePath) {
    return CFileAdapter::getDirS(filePath);
}

std::string CFileAdapter::getDirS (const std::string& filePath) {
    size_t found = filePath.find_last_of("/\\");
    return(filePath.substr(0, found));
}



void CFileAdapter::delOld(const std::string& dir, unsigned int keepCount) {
    delOldS(dir, keepCount);
}

void CFileAdapter::delOldS(const std::string& dir, unsigned int keepCount) {

}

bool CFileAdapter::file_existsS(const char * path) {
    struct stat fileStat;
    if ( stat(path, &fileStat) )
    {
        return false;
    }
#ifndef Windows
    if ( !S_ISREG(fileStat.st_mode) )
    {
        return false;
    }
#endif
    return true;
}

int CFileAdapter::saveTFile(const char * path, const char * data, uint32_t len) {
    int re = -1;
    if (!file_exists(path)) {
        if (saveTFileS(path, data, len)) {
            re = 1;
        } else {
            re = -2;
        }
    }
    return re;
}

bool CFileAdapter::saveTFileS(const char * filePath,  const char * data, unsigned long len) {
    bool re = false;
    if (mkdir_p(filePath)) {
        std::ofstream outfile (filePath);
        outfile.write (data, len);
        outfile.close();
        re = true;
    }
    return re;
}

/* Local usage for saveFile to enshure file path exists */
bool CFileAdapter::mkdir_p(const char * filePath){
    if (!(filePath && *filePath) ) { return false;}
    char _path[PATH_MAX];
    char *p = _path;
    char *end = _path + PATH_MAX;
    *p = *filePath;
    ++p;
    ++filePath;

    while (*filePath && p<end) {
        if ('/'==*filePath || '\\'==*filePath) {
            *p = 0;
#if defined(Windows)
			if (_mkdir(_path) != 0) {
#else
			if (mkdir(_path, S_IRWXU) != 0) {
#endif
                if (errno != EEXIST)
                    return false;
            }
        }
        *p = *filePath;
        ++p;
        ++filePath;
    }

    return true;
}

uint64_t CFileAdapter::removeAll(const char * path) {
    return  removeAllS(path);
}

uint64_t CFileAdapter::removeAllS(const char * path) {
    return 0;
}

bool CFileAdapter::file_exists(const char * path) {
  return file_existsS(path);
}

