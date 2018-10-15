#include "fileadapter.h"
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

FileAdapter::FileAdapter() { }


bool FileAdapter::setExePath(const std::string& path) {
    _exePath = path;
    if (_exePath.empty()) {
        return false;
    }
    return true;
}

std::string FileAdapter::getExePath() {
    return _exePath;
}

std::string FileAdapter::toFullPath(const char * path) {
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

std::string FileAdapter::loadFileF(const char * path) {
    return loadFileS(path);
}

std::string FileAdapter::loadFileR(const char * path) {
    std::string re (_exePath);
    re.append(path);
    return loadFileS(re.c_str());
}


std::string FileAdapter::loadFileS(const char * filePath) {
    std::string str;
    if (fs::exists(filePath)) {
        std::ifstream t(filePath);
        t.seekg(0, std::ios::end);
        str.reserve(t.tellg());
        t.seekg(0, std::ios::beg);

        str.assign((std::istreambuf_iterator<char>(t)),
                   std::istreambuf_iterator<char>());
    }
    return str;
}


//bool FileAdapter::file_exists(const char * path) {
//    struct stat fileStat;
//    if ( stat(path, &fileStat) )
//    {
//        return false;
//    }
//    if ( !S_ISREG(fileStat.st_mode) )
//    {
//        return false;
//    }
//    return true; //Есть такой и это файл
//}


void FileAdapter::mkdirs(const std::string& filePath) {
    FileAdapter::mkdirsS(filePath);
}

void FileAdapter::mkdirsS(const std::string& filePath) {
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

            if (mkdir(_path, S_IRWXU) != 0) {
                if (errno != EEXIST)
                    return;
            }

            *p = '/';
        }
    }

    if (mkdir(_path, S_IRWXU) != 0) {
        if (errno != EEXIST)
            return;
    }

    return;
}

std::string FileAdapter::getDir (const std::string& filePath) {
    return FileAdapter::getDirS(filePath);
}

std::string FileAdapter::getDirS (const std::string& filePath) {
    size_t found = filePath.find_last_of("/\\");
    return(filePath.substr(0, found));
}

std::vector<t_file_info> FileAdapter::file_list( const fs::path& dir ) {
    std::vector<t_file_info> result ;

    for( const auto& p : fs::recursive_directory_iterator(dir) )
    {
        const auto& path = p.path() ;
        if( fs::is_regular_file(path) )
            result.push_back( t_file_info {
                                  path
                                  ,fs::last_write_time( path )
                                  //,fs::file_size( path )
                              } ) ;
    }

    return result ;
}

void FileAdapter::delOld(const std::string& dir, unsigned int keepCount) {
    delOldS(dir, keepCount);
}

void FileAdapter::delOldS(const std::string& dir, unsigned int keepCount) {
    try {
        auto flist = file_list(dir) ;
        static const auto cmp_times = [] ( const t_file_info& a, const t_file_info& b )
                { return a.last_write_time > b.last_write_time ; } ;
        std::sort( std::begin( flist ), std::end( flist ), cmp_times ) ;

        for( std::size_t i = flist.size() ; i > keepCount ; --i ) {
            fs::remove( flist[i-1].path ) ;
        }
    } catch( const std::exception& ) {}
}

int FileAdapter::saveTFile(const char * path, const char * data, uint32_t len) {
    int re = -1;
    if (!fs::exists(path)) {
        if (saveTFileS(path, data, len)) {
            re = 1;
        } else {
            re = -2;
        }
    }
    return re;
}

bool FileAdapter::saveTFileS(const char * filePath,  const char * data, unsigned long len) {
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
bool FileAdapter::mkdir_p(const char * filePath){
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
            if (mkdir(_path, S_IRWXU) != 0) {
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

//int FileAdapter::mkdir_p(const std::string& filePath)
//{
//    const size_t len = filePath.length();
//    char _path[PATH_MAX];
//    char *p;

//    errno = 0;

//    /* Copy string so its mutable */
//    if (len > sizeof(_path)-1) {
//        errno = ENAMETOOLONG;
//        return -1;
//    }

//    strcpy(_path, filePath.c_str());

//    /* Iterate the string */
//    for (p = _path + 1; *p; p++) {
//        if (*p == '/') {
//            /* Temporarily truncate */
//            *p = '\0';

//            if (mkdir(_path, S_IRWXU) != 0) {
//                if (errno != EEXIST)
//                    return -1;
//            }

//            *p = '/';
//        }
//    }
////The fileName at the end of path- so in comment this:
////    if (mkdir(_path, S_IRWXU) != 0) {
////        if (errno != EEXIST)
////            return -1;
////    }

//    return 0;
//}

bool FileAdapter::createSymlink(const std::string& target, const std::string& link) {
    std::error_code ec;
    fs::create_symlink(fs::path(target),
                         fs::path(link),
                         ec );
    return !ec;
}

uint64_t FileAdapter::removeAll(const char * path) {
    return  removeAllS(path);
}

uint64_t FileAdapter::removeAllS(const char * path) {
    uint64_t re = 0;
    try {
        re = fs::remove_all(path);
    } catch (...){}
    return re;
}




