#include "windowssystem.h"
#if defined(Windows)
#include <Windows.h>
#endif

WindowsSystem::WindowsSystem()
{

}

std::string WindowsSystem::getExePath(){
    std::string _exePath;
#if defined(Windows)
    char buf[PATH_MAX];
    ssize_t len = 0;

    len = GetModuleFileNameA(GetModuleHandleA(0x0), buf, MAX_PATH);

    if (len>0) {
        for(--len; len>0; --len) {
            if ('/'==buf[len] || '\\'==buf[len]){
                _exePath = std::string(buf, len);
                break;
            }
        }
    }
#endif
    return _exePath;
}
