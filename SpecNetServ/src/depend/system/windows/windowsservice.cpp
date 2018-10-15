#include "windowsservice.h"
#include <iostream>
#include "spec/speccontext.h"

WindowsService::WindowsService(const std::function<void()> & f_startContext)
        : _f_startContext(f_startContext) {

}

bool WindowsService::startSpecNetServ() {
    bool re = false;
    //faux loop
    do {
        if (_f_startContext) {
            _f_startContext();
        } else {
            std::cerr << "Error: WindowsService::_f_startContext is nullptr" << std::endl;
            break;
        }

        SpecContext & sr = SpecContext::instance();
        if (!sr.keepRun.load(std::memory_order_acquire)) {
            std::cerr << "Error: SpecContext failed to start" << std::endl;
            break;
        }

        re = true;
    } while(false);
    return re;
}
