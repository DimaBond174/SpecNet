#ifndef WINDOWSSERVICE_H
#define WINDOWSSERVICE_H

#include <functional>

class WindowsService {
public:
    WindowsService(const std::function<void()> & f_startContext);

    void onCmd(int argc, char** argv);

private:
    std::function<void()> _f_startContext;
    bool startSpecNetServ();
};

#endif // WINDOWSSERVICE_H
