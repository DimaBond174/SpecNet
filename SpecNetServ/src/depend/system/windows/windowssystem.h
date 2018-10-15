#ifndef WINDOWSSYSTEM_H
#define WINDOWSSYSTEM_H

#include <string>
#include "i/isystem.h"

class WindowsSystem : public ISystem
{
public:
    WindowsSystem();

    std::string getExePath() override;
};

#endif // WINDOWSSYSTEM_H
