#include <thread>


bool waitForSUCCESS(bool (*f)(),
                    int msRepeat,
                    int msTimeout){
    auto start = std::chrono::system_clock::now();
    while (std::chrono::system_clock::now() - start < std::chrono::milliseconds(msTimeout)) {
        if ((*f)()) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(msRepeat));
    }//while
    return false;
}
