#ifndef CALLOC_H
#define CALLOC_H

#include "i/ialloc.h"
#include <cstdlib>
#ifdef Debug
    #include <set>
    #include <assert.h>
    #include <mutex>
#endif

/* Classic C allocator: malloc, free */
class CAlloc : public IAlloc
{
public:
    CAlloc() {}

#ifdef Debug
    std::set<void *> myAllocs;
    std::mutex myAllocsMutex;
#endif

    void * specAlloc(uint32_t size) override {
#ifdef Debug
        void * re = std::malloc(size);
        {
            myAllocsMutex.lock();
            myAllocs.insert(re);
            myAllocsMutex.unlock();
        }
        return re;
#else
        return std::malloc(size);
#endif
    }

    void specFree(void * ptr) override {
#ifdef Debug
        {
            myAllocsMutex.lock();
            assert(!myAllocs.empty());
            std::set<void *>::iterator it = myAllocs.find(ptr);
            assert(myAllocs.end()!=it);
            myAllocs.erase(it);
            myAllocsMutex.unlock();
        }
        std::free(ptr);
#else
        std::free(ptr);
#endif
    }
};

#endif // CALLOC_H
