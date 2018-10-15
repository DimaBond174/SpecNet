#ifndef IALLOC_H
#define IALLOC_H
#include <stdint.h>

class IAlloc {
public:
    virtual ~IAlloc(){}
    virtual void * specAlloc(uint32_t size) = 0;
    virtual void specFree(void * ptr) = 0;
};

#endif // IALLOC_H
