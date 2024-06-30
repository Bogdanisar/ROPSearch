#ifndef UTILS_H
#define UTILS_H

#include <iostream>
#include <stdlib.h>


#define pv(x) std::cout<<#x<<" = "<<(x)<<"; ";std::cout.flush()
#define pn std::cout<<std::endl

#define exiterror(msg) std::cerr << (msg) << '\n' << "exit(-1);" << std::endl; exit(-1)
#define assertMessage(condition, msg) \
    do { \
        if (!(condition)) { exiterror(msg); } \
    } while(0)

#define UNUSED(variable) do { (void)(variable); } while (0)


#endif // UTILS_H
