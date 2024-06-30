#ifndef UTILS_H
#define UTILS_H

#include <iostream>
#include <stdlib.h>


#define pv(x) std::cout<<#x<<" = "<<(x)<<"; ";std::cout.flush()
#define pn std::cout<<std::endl

#define exiterror(msg) std::cerr << (msg) << std::endl; exit(-1)

#define UNUSED(variable) do { (void)(variable); } while (0)


#endif // UTILS_H
