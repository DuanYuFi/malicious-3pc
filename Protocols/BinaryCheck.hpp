#ifndef PROTOCOLS_BINARYCHECK_HPP_
#define PROTOCOLS_BINARYCHECK_HPP_

#include "BinaryCheck.h"

#include <cstdlib>
#include <ctime>
#include <chrono>

using namespace std;

#ifndef PRINT_UINT128
#define PRINT_UINT128
void print_uint128(uint128_t x) {
    if (x > 9) print_uint128(x / 10);
    putchar(x % 10 + '0');
}
#endif

#define show_uint128(value) \
    cout << #value << " = "; \
    print_uint128(value); \
    cout << endl; 



#endif