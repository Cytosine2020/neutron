#ifndef NEUTRON_UTILITY_HPP
#define NEUTRON_UTILITY_HPP


#include <type_traits>

namespace neutron {
    template <typename T>
    T divide_ceil(T a, T b) {
        static_assert(std::is_unsigned<T>::value, "this function is only for unsigned!");

        return a == 0 ? 0 : (a - 1) / b + 1;
    }
}


#endif //NEUTRON_UTILITY_HPP
