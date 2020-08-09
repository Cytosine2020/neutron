#ifndef NEUTRON_UTILITY_HPP
#define NEUTRON_UTILITY_HPP


#include <iostream>
#include <cstddef>
#include <type_traits>


namespace neutron {
    void _warn(const char *file, int line, const char *msg) {
        std::cerr << "Warn at file " << file << ", line " << line << ": " << msg << std::endl;
    }

#define neutron_warn(msg) neutron::_warn(__FILE__, __LINE__, msg)

    __attribute__((noreturn)) void _abort(const char *file, int line, const char *msg) {
        std::cerr << "Abort at file " << file << ", line " << line << ": " << msg << std::endl;

        abort();
    }

#define neutron_abort(msg) neutron::_abort(__FILE__, __LINE__, msg)

    __attribute__((noreturn)) void _unreachable(const char *file, int line, const char *msg) {
        std::cerr << "Unreachable at file " << file << ", line " << line << ": " << msg << std::endl;

        abort();
    }

#define neutron_unreachable(msg) neutron::_unreachable(__FILE__, __LINE__, msg)

#define neutron_unused __attribute__((unused))

    using i8 = int8_t;
    using u8 = u_int8_t;
    using i16 = int16_t;
    using u16 = u_int16_t;
    using i32 = int32_t;
    using u32 = u_int32_t;
    using i64 = int64_t;
    using u64 = u_int64_t;
#if defined(__x86_64__)
    using isize = int64_t;
    using usize = u_int64_t;
#else
    using isize = int32_t;
    using usize = u_int32_t;
#endif

    template<typename T, usize end, usize begin>
    struct bits_mask {
    private:
        using RetT = typename std::enable_if<(std::is_unsigned<T>::value && sizeof(T) * 8 >= end &&
                                              end > begin), T>::type;

    public:
        static constexpr RetT val = ((static_cast<T>(1u) << (end - begin)) - static_cast<T>(1u)) << begin;
    };

    template<typename T, usize begin>
    struct bit_mask {
    public:
        static constexpr T val = bits_mask<T, begin + 1, begin>::val;
    };

    template<typename T, usize end, usize begin, isize offset = 0, bool flag = (begin > offset)>
    struct _get_bits;

    template<typename T, usize end, usize begin, isize offset>
    struct _get_bits<T, end, begin, offset, true> {
    public:
        static constexpr T inner(T val) {
            return (val >> (begin - offset)) & bits_mask<T, end - begin, 0>::val << offset;
        }
    };

    template<typename T, usize end, usize begin, isize offset>
    struct _get_bits<T, end, begin, offset, false> {
    public:
        static constexpr T inner(T val) {
            return (val << (offset - begin)) & bits_mask<T, end - begin, 0>::val << offset;
        }
    };

    template<typename T, usize end, usize begin, isize offset = 0>
    constexpr inline T get_bits(T val) {
        static_assert(sizeof(T) * 8 >= end, "end exceed length");
        static_assert(end > begin, "end need to be bigger than start");
        static_assert(sizeof(T) * 8 >= end - begin + offset, "result exceed length");

        return _get_bits<T, end, begin, offset>::inner(val);
    }

    template<typename T, usize begin, isize offset = 0>
    constexpr inline T get_bit(T val) { return get_bits<T, begin + 1, begin, offset>(val); }

    template<typename T>
    T divide_ceil(T a, T b) {
        static_assert(std::is_unsigned<T>::value, "this function is only for unsigned!");

        return a == 0 ? 0 : (a - 1) / b + 1;
    }
}


#endif //NEUTRON_UTILITY_HPP
