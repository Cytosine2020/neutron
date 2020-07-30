cmake_minimum_required(VERSION 3.10)
project(neutron)

set(CMAKE_CXX_STANDARD 11)

include_directories(include sysroot riscv_isa/include elf/include)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -fno-exceptions -fno-rtti")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O2")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -ggdb -g3 -fno-omit-frame-pointer -D DEBUG")

add_executable(neutron-riscv-linux src/neutron_riscv_linux.cpp)
target_compile_definitions(neutron-riscv-linux PRIVATE
        __RV_BASE_I__ __RV_BIT_WIDTH__=32
        __RV_SUPERVISOR_MODE__ __RV_USER_MODE__
        __RV_EXTENSION_M__ __RV_EXTENSION_ZICSR__)

add_executable(neutron-riscv-linux-fuzzer src/neutron_riscv_linux_fuzzer.cpp)
target_compile_definitions(neutron-riscv-linux-fuzzer PRIVATE
        __RV_BASE_I__ __RV_BIT_WIDTH__=32
        __RV_SUPERVISOR_MODE__ __RV_USER_MODE__
        __RV_EXTENSION_M__ __RV_EXTENSION_ZICSR__)
