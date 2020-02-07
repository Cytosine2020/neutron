cmake_minimum_required(VERSION 3.10)
project(neutron)

set(CMAKE_CXX_STANDARD 11)

include_directories(include riscv_isa/include elf/include)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O2")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g -D DEBUG")

add_executable(neutron-riscv src/neutron_riscv.cpp)
target_compile_definitions(neutron-riscv PRIVATE __RV_BASE_I__ __RV_BIT_WIDTH__=32 __RV_EXTENSION_M__)