cmake_minimum_required(VERSION 3.10)
project(neutron CXX C ASM)

set(CMAKE_CXX_STANDARD 11)

set(ASMJIT_STATIC true)
add_subdirectory(asmjit)
add_subdirectory(elf)
add_subdirectory(riscv_isa)

include_directories(include riscv_isa/include elf/include asmjit/src)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -fno-exceptions -fno-rtti")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -flto")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -ggdb -g3 -fno-omit-frame-pointer -D __DEBUG__")
set(CMAKE_ASM_FLAGS "${CFLAGS} -x assembler-with-cpp")

set(RISCV_LINUX_TARGET src/neutron_argument.cpp
                       src/dynamic_translation.cpp
                       src/riscv_linux_program.cpp
                       src/dynamic_translation.asm)

add_executable(neutron-riscv-linux src/riscv_linux_main.cpp ${RISCV_LINUX_TARGET})
target_compile_definitions(neutron-riscv-linux PRIVATE
        __RV_BASE_I__ __RV_BIT_WIDTH__=32
        __RV_SUPERVISOR_MODE__ __RV_USER_MODE__
        __RV_EXTENSION_M__ __RV_EXTENSION_A__ __RV_EXTENSION_ZICSR__)
target_link_libraries(neutron-riscv-linux asmjit riscv_isa_rv32ima)

add_executable(neutron-riscv-linux-fuzzer src/riscv_linux_fuzzer_main.cpp ${RISCV_LINUX_TARGET})
target_compile_definitions(neutron-riscv-linux-fuzzer PRIVATE
        __RV_BASE_I__ __RV_BIT_WIDTH__=32
        __RV_SUPERVISOR_MODE__ __RV_USER_MODE__
        __RV_EXTENSION_M__ __RV_EXTENSION_A__ __RV_EXTENSION_ZICSR__)
target_link_libraries(neutron-riscv-linux-fuzzer asmjit riscv_isa_rv32ima)

add_executable(neutron-riscv-linux-gdb src/riscv_linux_gdb_main.cpp
                                       src/gdb_server.cpp
                                       ${RISCV_LINUX_TARGET})
target_compile_definitions(neutron-riscv-linux-gdb PRIVATE
        __RV_BASE_I__ __RV_BIT_WIDTH__=32
        __RV_SUPERVISOR_MODE__ __RV_USER_MODE__
        __RV_EXTENSION_M__ __RV_EXTENSION_A__ __RV_EXTENSION_ZICSR__)
target_link_libraries(neutron-riscv-linux-gdb asmjit riscv_isa_rv32ima)
