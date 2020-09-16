#include "riscv_linux_program.hpp"

#include "riscv_isa_utility.hpp"


namespace neutron {
    template<> const char *LinuxProgram<riscv_isa::xlen_32_trait>::platform_string = "riscv32";

    template<> const char *LinuxProgram<riscv_isa::xlen_64_trait>::platform_string = "riscv64";
}


