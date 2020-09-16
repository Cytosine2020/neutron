#include <stddef.h>

#include "riscv_linux.hpp"
#include "dynamic_translation.h"


extern "C" {

bool neutron_mmu_execute(struct dynamic_info *info, uint32_t addr) {
    return neutron::LinuxHart<riscv_isa::xlen_32_trait>::neutron_mmu_execute_fast_call(info, addr);
}

bool neutron_mmu_load(struct dynamic_info *info, uint32_t addr) {
    return neutron::LinuxHart<riscv_isa::xlen_32_trait>::neutron_mmu_load_fast_call(info, addr);
}

bool neutron_mmu_store(struct dynamic_info *info, uint32_t addr) {
    return neutron::LinuxHart<riscv_isa::xlen_32_trait>::neutron_mmu_store_fast_call(info, addr);
}

}
