#ifndef NEUTRON_DYNAMIC_TRANSLATION_H
#define NEUTRON_DYNAMIC_TRANSLATION_H


#if defined(__cplusplus)
extern "C" {
#endif

#include <stddef.h>

struct memory_area {
    uint32_t start, end;
    size_t shift;
};

struct dynamic_info {
#if defined(__RV_BASE_E__)
    uint32_t int_reg[16];
#else
    uint32_t int_reg[32];
#endif
    void *core;

    struct memory_area execute_cache;
    struct memory_area load_cache;
    struct memory_area store_cache;

#if defined(__RV_EXTENSION_A__)
    uint32_t reserve_address, reserve_value;
#endif

    void *fast_call_return_addr;
};

/// this is not a normal function
extern void neutron_dynamic_fast_call(void);

bool neutron_mmu_execute(struct dynamic_info *info, uint32_t addr);

bool neutron_mmu_load(struct dynamic_info *info, uint32_t addr);

bool neutron_mmu_store(struct dynamic_info *info, uint32_t addr);

#if defined(__cplusplus)
}
#endif

#endif //NEUTRON_DYNAMIC_TRAMSLATION_H
