#ifndef NEUTRON_RISCV_LINUX_HPP
#define NEUTRON_RISCV_LINUX_HPP


#include <iostream>
#include <sys/mman.h>

#include "target/hart.hpp"
#include "target/dump.hpp"

using namespace riscv_isa;

#include "elf_header.hpp"

using namespace elf;

#include "unix_std.hpp"


namespace neutron {
    template<typename xlen=xlen_trait>
    class LinuxMemory {
    private:
        using XLenT = typename xlen::UXLenT;

        u8 *memory_offset;
        usize memory_size;

    public:

        LinuxMemory(usize _memory_size) : memory_size{_memory_size} {
            memory_offset = static_cast<u8 *>(mmap(nullptr, memory_size, PROT_READ | PROT_WRITE,
                                                   MAP_ANONYMOUS | MAP_SHARED, -1, 0));
            if (memory_offset == MAP_FAILED) {
                memory_offset = nullptr;
                memory_size = 0;
            }
        }

        LinuxMemory(const LinuxMemory &other) = delete;

        LinuxMemory &operator=(const LinuxMemory &other) = delete;

        template<typename T=void *>
        T *address(XLenT addr) {
            return addr < memory_size ? reinterpret_cast<T *>(memory_offset + addr) : nullptr;
        }

        bool memory_map(XLenT offset, const void *src, usize length) {
            if (offset <= memory_size - length) {
                memcpy(memory_offset + offset, src, length);
                return true;
            } else {
                return false;
            }
        }

        ~LinuxMemory() { if (memory_offset != nullptr) munmap(memory_offset, memory_size); }
    };

    class LinuxHart : public Hart<LinuxHart> {
    protected:
        LinuxMemory<> &mem;

    public:
        LinuxHart(XLenT pc, IntegerRegister<> &reg, LinuxMemory<> &mem) : Hart{pc, reg}, mem{mem} {}

        template<typename ValT>
        RetT mmu_load_int_reg(usize dest, XLenT addr) {
            ValT *ptr = mem.template address<ValT>(addr);
            if (ptr == nullptr) {
                csr_reg.scause = trap::LOAD_PAGE_FAULT;
                return false;
            } else {
                if (dest != 0) int_reg.set_x(dest, *ptr);
                return true;
            }
        }

        template<typename ValT>
        RetT mmu_store_int_reg(usize src, XLenT addr) {
            ValT *ptr = mem.template address<ValT>(addr);
            if (ptr == nullptr) {
                csr_reg.scause = trap::STORE_AMO_PAGE_FAULT;
                return false;
            } else {
                *ptr = static_cast<ValT>(int_reg.get_x(src));
                return true;
            }
        }

        template<usize offset>
        RetT mmu_load_inst_half(XLenT addr) {
            u16 *ptr = mem.template address<u16>(addr + offset * sizeof(u16));
            if (ptr == nullptr) {
                csr_reg.scause = trap::INSTRUCTION_PAGE_FAULT;
                return false;
            } else {
                *(reinterpret_cast<u16 *>(&this->inst_buffer) + offset) = *ptr;
                return true;
            }
        }

        bool system_call() {
            switch (int_reg.get_x(IntegerRegister<>::A7)) {
                case 57: {
                    int fd = int_reg.get_x(IntegerRegister<>::A0);
                    int_reg.set_x(IntegerRegister<>::A0,
                                  fd > 2 ? close(fd) : 0); // todo: stdin, stdout, stderr

                    return true;
                }
                case 64:
                    int_reg.set_x(IntegerRegister<>::A0, write(int_reg.get_x(IntegerRegister<>::A0),
                                                               mem.address<char>(
                                                                       int_reg.get_x(
                                                                               IntegerRegister<>::A1)),
                                                               IntegerRegister<>::A3));

                    return true;
                case 80:
                    int_reg.set_x(IntegerRegister<>::A0, -1); // todo: need convert

                    return true;
                case 93:
                    std::cout << std::endl << "[exit " << int_reg.get_x(IntegerRegister<>::A0) << ']'
                              << std::endl;

                    return false;
                case 214:

                    return true;
                default:
                    std::cerr << "Invalid enviroment call number at " << std::hex << get_pc()
                              << ", call number " << std::dec << int_reg.get_x(IntegerRegister<>::A7)
                              << std::endl;

                    return false;
            }
        }

        void start() {
            while (true) {
                if (visit()) continue;

                switch (csr_reg.scause) {
                    case trap::INSTRUCTION_ADDRESS_MISALIGNED:
                    case trap::INSTRUCTION_ACCESS_FAULT:
                        std::cerr << "Instruction address misaligned at "
                                  << std::hex << get_pc() << std::endl;

                        return;
                    case trap::ILLEGAL_INSTRUCTION:
                        std::cerr << "Illegal instruction at "
                                  << std::hex << get_pc() << ": " << std::dec
                                  << *reinterpret_cast<Instruction *>(&inst_buffer) << std::endl;

                        return;
                    case trap::BREAKPOINT:
                        std::cerr << "Break point at " << std::hex << get_pc() << std::endl;
                        inc_pc(ECALLInst::INST_WIDTH);

                        break;
                    case trap::LOAD_ADDRESS_MISALIGNED:
                    case trap::LOAD_ACCESS_FAULT:
                        std::cerr << "Load address misaligned at "
                                  << std::hex << get_pc() << ": " << std::dec
                                  << *reinterpret_cast<Instruction *>(&inst_buffer) << std::endl;

                        return;
                    case trap::STORE_AMO_ADDRESS_MISALIGNED:
                    case trap::STORE_AMO_ACCESS_FAULT:
                        std::cerr << "Store or AMO address misaligned at "
                                  << std::hex << get_pc() << ": " << std::dec
                                  << *reinterpret_cast<Instruction *>(&inst_buffer) << std::endl;

                        return;
                    case trap::U_MODE_ENVIRONMENT_CALL:
                        if (!system_call()) return;
                        inc_pc(ECALLInst::INST_WIDTH);

                        break;
                    case trap::S_MODE_ENVIRONMENT_CALL:
                        riscv_isa_unreachable("no system mode interrupt!");
                    case trap::INSTRUCTION_PAGE_FAULT:
                        std::cerr << "Instruction page fault at " << std::hex << get_pc() << std::endl;

                        return;
                    case trap::LOAD_PAGE_FAULT:
                        std::cerr << "Load page fault at " << std::hex << get_pc() << std::endl;

                        return;
                    case trap::STORE_AMO_PAGE_FAULT:
                        std::cerr << "Store or AMO page fault at " << std::hex << get_pc() << std::endl;

                        return;
                    default:
                        riscv_isa_unreachable("unknown internal interrupt!");
                }
            }
        }
    };
}


#endif //NEUTRON_RISCV_LINUX_HPP
