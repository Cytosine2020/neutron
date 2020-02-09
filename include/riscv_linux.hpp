#ifndef NEUTRON_RISCV_LINUX_HPP
#define NEUTRON_RISCV_LINUX_HPP


#include <iostream>
#include <sys/mman.h>
#include <map>

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
        using XLenT = typename xlen::XLenT;
        using UXLenT = typename xlen::UXLenT;

    public:
        static constexpr UXLenT R_BIT = 2;
        static constexpr UXLenT W_BIT = 4;
        static constexpr UXLenT X_BIT = 8;

        enum MemoryProtection : UXLenT {
            READ = R_BIT,
            READ_WRITE = R_BIT | W_BIT,
            EXECUTE = X_BIT,
            EXECUTE_READ = X_BIT | R_BIT,
            EXECUTE_READ_WRITE = X_BIT | R_BIT | W_BIT,
        };

        static constexpr UXLenT PAGE_SIZE = 0x1000;

    private:
        struct MemArea {
            void *physical;
            UXLenT size;
            MemoryProtection protection;
        };

        std::map<UXLenT, MemArea> mem_areas;
        UXLenT brk;

    public:
        LinuxMemory() : mem_areas{} {}

        LinuxMemory(const LinuxMemory &other) = delete;

        LinuxMemory &operator=(const LinuxMemory &other) = delete;

        template<typename T>
        T *address_read(UXLenT addr) {
            auto before = mem_areas.upper_bound(addr);
            if (before == mem_areas.begin() || --before == mem_areas.end())
                return nullptr;
            if (addr >= before->first + before->second.size)
                return nullptr;
            if ((before->second.protection & R_BIT) == 0)
                return nullptr;
            return reinterpret_cast<T *>(static_cast<u8 *>(before->second.physical) + (addr - before->first));
        }

        template<typename T>
        T *address_write(UXLenT addr) {
            auto before = mem_areas.upper_bound(addr);
            if (before == mem_areas.begin() || --before == mem_areas.end())
                return nullptr;
            if (addr >= before->first + before->second.size)
                return nullptr;
            if ((before->second.protection & W_BIT) == 0)
                return nullptr;
            return reinterpret_cast<T *>(static_cast<u8 *>(before->second.physical) + (addr - before->first));
        }

        template<typename T>
        T *address_execute(UXLenT addr) {
            auto before = mem_areas.upper_bound(addr);
            if (before == mem_areas.begin() || --before == mem_areas.end()) return nullptr;
            if (addr >= before->first + before->second.size) return nullptr;
            if ((before->second.protection & X_BIT) == 0) return nullptr;
            return reinterpret_cast<T *>(static_cast<u8 *>(before->second.physical) + (addr - before->first));
        }

        bool add_map(UXLenT offset, void *src, UXLenT length, MemoryProtection protection) {
//            auto before = --mem_areas.upper_bound(offset);
//            typename std::map<UXLenT, MemArea>::const_iterator after;
//            if (before == mem_areas.end()) {
//                after = mem_areas.lower_bound(offset);
//            } else {
//                if (before->first + before->second.size <= offset)
//                    after = ++before;
//                else
//                    return false;
//            }
//
//            if (after != mem_areas.end() && offset + length > after->first) return false;

            mem_areas.emplace(offset, MemArea{src, length, protection});

            return true;
        }

        void brk_init() {
            auto end = mem_areas.rbegin();
            if (end == mem_areas.rend()) brk = 0x100000;
            else brk = end->first + end->second.size;
        }

        bool set_brk(UXLenT _addr) {
            if (_addr < brk) return false;

            UXLenT addr = ((_addr - 1) / PAGE_SIZE + 1) * PAGE_SIZE;

            void *area = mmap(nullptr, addr - brk, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
            if (area == MAP_FAILED) return false;

            if (!add_map(brk, area, addr - brk, READ_WRITE)) return false;

            brk = addr;

            return true;
        }

        ~LinuxMemory() {
            // todo
        }
    };

    class LinuxHart : public Hart<LinuxHart> {
    protected:
        LinuxMemory<> &mem;

    public:
        LinuxHart(XLenT pc, IntegerRegister<> &reg, LinuxMemory<> &mem) : Hart{pc, reg}, mem{mem} {}

        template<typename ValT>
        RetT mmu_load_int_reg(usize dest, UXLenT addr) {
            ValT *ptr = mem.template address_read<ValT>(addr);
            if (ptr == nullptr) {
                csr_reg.scause = trap::LOAD_PAGE_FAULT;
                return false;
            } else {
                if (dest != 0) int_reg.set_x(dest, *ptr);
                return true;
            }
        }

        template<typename ValT>
        RetT mmu_store_int_reg(usize src, UXLenT addr) {
            ValT *ptr = mem.template address_write<ValT>(addr);
            if (ptr == nullptr) {
                csr_reg.scause = trap::STORE_AMO_PAGE_FAULT;
                return false;
            } else {
                *ptr = static_cast<ValT>(int_reg.get_x(src));
                return true;
            }
        }

        template<usize offset>
        RetT mmu_load_inst_half(UXLenT addr) {
            u16 *ptr = mem.template address_execute<u16>(addr + offset * sizeof(u16));
            if (ptr == nullptr) {
                csr_reg.scause = trap::INSTRUCTION_PAGE_FAULT;
                return false;
            } else {
                *(reinterpret_cast<u16 *>(&this->inst_buffer) + offset) = *ptr;
                return true;
            }
        }

        void sys_write() {
            UXLenT size = int_reg.get_x(IntegerRegister<>::A2);
            UXLenT addr = int_reg.get_x(IntegerRegister<>::A1);

            char *buffer = new char[size];

            for (usize i = 0; i < size; ++i) {
                char *byte = mem.address_read<char>(addr + i);
                if (byte == nullptr) {
                    int_reg.set_x(IntegerRegister<>::A0, 0);
                    return;
                } else {
                    buffer[i] = *byte;
                }
            }

            XLenT result = write(int_reg.get_x(IntegerRegister<>::A0), buffer, size);

            int_reg.set_x(IntegerRegister<>::A0, result);
        }

        void sys_brk() {
            UXLenT addr = int_reg.get_x(IntegerRegister<>::A0);

            int_reg.set_x(IntegerRegister<>::A0, mem.set_brk(addr) ? 0 : -1);
        }

        bool system_call() {
            switch (int_reg.get_x(IntegerRegister<>::A7)) {
                case 57: {
                    int fd = int_reg.get_x(IntegerRegister<>::A0);
                    int_reg.set_x(IntegerRegister<>::A0,
                                  fd > 2 ? close(fd) : 0); // todo: stdin, stdout, stderr

                    return true;
                }
                case syscall::write:
                    sys_write();
                    return true;
                case 80:
                    int_reg.set_x(IntegerRegister<>::A0, -1); // todo: need convert

                    return true;
                case 93:
                    std::cout << std::endl << "[exit " << int_reg.get_x(IntegerRegister<>::A0) << ']'
                              << std::endl;

                    return false;
                case syscall::brk:
                    sys_brk();
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
                        std::cerr << "Instruction page fault at "
                                  << std::hex << get_pc() << ": " << std::dec
                                  << *reinterpret_cast<Instruction *>(&inst_buffer) << std::endl;

                        return;
                    case trap::LOAD_PAGE_FAULT:
                        std::cerr << "Load page fault at "
                                  << std::hex << get_pc() << ": " << std::dec
                                  << *reinterpret_cast<Instruction *>(&inst_buffer) << std::endl;

                        return;
                    case trap::STORE_AMO_PAGE_FAULT:
                        std::cerr << "Store or AMO page fault at "
                                  << std::hex << get_pc() << ": " << std::dec
                                  << *reinterpret_cast<Instruction *>(&inst_buffer) << std::endl;

                        return;
                    default:
                        riscv_isa_unreachable("unknown internal interrupt!");
                }
            }
        }
    };
}


#endif //NEUTRON_RISCV_LINUX_HPP
