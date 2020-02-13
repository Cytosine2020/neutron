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

#include "riscv_linux_program.hpp"
#include "unix_std.hpp"


#define neutron_syscall_0(func, reg) \
    reg.set_x(IntRegT::A0, func())

#define neutron_syscall_1(func, reg) \
    reg.set_x(IntRegT::A0, func(reg.get_x(IntRegT::A0)))

#define neutron_syscall_2(func, reg) \
    reg.set_x(IntRegT::A0, func(reg.get_x(IntRegT::A0), \
                                          reg.get_x(IntRegT::A1)))

#define neutron_syscall_3(func, reg) \
    reg.set_x(IntRegT::A0, func(reg.get_x(IntRegT::A0), \
                                          reg.get_x(IntRegT::A1), \
                                          reg.get_x(IntRegT::A2)))

#define neutron_syscall_4(func, reg) \
    reg.set_x(IntRegT::A0, func(reg.get_x(IntRegT::A0), \
                                          reg.get_x(IntRegT::A1), \
                                          reg.get_x(IntRegT::A2), \
                                          reg.get_x(IntRegT::A3)))

#define neutron_syscall_5(func, reg) \
    reg.set_x(IntRegT::A0, func(reg.get_x(IntRegT::A0), \
                                          reg.get_x(IntRegT::A1), \
                                          reg.get_x(IntRegT::A2), \
                                          reg.get_x(IntRegT::A3), \
                                          reg.get_x(IntRegT::A4)))

#define neutron_syscall_6(func, reg) \
    reg.set_x(IntRegT::A0, func(reg.get_x(IntRegT::A0), \
                                          reg.get_x(IntRegT::A1), \
                                          reg.get_x(IntRegT::A2), \
                                          reg.get_x(IntRegT::A3), \
                                          reg.get_x(IntRegT::A4), \
                                          reg.get_x(IntRegT::A5)))

#define neutron_syscall(num, func, reg) \
    neutron_syscall_##num(func, reg)


namespace neutron {
    class LinuxHart : public Hart<LinuxHart> {
    protected:
        LinuxProgram<> &pcb;

    public:
        LinuxHart(UXLenT hart_id, LinuxProgram<> &mem) : Hart{hart_id, mem.pc, mem.int_reg}, pcb{mem} {
            cur_level = USER_MODE;
        }

        void internal_interrupt_action(UXLenT interrupt, riscv_isa_unused UXLenT trap_value) {
            csr_reg[CSRRegT::SCAUSE] = interrupt;
        }

        template<typename ValT>
        RetT mmu_load_int_reg(usize dest, UXLenT addr) {
            static_assert(sizeof(ValT) <= sizeof(UXLenT), "load width exceed bit width!");

            if ((addr & (sizeof(ValT) - 1)) != 0)
                return internal_interrupt(trap::LOAD_ACCESS_FAULT, addr);

            ValT *ptr = pcb.template address_read<ValT>(addr);
            if (ptr == nullptr) {
                return internal_interrupt(trap::LOAD_PAGE_FAULT, addr);
            } else {
                if (dest != 0) int_reg.set_x(dest, *ptr);
                return true;
            }
        }

        template<typename ValT>
        RetT mmu_store_int_reg(usize src, UXLenT addr) {
            static_assert(sizeof(ValT) <= sizeof(UXLenT), "store width exceed bit width!");

            if ((addr & (sizeof(ValT) - 1)) != 0)
                return internal_interrupt(trap::STORE_AMO_ACCESS_FAULT, addr);

            ValT *ptr = pcb.template address_write<ValT>(addr);
            if (ptr == nullptr) {
                return internal_interrupt(trap::STORE_AMO_PAGE_FAULT, addr);
            } else {
                *ptr = static_cast<ValT>(int_reg.get_x(src));
                return true;
            }
        }

        template<usize offset>
        RetT mmu_load_inst_half(UXLenT addr) {
            /// instruction misaligned is checked in jump or branch instructions

            u16 *ptr = pcb.template address_execute<u16>(addr + offset * sizeof(u16));
            if (ptr == nullptr) {
                return internal_interrupt(trap::INSTRUCTION_PAGE_FAULT, addr);
            } else {
                *(reinterpret_cast<u16 *>(&this->inst_buffer) + offset) = *ptr;
                return true;
            }
        }

#if defined(__RV_EXTENSION_ZICSR__)

        RetT get_csr_reg(riscv_isa_unused UXLenT index) { return csr_reg[index]; }

        RetT set_csr_reg(riscv_isa_unused UXLenT index, riscv_isa_unused UXLenT val) { return true; }

#endif // defined(__RV_EXTENSION_ZICSR__)
#if defined(__RV_SUPERVISOR_MODE__)

        RetT visit_sret_inst(riscv_isa_unused SRETInst *inst) { return illegal_instruction(inst); }

#endif // defined(__RV_SUPERVISOR_MODE__)

        RetT visit_mret_inst(riscv_isa_unused MRETInst *inst) { return illegal_instruction(inst); }

        RetT visit_wfi_inst(riscv_isa_unused WFIInst *inst) { return illegal_instruction(inst); }

#if defined(__RV_SUPERVISOR_MODE__)

        RetT visit_sfencevma_inst(riscv_isa_unused SFENCEVAMInst *inst) { return illegal_instruction(inst); }

#endif // defined(__RV_SUPERVISOR_MODE__)

        XLenT sys_close(UXLenT fd) {
            return fd > 2 ? close(fd) : 0; // todo: stdin, stdout, stderr
        }

        XLenT sys_write(UXLenT fd, UXLenT addr, UXLenT size) {
            char *buffer = new char[size];

            for (usize i = 0; i < size; ++i) {
                char *byte = pcb.address_read<char>(addr + i);
                if (byte == nullptr) return 0;
                else buffer[i] = *byte;
            }

            XLenT result = write(fd, buffer, size);

            delete[] buffer;

            return result;
        }

        XLenT sys_fstat(riscv_isa_unused UXLenT fd, riscv_isa_unused UXLenT addr) {
            return -1; // todo
        }

        UXLenT sys_brk(UXLenT addr) {
            return pcb.set_brk(addr);
        }

        bool syscall_handler() {
            switch (int_reg.get_x(IntRegT::A7)) {
                case syscall::close:
                    neutron_syscall(1, sys_close, int_reg);
                    return true;
                case syscall::write:
                    neutron_syscall(3, sys_write, int_reg);
                    return true;
                case syscall::fstat:
                    neutron_syscall(2, sys_fstat, int_reg);
                    return true;
                case syscall::exit:
                    std::cout << std::endl << "[exit " << int_reg.get_x(IntRegT::A0) << ']'
                              << std::endl;

                    return false;
                case syscall::brk:
                    neutron_syscall(1, sys_brk, int_reg);
                    return true;
                default:
                    std::cerr << "Invalid environment call number at " << std::hex << get_pc()
                              << ", call number " << std::dec << int_reg.get_x(IntRegT::A7)
                              << std::endl;

                    return false;
            }
        }

        bool supervisor_trap_handler(XLenT cause) {
            switch (cause) {
                case trap::INSTRUCTION_ADDRESS_MISALIGNED:
                case trap::INSTRUCTION_ACCESS_FAULT:
                    std::cerr << "Instruction address misaligned at "
                              << std::hex << get_pc() << std::endl;

                    return false;
                case trap::ILLEGAL_INSTRUCTION:
                    std::cerr << "Illegal instruction at "
                              << std::hex << get_pc() << ": " << std::dec
                              << *reinterpret_cast<Instruction *>(&inst_buffer) << std::endl;

                    return false;
                case trap::BREAKPOINT:
                    std::cerr << "Break point at " << std::hex << get_pc() << std::endl;
                    inc_pc(ECALLInst::INST_WIDTH);

                    return true;
                case trap::LOAD_ADDRESS_MISALIGNED:
                case trap::LOAD_ACCESS_FAULT:
                    std::cerr << "Load address misaligned at "
                              << std::hex << get_pc() << ": " << std::dec
                              << *reinterpret_cast<Instruction *>(&inst_buffer) << std::endl;

                    return false;
                case trap::STORE_AMO_ADDRESS_MISALIGNED:
                case trap::STORE_AMO_ACCESS_FAULT:
                    std::cerr << "Store or AMO address misaligned at "
                              << std::hex << get_pc() << ": " << std::dec
                              << *reinterpret_cast<Instruction *>(&inst_buffer) << std::endl;

                    return false;
                case trap::U_MODE_ENVIRONMENT_CALL:
                    if (syscall_handler()) {
                        inc_pc(ECALLInst::INST_WIDTH);
                        return true;
                    } else {
                        return false;
                    }
                case trap::S_MODE_ENVIRONMENT_CALL:
                    riscv_isa_unreachable("no system mode interrupt!");
                case trap::M_MODE_ENVIRONMENT_CALL:
                    riscv_isa_unreachable("no machine mode interrupt!");
                case trap::INSTRUCTION_PAGE_FAULT:
                    std::cerr << "Instruction page fault at "
                              << std::hex << get_pc() << ": " << std::dec
                              << *reinterpret_cast<Instruction *>(&inst_buffer) << std::endl;

                    return false;
                case trap::LOAD_PAGE_FAULT:
                    std::cerr << "Load page fault at "
                              << std::hex << get_pc() << ": " << std::dec
                              << *reinterpret_cast<Instruction *>(&inst_buffer) << std::endl;

                    return false;
                case trap::STORE_AMO_PAGE_FAULT:
                    std::cerr << "Store or AMO page fault at "
                              << std::hex << get_pc() << ": " << std::dec
                              << *reinterpret_cast<Instruction *>(&inst_buffer) << std::endl;

                    return false;
                default:
                    riscv_isa_unreachable("unknown internal interrupt!");
            }
        }

        void start() { while (visit() || supervisor_trap_handler(csr_reg[CSRRegT::SCAUSE])); }
    };
}


#endif //NEUTRON_RISCV_LINUX_HPP
