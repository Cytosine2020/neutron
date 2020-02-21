#ifndef NEUTRON_RISCV_LINUX_HPP
#define NEUTRON_RISCV_LINUX_HPP


#include <iostream>
#include <map>

#include "target/hart.hpp"
#include "target/dump.hpp"

using namespace riscv_isa;

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
    template <typename SubT>
    class LinuxHart : public Hart<SubT> {
    private:
        SubT *sub_type() { return static_cast<SubT *>(this); }

    protected:
        LinuxProgram<> &pcb;

    public:
        using RetT = typename Hart<SubT>::RetT;
        using XLenT = typename Hart<SubT>::XLenT;
        using UXLenT = typename Hart<SubT>::UXLenT;
        using IntRegT = typename Hart<SubT>::IntRegT;
        using CSRRegT = typename Hart<SubT>::CSRRegT;

        LinuxHart(UXLenT hart_id, LinuxProgram<> &mem) : Hart<SubT>{hart_id, mem.pc, mem.int_reg}, pcb{mem} {
            this->cur_level = USER_MODE;
        }

        void internal_interrupt_action(UXLenT interrupt, riscv_isa_unused UXLenT trap_value) {
            this->csr_reg[CSRRegT::SCAUSE] = interrupt;
        }

        template<typename ValT>
        RetT mmu_load_int_reg(usize dest, UXLenT addr) {
            static_assert(sizeof(ValT) <= sizeof(UXLenT), "load width exceed bit width!");

            if ((addr & (sizeof(ValT) - 1)) != 0)
                return sub_type()->internal_interrupt(trap::LOAD_ACCESS_FAULT, addr);

            ValT *ptr = pcb.template address_read<ValT>(addr);
            if (ptr == nullptr) {
                return sub_type()->internal_interrupt(trap::LOAD_PAGE_FAULT, addr);
            } else {
                if (dest != 0) this->int_reg.set_x(dest, *ptr);
                return true;
            }
        }

        template<typename ValT>
        RetT mmu_store_int_reg(usize src, UXLenT addr) {
            static_assert(sizeof(ValT) <= sizeof(UXLenT), "store width exceed bit width!");

            if ((addr & (sizeof(ValT) - 1)) != 0)
                return sub_type()->internal_interrupt(trap::STORE_AMO_ACCESS_FAULT, addr);

            ValT *ptr = pcb.template address_write<ValT>(addr);
            if (ptr == nullptr) {
                return sub_type()->internal_interrupt(trap::STORE_AMO_PAGE_FAULT, addr);
            } else {
                *ptr = static_cast<ValT>(this->int_reg.get_x(src));
                return true;
            }
        }

        template<usize offset>
        RetT mmu_load_inst_half(UXLenT addr) {
            /// instruction misaligned is checked in jump or branch instructions

            u16 *ptr = pcb.template address_execute<u16>(addr + offset * sizeof(u16));
            if (ptr == nullptr) {
                return sub_type()->internal_interrupt(trap::INSTRUCTION_PAGE_FAULT, addr);
            } else {
                *(reinterpret_cast<u16 *>(&this->inst_buffer) + offset) = *ptr;
                return true;
            }
        }

#if defined(__RV_EXTENSION_ZICSR__)

        RetT get_csr_reg(riscv_isa_unused UXLenT index) { return this->csr_reg[index]; }

        RetT set_csr_reg(riscv_isa_unused UXLenT index, riscv_isa_unused UXLenT val) { return true; }

#endif // defined(__RV_EXTENSION_ZICSR__)

        RetT visit_fence_inst(riscv_isa_unused FENCEInst *inst) { return sub_type()->illegal_instruction(inst); }

#if defined(__RV_SUPERVISOR_MODE__)

        RetT visit_sret_inst(riscv_isa_unused SRETInst *inst) { return sub_type()->illegal_instruction(inst); }

#endif // defined(__RV_SUPERVISOR_MODE__)

        RetT visit_mret_inst(riscv_isa_unused MRETInst *inst) { return sub_type()->illegal_instruction(inst); }

        RetT visit_wfi_inst(riscv_isa_unused WFIInst *inst) { return sub_type()->illegal_instruction(inst); }

#if defined(__RV_SUPERVISOR_MODE__)

        RetT visit_sfencevma_inst(riscv_isa_unused SFENCEVAMInst *inst) { return sub_type()->illegal_instruction(inst); }

#endif // defined(__RV_SUPERVISOR_MODE__)

        XLenT sys_close(UXLenT fd) {
            return fd > 2 ? close(fd) : 0; // todo: stdin, stdout, stderr
        }

        XLenT sys_lseek(XLenT fd, XLenT offset, XLenT whence) {
            return lseek(fd, offset, whence);
        }

        XLenT sys_read(XLenT fd, UXLenT addr, UXLenT size) {
            char *buffer = new char[size];

            XLenT result = read(fd, buffer, size);

            for (usize i = 0; i < size; ++i) {
                char *byte = pcb.address_write<char>(addr + i); // todo: optimize
                if (byte == nullptr) return 0;
                else *byte = buffer[i];
            }

            delete[] buffer;

            return result;
        }

        XLenT sys_write(XLenT fd, UXLenT addr, UXLenT size) {
            char *buffer = new char[size];

            for (usize i = 0; i < size; ++i) {
                char *byte = pcb.address_read<char>(addr + i); // todo: optimize
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
            switch (this->int_reg.get_x(IntRegT::A7)) {
                case syscall::close:
                    neutron_syscall(1, sub_type()->sys_close, this->int_reg);
                    return true;
                case syscall::lseek:
                    neutron_syscall(3, sub_type()->sys_lseek, this->int_reg);
                    return true;
                case syscall::read:
                    neutron_syscall(3, sub_type()->sys_read, this->int_reg);
                    return true;
                case syscall::write:
                    neutron_syscall(3, sub_type()->sys_write, this->int_reg);
                    return true;
                case syscall::fstat:
                    neutron_syscall(2, sub_type()->sys_fstat, this->int_reg);
                    return true;
                case syscall::exit:
                    std::cout << std::endl << "[exit " << this->int_reg.get_x(IntRegT::A0) << ']'
                              << std::endl;

                    return false;
                case syscall::brk:
                    neutron_syscall(1, sys_brk, this->int_reg);
                    return true;
                default:
                    std::cerr << "Invalid environment call number at " << std::hex << this->get_pc()
                              << ", call number " << std::dec << this->int_reg.get_x(IntRegT::A7)
                              << std::endl;

                    return false;
            }
        }

        bool supervisor_trap_handler(XLenT cause) {
            switch (cause) {
                case trap::INSTRUCTION_ADDRESS_MISALIGNED:
                case trap::INSTRUCTION_ACCESS_FAULT:
                    std::cerr << "Instruction address misaligned at "
                              << std::hex << this->get_pc() << std::endl;

                    return false;
                case trap::ILLEGAL_INSTRUCTION:
                    std::cerr << "Illegal instruction at "
                              << std::hex << this->get_pc() << ": " << std::dec
                              << *reinterpret_cast<Instruction *>(&this->inst_buffer) << std::endl;

                    return false;
                case trap::BREAKPOINT:
                    std::cerr << "Break point at " << std::hex << this->get_pc() << std::endl;
                    this->inc_pc(ECALLInst::INST_WIDTH);

                    return true;
                case trap::LOAD_ADDRESS_MISALIGNED:
                case trap::LOAD_ACCESS_FAULT:
                    std::cerr << "Load address misaligned at "
                              << std::hex << this->get_pc() << ": " << std::dec
                              << *reinterpret_cast<Instruction *>(&this->inst_buffer) << std::endl;

                    return false;
                case trap::STORE_AMO_ADDRESS_MISALIGNED:
                case trap::STORE_AMO_ACCESS_FAULT:
                    std::cerr << "Store or AMO address misaligned at "
                              << std::hex << this->get_pc() << ": " << std::dec
                              << *reinterpret_cast<Instruction *>(&this->inst_buffer) << std::endl;

                    return false;
                case trap::U_MODE_ENVIRONMENT_CALL:
                    if (syscall_handler()) {
                        this->inc_pc(ECALLInst::INST_WIDTH);
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
                              << std::hex << this->get_pc() << ": " << std::dec
                              << *reinterpret_cast<Instruction *>(&this->inst_buffer) << std::endl;

                    return false;
                case trap::LOAD_PAGE_FAULT:
                    std::cerr << "Load page fault at "
                              << std::hex << this->get_pc() << ": " << std::dec
                              << *reinterpret_cast<Instruction *>(&this->inst_buffer) << std::endl;

                    return false;
                case trap::STORE_AMO_PAGE_FAULT:
                    std::cerr << "Store or AMO page fault at "
                              << std::hex << this->get_pc() << ": " << std::dec
                              << *reinterpret_cast<Instruction *>(&this->inst_buffer) << std::endl;

                    return false;
                default:
                    riscv_isa_unreachable("unknown internal interrupt!");
            }
        }

        void start() { while (sub_type()->visit() || supervisor_trap_handler(this->csr_reg[CSRRegT::SCAUSE])); }
    };
}


#endif //NEUTRON_RISCV_LINUX_HPP
