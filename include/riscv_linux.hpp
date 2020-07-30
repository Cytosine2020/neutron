#ifndef NEUTRON_RISCV_LINUX_HPP
#define NEUTRON_RISCV_LINUX_HPP


#include <iostream>
#include <map>

#include "target/hart.hpp"
#include "target/dump.hpp"

#include "riscv_linux_program.hpp"
#include "unix_std.hpp"


#define neutron_syscall_0(func) \
    this->set_x(IntRegT::A0, func())

#define neutron_syscall_1(func) \
    this->set_x(IntRegT::A0, func(this->get_x(IntRegT::A0)))

#define neutron_syscall_2(func) \
    this->set_x(IntRegT::A0, func(this->get_x(IntRegT::A0), \
                            this->get_x(IntRegT::A1)))

#define neutron_syscall_3(func) \
    this->set_x(IntRegT::A0, func(this->get_x(IntRegT::A0), \
                                  this->get_x(IntRegT::A1), \
                                  this->get_x(IntRegT::A2)))

#define neutron_syscall_4(func) \
    this->set_x(IntRegT::A0, func(this->get_x(IntRegT::A0), \
                                  this->get_x(IntRegT::A1), \
                                  this->get_x(IntRegT::A2), \
                                  this->get_x(IntRegT::A3)))

#define neutron_syscall_5(func) \
    this->set_x(IntRegT::A0, func(this->get_x(IntRegT::A0), \
                                  this->get_x(IntRegT::A1), \
                                  this->get_x(IntRegT::A2), \
                                  this->get_x(IntRegT::A3), \
                                  this->get_x(IntRegT::A4)))

#define neutron_syscall_6(func) \
    this->set_x(IntRegT::A0, func(this->get_x(IntRegT::A0), \
                                  this->get_x(IntRegT::A1), \
                                  this->get_x(IntRegT::A2), \
                                  this->get_x(IntRegT::A3), \
                                  this->get_x(IntRegT::A4), \
                                  this->get_x(IntRegT::A5)))

#define neutron_syscall(num, func) \
    neutron_syscall_##num(func)


namespace neutron {
    template<typename SubT>
    class LinuxHart : public riscv_isa::Hart<SubT> {
    private:
        SubT *sub_type() { return static_cast<SubT *>(this); }

    protected:
        LinuxProgram<> &pcb;
        bool debug;

    public:
        using RetT = typename riscv_isa::Hart<SubT>::RetT;
        using XLenT = typename riscv_isa::Hart<SubT>::XLenT;
        using UXLenT = typename riscv_isa::Hart<SubT>::UXLenT;
        using IntRegT = typename riscv_isa::Hart<SubT>::IntRegT;
        using CSRRegT = typename riscv_isa::Hart<SubT>::CSRRegT;

        LinuxHart(UXLenT hart_id, LinuxProgram<> &mem) :
                riscv_isa::Hart<SubT>{hart_id, mem.pc, mem.int_reg}, pcb{mem}, debug{true} {
            this->cur_level = riscv_isa::USER_MODE;
            dup(0); // todo: ad hoc
            dup(1);
            dup(2);
        }

        void internal_interrupt_action(UXLenT interrupt, neutron_unused UXLenT trap_value) {
            this->csr_reg[CSRRegT::SCAUSE] = interrupt;
            this->csr_reg[CSRRegT::STVAL] = trap_value;
        }

        template<typename ValT>
        RetT mmu_load_int_reg(usize dest, UXLenT addr) {
            static_assert(sizeof(ValT) <= sizeof(UXLenT), "load width exceed bit width!");

            if ((addr & (sizeof(ValT) - 1)) != 0)
                return sub_type()->internal_interrupt(riscv_isa::trap::LOAD_ACCESS_FAULT, addr);

            ValT *ptr = pcb.template address_read<ValT>(addr);
            if (ptr == nullptr) {
                return sub_type()->internal_interrupt(riscv_isa::trap::LOAD_PAGE_FAULT, addr);
            } else {
                if (dest != 0) this->set_x(dest, *ptr);
                return true;
            }
        }

        template<typename ValT>
        RetT mmu_store_int_reg(usize src, UXLenT addr) {
            static_assert(sizeof(ValT) <= sizeof(UXLenT), "store width exceed bit width!");

            if ((addr & (sizeof(ValT) - 1)) != 0)
                return sub_type()->internal_interrupt(riscv_isa::trap::STORE_AMO_ACCESS_FAULT, addr);

            ValT *ptr = pcb.template address_write<ValT>(addr);
            if (ptr == nullptr) {
                return sub_type()->internal_interrupt(riscv_isa::trap::STORE_AMO_PAGE_FAULT, addr);
            } else {
                *ptr = static_cast<ValT>(this->get_x(src));
                return true;
            }
        }

        template<usize offset>
        RetT mmu_load_inst_half(UXLenT addr) {
            /// instruction misaligned is checked in jump or branch instructions

            u16 *ptr = pcb.template address_execute<u16>(addr + offset * sizeof(u16));
            if (ptr == nullptr) {
                return sub_type()->internal_interrupt(riscv_isa::trap::INSTRUCTION_PAGE_FAULT, addr);
            } else {
                *(reinterpret_cast<u16 *>(&this->inst_buffer) + offset) = *ptr;
                return true;
            }
        }

#if defined(__RV_EXTENSION_ZICSR__)

        RetT get_csr_reg(neutron_unused UXLenT index) { return this->csr_reg[index]; }

        RetT set_csr_reg(neutron_unused UXLenT index, neutron_unused UXLenT val) { return true; }

#endif // defined(__RV_EXTENSION_ZICSR__)

        RetT visit_fence_inst(neutron_unused riscv_isa::FENCEInst *inst) {
            return true; // todo
        }

#if defined(__RV_SUPERVISOR_MODE__)

        RetT visit_sret_inst(neutron_unused riscv_isa::SRETInst *inst) {
            return sub_type()->illegal_instruction(inst);
        }

#endif // defined(__RV_SUPERVISOR_MODE__)

        RetT visit_mret_inst(neutron_unused riscv_isa::MRETInst *inst) {
            return sub_type()->illegal_instruction(inst);
        }

        RetT visit_wfi_inst(neutron_unused riscv_isa::WFIInst *inst) {
            return sub_type()->illegal_instruction(inst);
        }

#if defined(__RV_SUPERVISOR_MODE__)

        RetT visit_sfencevma_inst(neutron_unused riscv_isa::SFENCEVAMInst *inst) {
            return sub_type()->illegal_instruction(inst);
        }

#endif // defined(__RV_SUPERVISOR_MODE__)

        int get_host_fd(int fd) { return fd + 3; }

        int get_guest_fd(int fd) { return fd - 3; }

        XLenT sys_faccessat(int dirfd, UXLenT pathname, XLenT mode, XLenT flags) {
            int ret;

            char *name = pcb.string_copy_from_guest(pathname);

            if (name == nullptr) {
                ret = -EFAULT;
            } else {
                ret = faccessat(dirfd, name, mode, flags);
                if (ret == -1) { ret = -errno; }
            }

            if (debug) {
                std::cout << "system call: " << ret
                          << " = faccessat(<dirfd> " << dirfd
                          << ", <pathname> " << name
                          << ", <mode> " << mode
                          << ", <flags> " << flags
                          << ");" << std::endl;
            }

            delete[] name;

            return ret;
        }

        XLenT sys_openat(int dirfd, UXLenT pathname, XLenT flags, XLenT mode) {
            int ret;

            char *name = pcb.string_copy_from_guest(pathname);

            if (name == nullptr) {
                ret = -EFAULT;
            } else {
                ret = openat(dirfd, name, flags, mode);
                if (ret == -1) {
                    ret = -errno;
                } else {
                    ret = get_guest_fd(ret);
                }
            }

            if (debug) {
                std::cout << "system call: " << ret
                          << " = openat(<dirfd> " << dirfd
                          << ", <pathname> " << name
                          << ", <flags> " << flags
                          << ", <mode> " << mode
                          << ");" << std::endl;
            }

            delete[] name;

            return ret;
        }

        XLenT sys_close(int fd) {
            int ret = close(get_host_fd(fd));

            if (ret != 0) {
                ret = -errno;
            }

            if (debug) {
                std::cout << "system call: " << ret
                << " = close(<fd> " << fd
                << ");" << std::endl;
            }

            return ret;
        }

        XLenT sys_lseek(int fd, XLenT offset, XLenT whence) {
            int ret = lseek(get_host_fd(fd), offset, whence);

            if (ret != 0) {
                ret = -errno;
            }

            if (debug) {
                std::cout << "system call: " << ret
                          << " = lseek(<fd> " << fd
                          << ", <offset>" << offset
                          << ", <whence>" << whence
                          << ");" << std::endl;
            }

            return ret;
        }

        XLenT sys_read(int fd, UXLenT addr, UXLenT size) {
            char *buffer = new char[size];

            int ret = read(get_host_fd(fd), buffer, size);
            UXLenT byte;

            if (ret == -1) {
                ret = -errno;
            } else {
                byte = pcb.memory_copy_to_guest(addr, buffer, ret);
                if (byte != static_cast<UXLenT>(ret)) { ret = -EFAULT; }
            }

            delete[] buffer;

            if (debug) {
                std::cout << "system call: " << ret
                          << " = read(<fd> " << fd
                          << ", <addr>" << addr
                          << ", <size>" << size
                          << ");" << std::endl;
            }

            return ret;
        }

        XLenT sys_write(int fd, UXLenT addr, UXLenT size) {
            char *buffer = new char[size];

            UXLenT byte = pcb.memory_copy_from_guest(buffer, addr, size);
            int ret;

            if (byte == size) {
                ret = write(get_host_fd(fd), buffer, byte);
                if (ret == -1) { ret = -errno; }
            } else {
                ret = -EFAULT;
            }

            delete[] buffer;

            if (debug) {
                std::cout << "system call: " << ret
                          << " = write(<fd> " << fd
                          << ", <addr>" << addr
                          << ", <size>" << size
                          << ");" << std::endl;
            }

            return ret;
        }

        XLenT sys_readv(int fd, UXLenT iov, UXLenT iovcnt) {
            (void) fd;
            (void) iov;
            (void) iovcnt;

            return -1; // todo
        }

        XLenT sys_writev(int fd, UXLenT iov, UXLenT iovcnt) {
            (void) fd;
            (void) iov;
            (void) iovcnt;

            return -1; // todo
        }

        XLenT sys_fstat(UXLenT fd, UXLenT addr) {
            (void) fd;
            (void) addr;
            return -1; // todo
        }

        XLenT sys_uname(UXLenT buf) {
            (void) buf;
            return -1; // todo
        }

        XLenT sys_brk(UXLenT addr) {
            return pcb.set_brk(addr);
        }

        XLenT sys_getpid() {
            int ret = getpid();

            if (debug) { std::cout << "system call: " << ret << " = getpid();" << std::endl; }

            return ret;
        }

        XLenT sys_getppid() {
            int ret = getppid();

            if (debug) { std::cout << "system call: " << ret << " = getppid();" << std::endl; }

            return ret;
        }

        XLenT sys_getuid() {
            int ret = getuid();

            if (debug) { std::cout << "system call: " << ret << " = getuid();" << std::endl; }

            return ret;
        }

        XLenT sys_geteuid() {
            int ret = geteuid();

            if (debug) { std::cout << "system call: " << ret << " = geteuid();" << std::endl; }

            return ret;
        }

        XLenT sys_getgid() {
            int ret = getgid();

            if (debug) { std::cout << "system call: " << ret << " = getgid();" << std::endl; }

            return ret;
        }

        XLenT sys_getegid() {
            int ret = getegid();

            if (debug) { std::cout << "system call: " << ret << " = getegid();" << std::endl; }

            return ret;
        }

        XLenT sys_gettid() {
            int ret = gettid();

            if (debug) { std::cout << "system call: " << ret << " = gettid();" << std::endl; }

            return ret;
        }

        XLenT sys_sysinfo(UXLenT info) {
            (void) info;
            return -1;
        }

        XLenT sys_statx(int dirfd, UXLenT pathname, XLenT flags, UXLenT mask, UXLenT statxbuf) {
            (void) dirfd;
            (void) pathname;
            (void) flags;
            (void) mask;
            (void) statxbuf;
            return -1; // todo
        }

        bool syscall_handler() {
            switch (this->get_x(IntRegT::A7)) {

#define make_syscall(num, name) \
                case syscall::name: \
                    neutron_syscall(num, sub_type()->sys_##name); \
                    return true

                make_syscall(4, faccessat);
                make_syscall(4, openat);
                make_syscall(1, close);
                make_syscall(3, lseek);
                make_syscall(3, read);
                make_syscall(3, write);
                make_syscall(3, readv);
                make_syscall(3, writev);
                make_syscall(2, fstat);
                case syscall::exit:
                    std::cout << std::endl << "[exit " << this->get_x(IntRegT::A0) << ']'
                              << std::endl;

                    return false;
                make_syscall(1, uname);
                make_syscall(1, brk);
                make_syscall(0, getpid);
                make_syscall(0, getppid);
                make_syscall(0, getuid);
                make_syscall(0, geteuid);
                make_syscall(0, getgid);
                make_syscall(0, getegid);
                make_syscall(0, gettid);
                make_syscall(1, sysinfo);
                make_syscall(5, statx);
                default:
                    std::cerr << "Invalid environment call number at " << std::hex << this->get_pc()
                              << ", call number " << std::dec << this->get_x(IntRegT::A7)
                              << std::endl;

                    return false;
#undef make_syscall
            }
        }

        bool trap_handler(XLenT cause) {
            switch (cause) {
                case riscv_isa::trap::INSTRUCTION_ADDRESS_MISALIGNED:
                case riscv_isa::trap::INSTRUCTION_ACCESS_FAULT:
                    std::cerr << "Instruction address misaligned at "
                              << std::hex << this->get_pc() << std::endl;

                    return false;
                case riscv_isa::trap::ILLEGAL_INSTRUCTION:
                    std::cerr << "Illegal instruction at "
                              << std::hex << this->get_pc() << ": " << std::dec
                              << *reinterpret_cast<riscv_isa::Instruction *>(&this->inst_buffer) << std::endl;

                    return false;
                case riscv_isa::trap::BREAKPOINT:
                    std::cerr << "Break point at " << std::hex << this->get_pc() << std::endl;
                    this->inc_pc(riscv_isa::ECALLInst::INST_WIDTH);

                    return true;
                case riscv_isa::trap::LOAD_ADDRESS_MISALIGNED:
                case riscv_isa::trap::LOAD_ACCESS_FAULT:
                    std::cerr << "Load address misaligned at "
                              << std::hex << this->get_pc() << ": " << std::dec
                              << *reinterpret_cast<riscv_isa::Instruction *>(&this->inst_buffer)
                              << " STVAL: " << this->csr_reg[CSRRegT::STVAL] << std::endl;

                    return false;
                case riscv_isa::trap::STORE_AMO_ADDRESS_MISALIGNED:
                case riscv_isa::trap::STORE_AMO_ACCESS_FAULT:
                    std::cerr << "Store or AMO address misaligned at "
                              << std::hex << this->get_pc() << ": " << std::dec
                              << *reinterpret_cast<riscv_isa::Instruction *>(&this->inst_buffer)
                              << " STVAL: " << this->csr_reg[CSRRegT::STVAL] << std::endl;

                    return false;
                case riscv_isa::trap::U_MODE_ENVIRONMENT_CALL:
                    if (syscall_handler()) {
                        this->inc_pc(riscv_isa::ECALLInst::INST_WIDTH);
                        return true;
                    } else {
                        return false;
                    }
                case riscv_isa::trap::S_MODE_ENVIRONMENT_CALL:
                    riscv_isa_unreachable("no system mode interrupt!");
                case riscv_isa::trap::M_MODE_ENVIRONMENT_CALL:
                    riscv_isa_unreachable("no machine mode interrupt!");
                case riscv_isa::trap::INSTRUCTION_PAGE_FAULT:
                    std::cerr << "Instruction page fault at "
                              << std::hex << this->get_pc() << ": " << std::dec
                              << *reinterpret_cast<riscv_isa::Instruction *>(&this->inst_buffer)
                              << " STVAL: " << this->csr_reg[CSRRegT::STVAL] << std::endl;

                    return false;
                case riscv_isa::trap::LOAD_PAGE_FAULT:
                    std::cerr << "Load page fault at "
                              << std::hex << this->get_pc() << ": " << std::dec
                              << *reinterpret_cast<riscv_isa::Instruction *>(&this->inst_buffer)
                              << " STVAL: " << this->csr_reg[CSRRegT::STVAL] << std::endl;

                    return false;
                case riscv_isa::trap::STORE_AMO_PAGE_FAULT:
                    std::cerr << "Store or AMO page fault at "
                              << std::hex << this->get_pc() << ": " << std::dec
                              << *reinterpret_cast<riscv_isa::Instruction *>(&this->inst_buffer)
                              << " STVAL: " << this->csr_reg[CSRRegT::STVAL] << std::endl;

                    return false;
                default:
                    riscv_isa_unreachable("unknown internal interrupt!");
            }
        }

        void start() { while (sub_type()->visit() || trap_handler(this->csr_reg[CSRRegT::SCAUSE])) {}}
    };
}


#endif //NEUTRON_RISCV_LINUX_HPP
