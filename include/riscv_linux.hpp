#ifndef NEUTRON_RISCV_LINUX_HPP
#define NEUTRON_RISCV_LINUX_HPP


#include <cerrno>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <sys/syscall.h>

#include <iostream>
#include <map>

#include "target/hart.hpp"
#include "target/dump.hpp"

#include "riscv_linux_program.hpp"
#include "unix_std.hpp"


namespace neutron {
    template<typename SubT, typename xlen = typename riscv_isa::xlen_trait>
    class LinuxHart : public riscv_isa::Hart<SubT> {
    private:
        using iovec = typename LinuxProgram<xlen>::iovec;

        SubT *sub_type() { return static_cast<SubT *>(this); }

    protected:
        LinuxProgram<xlen> &pcb;
        std::string riscv_sysroot;
        std::ostream &debug_stream;
        bool debug;

    public:
        using RetT = typename riscv_isa::Hart<SubT>::RetT;
        using XLenT = typename riscv_isa::Hart<SubT>::XLenT;
        using UXLenT = typename riscv_isa::Hart<SubT>::UXLenT;
        using IntRegT = typename riscv_isa::Hart<SubT>::IntRegT;
        using CSRRegT = typename riscv_isa::Hart<SubT>::CSRRegT;

        LinuxHart(UXLenT hart_id, LinuxProgram<> &mem) :
                riscv_isa::Hart<SubT>{hart_id, mem.pc, mem.int_reg}, pcb{mem},
                riscv_sysroot{getenv("RISCV_SYSROOT")}, debug_stream{std::cout}, debug{true} {
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

        int get_host_fd(int fd) { return fd > 0 ? fd + 3 : fd; }

        int get_guest_fd(int fd) { return fd > 0 ? fd - 3 : fd; }

        std::string file_name_resolve(const std::string &origin) {
            if (origin[0] == '/') {
                if (origin == "/etc/ld.so.cache") return riscv_sysroot + origin;
                if (origin == "/etc/ld.so.preload") return riscv_sysroot + origin;
                if (access((riscv_sysroot + origin).c_str(), F_OK) == 0) return riscv_sysroot + origin;
            }

            return origin;
        }

        XLenT sys_getcwd(UXLenT buf, XLenT size) {
            // todo: remove riscv system root

            char *host_buf = new char[size];

            int ret = buf;

            char *result = getcwd(host_buf, size);

            if (result == host_buf) {
                usize len = strlen(host_buf);
                usize byte = pcb.memory_copy_to_guest(buf, host_buf, len);
                if (byte != len) {
                    ret = -EFAULT;
                }
            } else {
                ret = -errno;
            }

            if (debug) {
                debug_stream << "system call: " << ret
                             << " = getcwd(<buf> " << buf
                             << ", <size> " << size
                             << ");" << std::endl;
            }

            return ret;
        }

        XLenT sys_faccessat(int dirfd, UXLenT pathname, XLenT mode, XLenT flags) {
            int ret;
            std::string name{};

            if (pcb.string_copy_from_guest(pathname, name)) {
                auto real_name = file_name_resolve(name);

                ret = faccessat(get_host_fd(dirfd), real_name.c_str(), mode, flags);
                if (ret == -1) { ret = -errno; }
            } else {
                ret = -EFAULT;
            }

            if (debug) {
                debug_stream << "system call: " << ret
                             << " = faccessat(<dirfd> " << dirfd
                             << ", <pathname> " << name
                             << ", <mode> " << mode
                             << ", <flags> " << flags
                             << ");" << std::endl;
            }

            return ret;
        }

        XLenT sys_openat(int dirfd, UXLenT pathname, XLenT flags, XLenT mode) {
            int ret;
            std::string name{};

            if (pcb.string_copy_from_guest(pathname, name)) {
                auto real_name = file_name_resolve(name);

                ret = openat(get_host_fd(dirfd), real_name.c_str(), flags, mode);
                if (ret == -1) { ret = -errno; }
                else { ret = get_guest_fd(ret); }
            } else {
                ret = -EFAULT;
            }

            if (debug) {
                debug_stream << "system call: " << ret
                             << " = openat(<dirfd> " << dirfd
                             << ", <pathname> " << name
                             << ", <flags> " << flags
                             << ", <mode> " << mode
                             << ");" << std::endl;
            }

            return ret;
        }

        XLenT sys_close(int fd) {
            int ret = close(get_host_fd(fd));

            if (ret != 0) {
                ret = -errno;
            }

            if (debug) {
                debug_stream << "system call: " << ret
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
                debug_stream << "system call: " << ret
                             << " = lseek(<fd> " << fd
                             << ", <offset> " << offset
                             << ", <whence> " << whence
                             << ");" << std::endl;
            }

            return ret;
        }

        XLenT sys_read(int fd, UXLenT addr, UXLenT size) {
            int ret;

            std::vector<::iovec> vec{};

            if (pcb.memory_get_vector(addr, size, riscv_isa::W_BIT, vec)) {
                ret = readv(get_host_fd(fd), vec.data(), vec.size());
                if (ret == -1) { ret = -errno; }
            } else {
                ret = -EFAULT;
            }

            if (debug) {
                debug_stream << "system call: " << ret
                             << " = read(<fd> " << fd
                             << ", <addr> " << addr
                             << ", <size> " << size
                             << ");" << std::endl;
            }

            return ret;
        }

        XLenT sys_write(int fd, UXLenT addr, UXLenT size) {
            int ret;

            std::vector<::iovec> vec{};

            if (pcb.memory_get_vector(addr, size, riscv_isa::R_BIT, vec)) {
                ret = writev(get_host_fd(fd), vec.data(), vec.size());
                if (ret == -1) { ret = -errno; }
            } else {
                ret = -EFAULT;
            }

            if (debug) {
                debug_stream << "system call: " << ret
                             << " = write(<fd> " << fd
                             << ", <addr> " << addr
                             << ", <size> " << size
                             << ");" << std::endl;
            }

            return ret;
        }

        XLenT sys_readv(int fd, UXLenT iov, UXLenT iovcnt) {
            int ret;

            std::vector<::iovec> vec{};

            if (pcb.memory_convert_io_vec(iov, iovcnt, riscv_isa::W_BIT, vec)) {
                ret = readv(get_host_fd(fd), vec.data(), vec.size());

                if (ret == -1) { ret = -errno; }
            } else {
                ret = -EINVAL;
            }

            if (debug) {
                debug_stream << "system call: " << ret
                             << " = readv(<fd> " << fd
                             << ", <iov> " << iov
                             << ", <iovcnt> " << iovcnt
                             << ");" << std::endl;
            }

            return ret;
        }

        XLenT sys_writev(int fd, UXLenT iov, UXLenT iovcnt) {
            int ret;

            std::vector<::iovec> vec{};

            if (pcb.memory_convert_io_vec(iov, iovcnt, riscv_isa::R_BIT, vec)) {
                ret = writev(get_host_fd(fd), vec.data(), vec.size());

                if (ret == -1) { ret = -errno; }
            } else {
                ret = -EINVAL;
            }

            if (debug) {
                debug_stream << "system call: " << ret
                             << " = writev(<fd> " << fd
                             << ", <iov> " << iov
                             << ", <iovcnt> " << iovcnt
                             << ");" << std::endl;
            }

            return ret;
        }

        XLenT sys_fstat(UXLenT fd, UXLenT addr) {
            struct ::stat host_buf{};
            stat guest_buf{};

            int ret = fstat(get_host_fd(fd), &host_buf);

            if (ret == 0) {
                guest_buf.st_dev = host_buf.st_dev;
                guest_buf.st_ino = host_buf.st_ino;
                guest_buf.st_mode = host_buf.st_mode;
                guest_buf.st_nlink = host_buf.st_nlink;
                guest_buf.st_uid = host_buf.st_uid;
                guest_buf.st_gid = host_buf.st_gid;
                guest_buf.st_rdev = host_buf.st_rdev;
                guest_buf.st_size = host_buf.st_size;
                guest_buf.st_blksize = host_buf.st_blksize;
                guest_buf.st_blocks = host_buf.st_blocks;
#if defined(__linux__)
                guest_buf.atime.tv_sec = host_buf.st_atim.tv_sec;
                guest_buf.atime.tv_nsec = host_buf.st_atim.tv_nsec;
                guest_buf.mtime.tv_sec = host_buf.st_mtim.tv_sec;
                guest_buf.mtime.tv_nsec = host_buf.st_mtim.tv_nsec;
                guest_buf.ctime.tv_sec = host_buf.st_ctim.tv_sec;
                guest_buf.ctime.tv_nsec = host_buf.st_ctim.tv_nsec;
#elif defined(__APPLE__)
                guest_buf.atime.tv_sec = host_buf.st_atimespec.tv_sec;
                guest_buf.atime.tv_nsec = host_buf.st_atimespec.tv_nsec;
                guest_buf.mtime.tv_sec = host_buf.st_mtimespec.tv_sec;
                guest_buf.mtime.tv_nsec = host_buf.st_mtimespec.tv_nsec;
                guest_buf.ctime.tv_sec = host_buf.st_ctimespec.tv_sec;
                guest_buf.ctime.tv_nsec = host_buf.st_ctimespec.tv_nsec;
#endif

                if (pcb.memory_copy_to_guest(addr, &guest_buf, sizeof(guest_buf)) != sizeof(guest_buf)) {
                    ret = -EFAULT;
                }
            } else {
                ret = -errno;
            }

            if (debug) {
                debug_stream << "system call: " << ret
                             << " = fstatv(<fd> " << fd
                             << ", <addr> "
                             << ");" << std::endl;
            }

            return ret;
        }

        XLenT sys_uname(UXLenT buf) {
            (void) buf;

            struct ::utsname host_buf{};
            utsname guest_buf{};

            int ret = uname(&host_buf);

            if (ret == 0) {
                strncpy(guest_buf.sysname, "Linux", sizeof(guest_buf.sysname) - 1);
                strncpy(guest_buf.nodename, host_buf.nodename, sizeof(guest_buf.nodename) - 1);
                strncpy(guest_buf.release, host_buf.release, sizeof(guest_buf.release) - 1);
                strncpy(guest_buf.version, host_buf.version, sizeof(guest_buf.version) - 1);
                strncpy(guest_buf.machine, "riscv32", sizeof(guest_buf.machine) - 1);

                if (pcb.memory_copy_to_guest(buf, &guest_buf, sizeof(guest_buf)) != sizeof(guest_buf)) {
                    ret = -EFAULT;
                }
            } else {
                ret = -errno;
            }

            if (debug) {
                debug_stream << "system call: " << ret
                             << " = uname(<buf> struct utsname{<sysname> " << guest_buf.sysname
                             << ", <nodename> " << guest_buf.nodename
                             << ", <release> " << guest_buf.release
                             << ", <version> " << guest_buf.version
                             << ", <machine> " << guest_buf.machine
                             << "})" << std::endl;
            }

            return ret;
        }

        XLenT sys_brk(UXLenT addr) {
            int ret = pcb.set_brk(addr);

            if (debug) {
                debug_stream << "system call: " << ret
                << " = brk(<addr> " << addr
                << ");" << std::endl;
            }

            return ret;
        }

        XLenT sys_getpid() {
            int ret = getpid();

            if (debug) { debug_stream << "system call: " << ret << " = getpid();" << std::endl; }

            return ret;
        }

        XLenT sys_getppid() {
            int ret = getppid();

            if (debug) { debug_stream << "system call: " << ret << " = getppid();" << std::endl; }

            return ret;
        }

        XLenT sys_getuid() {
            int ret = getuid();

            if (debug) { debug_stream << "system call: " << ret << " = getuid();" << std::endl; }

            return ret;
        }

        XLenT sys_geteuid() {
            int ret = geteuid();

            if (debug) { debug_stream << "system call: " << ret << " = geteuid();" << std::endl; }

            return ret;
        }

        XLenT sys_getgid() {
            int ret = getgid();

            if (debug) { debug_stream << "system call: " << ret << " = getgid();" << std::endl; }

            return ret;
        }

        XLenT sys_getegid() {
            int ret = getegid();

            if (debug) { debug_stream << "system call: " << ret << " = getegid();" << std::endl; }

            return ret;
        }

        XLenT sys_gettid() {
            pid_t ret = ::syscall(SYS_gettid);

            if (debug) { debug_stream << "system call: " << ret << " = gettid();" << std::endl; }

            return ret;
        }

        XLenT sys_sysinfo(UXLenT info) {
            (void) info;

            if (debug) {
                debug_stream << "system call: "
                             << " = sysinfo("
                             << ");" << std::endl;
            }

            return -1; // todo
        }

        XLenT sys_mmap(UXLenT addr, UXLenT length, XLenT prot, XLenT flags, XLenT fd, UXLenT offset) {
            int ret;
            int fix = false;
            void *map = MAP_FAILED;

            riscv_isa::MemoryProtection guest_prot = riscv_isa::NOT_PRESENT;
            int host_prot = 0;

            if ((prot & PROT_EXEC) > 0) {
                if ((prot & PROT_WRITE) > 0) {
                    guest_prot = riscv_isa::EXECUTE_READ_WRITE;
                    host_prot = PROT_READ | PROT_WRITE;
                } else if ((prot & PROT_READ) > 0) {
                    guest_prot = riscv_isa::EXECUTE_READ;
                    host_prot = PROT_READ;
                } else {
                    guest_prot = riscv_isa::EXECUTE;
                    host_prot = PROT_READ;
                }
            } else {
                if ((prot & PROT_WRITE) > 0) {
                    guest_prot = riscv_isa::READ_WRITE;
                    host_prot = PROT_READ | PROT_WRITE;
                } else {
                    guest_prot = riscv_isa::READ;
                    host_prot = PROT_READ;
                }
            }

            UXLenT guest_addr = addr / RISCV_PAGE_SIZE * RISCV_PAGE_SIZE;
            UXLenT guest_length = divide_ceil(length, RISCV_PAGE_SIZE) * RISCV_PAGE_SIZE;

            if ((flags & MAP_FIXED) > 0) {
                if (addr != guest_addr) {
                    ret = -EINVAL;
                    goto end;
                }

                fix = true;
                flags &= (~MAP_FIXED);
            } // todo: replace

            if ((flags & MAP_FIXED_NOREPLACE) > 0) { neutron_abort("MAP_FIXED_NOREPLACE not support!"); }

            if ((flags & MAP_GROWSDOWN) > 0) { neutron_abort("MAP_GROWSDOWN not support!"); }

            if ((flags & MAP_HUGETLB) > 0) { neutron_abort("MAP_HUGETLB not support!"); }

            if ((flags & MAP_STACK) > 0) { neutron_abort("MAP_STACK not support!"); }

            map = mmap(nullptr, length, host_prot, flags, get_host_fd(fd), offset);

            if (map != MAP_FAILED) {
                ret = pcb.add_map(guest_addr, map, guest_length, guest_prot, fix);
                if (ret == 0) {
                    ret = -ENOMEM;
                }
            } else {
                ret = -errno;
            }

            end:

            if (debug) {
                debug_stream << "system call: " << ret
                             << " = mmap(<addr> " << addr
                             << ", <length> " << length
                             << ", <prot> " << prot
                             << ", <flags> " << flags
                             << ", <fd> " << fd
                             << ", <offset> " << offset
                             << ");" << std::endl;
            }

            return ret;
        }

        XLenT sys_mprotect(UXLenT addr, UXLenT len, XLenT prot) {
            int ret = 0; // todo: not implemented

            if (debug) {
                debug_stream << "system call: " << ret
                             << " = mprotect(<addr> " << addr
                             << ", <len> " << len
                             << ", <prot> " << prot
                             << ");" << std::endl;
            }

            return ret;
        }

        XLenT sys_statx(int dirfd, UXLenT pathname, XLenT flags, UXLenT mask, UXLenT statxbuf) {
            int ret;
            std::string name{};

            struct ::statx host_buf{};
            statx guest_buf{};

            if (pcb.string_copy_from_guest(pathname, name)) {
                auto real_name = file_name_resolve(name);

                ret = ::statx(get_host_fd(dirfd), real_name.c_str(), flags, mask, &host_buf);

                if (ret == 0) {
                    guest_buf.stx_mask = host_buf.stx_mask;
                    guest_buf.stx_blksize = host_buf.stx_blksize;
                    guest_buf.stx_attributes = host_buf.stx_attributes;
                    guest_buf.stx_nlink = host_buf.stx_nlink;
                    guest_buf.stx_uid = host_buf.stx_uid;
                    guest_buf.stx_gid = host_buf.stx_uid;
                    guest_buf.stx_mode = host_buf.stx_uid;
                    guest_buf.stx_ino = host_buf.stx_uid;
                    guest_buf.stx_size = host_buf.stx_uid;
                    guest_buf.stx_blocks = host_buf.stx_uid;
                    guest_buf.stx_attributes_mask = host_buf.stx_uid;
                    guest_buf.stx_atime.tv_sec = host_buf.stx_atime.tv_sec;
                    guest_buf.stx_atime.tv_nsec = host_buf.stx_atime.tv_nsec;
                    guest_buf.stx_btime.tv_sec = host_buf.stx_btime.tv_sec;
                    guest_buf.stx_btime.tv_nsec = host_buf.stx_btime.tv_nsec;
                    guest_buf.stx_ctime.tv_sec = host_buf.stx_ctime.tv_sec;
                    guest_buf.stx_ctime.tv_nsec = host_buf.stx_ctime.tv_nsec;
                    guest_buf.stx_mtime.tv_sec = host_buf.stx_mtime.tv_sec;
                    guest_buf.stx_mtime.tv_nsec = host_buf.stx_mtime.tv_nsec;
                    guest_buf.stx_rdev_major = host_buf.stx_rdev_major;
                    guest_buf.stx_rdev_minor = host_buf.stx_rdev_minor;
                    guest_buf.stx_dev_major = host_buf.stx_dev_major;
                    guest_buf.stx_dev_minor = host_buf.stx_dev_minor;

                    if (pcb.memory_copy_to_guest(statxbuf, &guest_buf, sizeof(guest_buf)) != sizeof(guest_buf)) {
                        ret = -EFAULT;
                    }
                } else {
                    ret = -errno;
                }
            } else {
                ret = -EFAULT;
            }

            if (debug) {
                debug_stream << "system call: " << ret
                             << " = statx(<dirfd> " << dirfd
                             << ", <pathname> " << name
                             << ", <flags> " << flags
                             << ", <mask> " << mask
                             << ", <statxbuf> "
                             << ");" << std::endl;
            }

            return ret;
        }

        bool syscall_handler() {
            switch (this->get_x(IntRegT::A7)) {

#define make_syscall(num, name) \
                case syscall::name: \
                    neutron_syscall(num, sub_type()->sys_##name); \
                    return true

                make_syscall(2, getcwd);
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
                make_syscall(6, mmap);
                make_syscall(3, mprotect);
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
