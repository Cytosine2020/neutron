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
#include <sys/resource.h>

#include <iostream>
#include <map>

#include "target/hart.hpp"
#include "target/dump.hpp"

#include "neutron_utility.hpp"
#include "riscv_linux_program.hpp"
#include "linux_std.hpp"


namespace neutron {
    template<typename SubT, typename xlen = typename riscv_isa::xlen_trait>
    class LinuxHart : public riscv_isa::Hart<SubT> {
    private:
        using iovec = typename LinuxProgram<xlen>::iovec;

        SubT *sub_type() { return static_cast<SubT *>(this); }

    protected:
        LinuxProgram<xlen> &pcb;
        std::string riscv_sysroot;
        std::map<int, int> fd_map;
        std::ostream &debug_stream;
        bool debug;

    public:
        using RetT = typename riscv_isa::Hart<SubT>::RetT;
        using XLenT = typename riscv_isa::Hart<SubT>::XLenT;
        using UXLenT = typename riscv_isa::Hart<SubT>::UXLenT;
        using IntRegT = typename riscv_isa::Hart<SubT>::IntRegT;
        using CSRRegT = typename riscv_isa::Hart<SubT>::CSRRegT;

        LinuxHart(UXLenT hart_id, LinuxProgram<xlen> &mem) :
                riscv_isa::Hart<SubT>{hart_id, mem.pc, mem.int_reg}, pcb{mem},
                riscv_sysroot{getenv("RISCV_SYSROOT")}, debug_stream{std::cout}, debug{false} {
            this->cur_level = riscv_isa::USER_MODE;
            fd_map.emplace(0, dup(0));
            fd_map.emplace(1, dup(1));
            fd_map.emplace(2, dup(2));
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
                memcpy(reinterpret_cast<u16 *>(&this->inst_buffer) + offset, ptr, 2);
                return true;
            }
        }

#if defined(__RV_EXTENSION_A__)

        template<typename ValT>
        RetT mmu_store_xlen(XLenT val, riscv_isa_unused XLenT addr) {
            static_assert(sizeof(ValT) <= sizeof(UXLenT), "store width exceed bit width!");

            if ((addr & (sizeof(ValT) - 1)) != 0)
                return sub_type()->internal_interrupt(riscv_isa::trap::STORE_AMO_ACCESS_FAULT, addr);

            ValT *ptr = pcb.template address_write<ValT>(addr);
            if (ptr == nullptr) {
                return sub_type()->internal_interrupt(riscv_isa::trap::STORE_AMO_PAGE_FAULT, addr);
            } else {
                *ptr = val;
                return true;
            }
        }

#endif

#if defined(__RV_EXTENSION_ZICSR__)

        RetT get_csr_reg(neutron_unused UXLenT index) { return this->csr_reg[index]; }

        RetT set_csr_reg(neutron_unused UXLenT index, neutron_unused UXLenT val) { return true; }

#endif // defined(__RV_EXTENSION_ZICSR__)

        RetT visit_fence_inst(neutron_unused riscv_isa::FENCEInst *inst) {
            this->inc_pc(riscv_isa::FENCEInst::INST_WIDTH);
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

        int get_host_fd(int fd) {
            if (fd < 0) return fd;

            auto ptr = fd_map.find(fd);

            if (ptr != fd_map.end()) {
                return ptr->second;
            } else {
                return -1; // todo: bad fd?
            }
        }

        int get_guest_fd(int fd) {
            if (fd < 0) return fd;

            auto ptr = fd_map.rbegin();

            int ret;

            if (ptr != fd_map.rend()) {
                ret = ptr->first + 1;
            } else {
                ret = 0;
            }

            fd_map.emplace(ret, fd);

            return ret;
        }

        std::string file_name_resolve(const std::string &origin) {
            if (origin[0] == '/') {
                if (origin == "/etc/ld.so.cache") return riscv_sysroot + origin;
                if (origin == "/etc/ld.so.preload") return riscv_sysroot + origin;
                if (access((riscv_sysroot + origin).c_str(), F_OK) == 0) return riscv_sysroot + origin;
            }

            return origin;
        }

        std::pair<riscv_isa::MemoryProtection, int> prot_convert(int prot) {
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
                } else if ((prot & PROT_READ) > 0) {
                    guest_prot = riscv_isa::EXECUTE_READ;
                    host_prot = PROT_READ;
                }
            }

            return std::make_pair(guest_prot, host_prot);
        }

        XLenT sys_getcwd(UXLenT buf, XLenT size) {
            // todo: remove riscv system root

            char *host_buf = new char[size];

            XLenT ret = buf;

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

        XLenT sys_fcntl(int fd, XLenT cmd, XLenT arg) {
            XLenT ret;

            ret = fcntl(get_host_fd(fd), cmd, arg);

            if (ret == -1) {
                ret = -errno;
            } else {
                switch (cmd) {
                    case F_DUPFD:
                    case F_DUPFD_CLOEXEC:
                        ret = get_guest_fd(ret);
                }
            }

            if (debug) {
                debug_stream << "system call: " << ret
                             << " = openat(<fd> " << fd
                             << ", <cmd> " << cmd
                             << ", <arg> " << arg
                             << ");" << std::endl;
            }

            return ret;
        }

        XLenT sys_faccessat(int dirfd, UXLenT pathname, XLenT mode, XLenT flags) {
            XLenT ret;
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
                             << ", <pathname> \"" << name
                             << "\", <mode> " << mode
                             << ", <flags> " << flags
                             << ");" << std::endl;
            }

            return ret;
        }

        XLenT sys_openat(int dirfd, UXLenT pathname, XLenT flags, XLenT mode) {
            XLenT ret;
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
                             << ", <pathname> \"" << name
                             << "\", <flags> " << flags
                             << ", <mode> " << mode
                             << ");" << std::endl;
            }

            return ret;
        }

        XLenT sys_close(int fd) {
            XLenT ret = close(get_host_fd(fd));

            if (ret != 0) {
                ret = -errno;
            }

            fd_map.erase(fd);

            if (debug) {
                debug_stream << "system call: " << ret
                             << " = close(<fd> " << fd
                             << ");" << std::endl;
            }

            return ret;
        }

        XLenT sys_lseek(int fd, XLenT offset, XLenT whence) {
            XLenT ret = lseek(get_host_fd(fd), offset, whence);

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
            XLenT ret;

            std::vector<::iovec> vec{};

            if (pcb.memory_get_vector(addr, size, riscv_isa::W_BIT, vec)) {
                ret = readv(get_host_fd(fd), vec.data(), vec.size());
                if (ret == -1) { ret = -errno; }
            } else {
                ret = -EFAULT;
            }

            if (debug) {
                char content[11]{};
                UXLenT read_size = std::min(10u, size);

                if (pcb.memory_copy_from_guest(content, addr, read_size) != read_size) {
                    neutron_unreachable("");
                }

                debug_stream << "system call: " << ret
                             << " = read(<fd> " << fd
                             << ", <addr> \"" << content
                             << "\", <size> " << size
                             << ");" << std::endl;
            }

            return ret;
        }

        XLenT sys_write(int fd, UXLenT addr, UXLenT size) {
            XLenT ret;

            std::vector<::iovec> vec{};

            if (pcb.memory_get_vector(addr, size, riscv_isa::R_BIT, vec)) {
                ret = writev(get_host_fd(fd), vec.data(), vec.size());
                if (ret == -1) { ret = -errno; }
            } else {
                ret = -EFAULT;
            }

            if (debug) {
                char content[11]{};
                UXLenT read_size = std::min(10u, size);

                if (pcb.memory_copy_from_guest(content, addr, read_size) != read_size) {
                    neutron_unreachable("");
                }

                debug_stream << "system call: " << ret
                             << " = write(<fd> " << fd
                             << ", <addr> \"" << content
                             << "\", <size> " << size
                             << ");" << std::endl;
            }

            return ret;
        }

        XLenT sys_readv(int fd, UXLenT iov, UXLenT iovcnt) {
            XLenT ret;

            std::vector<::iovec> vec{};

            if (pcb.memory_convert_io_vec(iov, iovcnt, riscv_isa::W_BIT, vec)) {
                ret = readv(get_host_fd(fd), vec.data(), vec.size());

                if (ret == -1) { ret = -errno; }
            } else {
                ret = -EFAULT;
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
            XLenT ret;

            std::vector<::iovec> vec{};

            if (pcb.memory_convert_io_vec(iov, iovcnt, riscv_isa::R_BIT, vec)) {
                ret = writev(get_host_fd(fd), vec.data(), vec.size());

                if (ret == -1) { ret = -errno; }
            } else {
                ret = -EFAULT;
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

            XLenT ret = fstat(get_host_fd(fd), &host_buf);

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

        XLenT sys_futex(UXLenT uaddr, XLenT futex_op, XLenT val,
                        UXLenT val2, UXLenT uaddr2, XLenT val3) {
            (void) val2;
            (void) uaddr2;
            (void) val3;

            XLenT ret = 0;

            // todo: not implement

            i32 *host_uaddr = pcb.template address_write<i32>(uaddr);

            switch (futex_op) {
                case FUTEX_WAIT_PRIVATE:
                    if (host_uaddr == nullptr) {
                        ret = -EINVAL;
                    }

                    *host_uaddr = 0;

//                    if (*host_uaddr != val) {
//                        ret = -EAGAIN;
//                    }

                    break;
            }

            if (debug) {
                debug_stream << "system call: " << ret;
                if (host_uaddr == nullptr) {
                    debug_stream << " = futex(<uaddr> nullptr";
                } else {
                    debug_stream << " = futex(<uaddr> " << *host_uaddr;
                }
                debug_stream << ", <futex_op> " << futex_op
                             << ", <val> " << val
                             << ", <val2> " << val2
                             << ", <uaddr2> " << uaddr2
                             << ", <val3> " << val3
                             << ");" << std::endl;
            }

            return ret;
        }

        XLenT sys_sched_yield() {
            XLenT ret = 0;

            // todo: real yield for multi-thread

            if (debug) { debug_stream << "system call: " << ret << " = sched_yield();" << std::endl; }

            return ret;
        }

        XLenT sys_uname(UXLenT buf) {
            (void) buf;

            struct ::utsname host_buf{};
            utsname guest_buf{};

            XLenT ret = uname(&host_buf);

            if (ret == 0) {
                memcpy(guest_buf.sysname, "Linux",
                       std::min(sizeof(guest_buf.sysname), sizeof("Linux")));
                memcpy(guest_buf.nodename, host_buf.nodename,
                       std::min(sizeof(guest_buf.nodename), sizeof(host_buf.nodename)));
                memcpy(guest_buf.release, host_buf.release,
                       std::min(sizeof(guest_buf.release), sizeof(host_buf.release)));
                memcpy(guest_buf.version, host_buf.version,
                       std::min(sizeof(guest_buf.version), sizeof(host_buf.version)));
                memcpy(guest_buf.machine, "riscv32",
                       std::min(sizeof(guest_buf.machine), sizeof("riscv32")));

                if (pcb.memory_copy_to_guest(buf, &guest_buf, sizeof(guest_buf)) != sizeof(guest_buf)) {
                    ret = -EFAULT;
                }
            } else {
                ret = -errno;
            }

            if (debug) {
                debug_stream << "system call: " << ret
                             << " = uname(<buf> struct utsname{<sysname> \"" << guest_buf.sysname
                             << "\", <nodename> \"" << guest_buf.nodename
                             << "\", <release> \"" << guest_buf.release
                             << "\", <version> \"" << guest_buf.version
                             << "\", <machine> \"" << guest_buf.machine
                             << "\"})" << std::endl;
            }

            return ret;
        }

        XLenT sys_brk(UXLenT addr) {
            XLenT ret = pcb.set_brk(addr);

            if (debug) {
                debug_stream << "system call: " << ret
                             << " = brk(<addr> " << addr
                             << ");" << std::endl;
            }

            return ret;
        }

        XLenT sys_getpid() {
            XLenT ret = getpid();

            if (debug) { debug_stream << "system call: " << ret << " = getpid();" << std::endl; }

            return ret;
        }

        XLenT sys_getppid() {
            XLenT ret = getppid();

            if (debug) { debug_stream << "system call: " << ret << " = getppid();" << std::endl; }

            return ret;
        }

        XLenT sys_getuid() {
            XLenT ret = getuid();

            if (debug) { debug_stream << "system call: " << ret << " = getuid();" << std::endl; }

            return ret;
        }

        XLenT sys_geteuid() {
            XLenT ret = geteuid();

            if (debug) { debug_stream << "system call: " << ret << " = geteuid();" << std::endl; }

            return ret;
        }

        XLenT sys_getgid() {
            XLenT ret = getgid();

            if (debug) { debug_stream << "system call: " << ret << " = getgid();" << std::endl; }

            return ret;
        }

        XLenT sys_getegid() {
            XLenT ret = getegid();

            if (debug) { debug_stream << "system call: " << ret << " = getegid();" << std::endl; }

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
            XLenT ret;
            bool fix = false;
            void *map = MAP_FAILED;

            auto pair = prot_convert(prot);
            auto guest_prot = pair.first;
            auto host_prot = pair.second;

            UXLenT guest_addr = addr / RISCV_PAGE_SIZE * RISCV_PAGE_SIZE;
            UXLenT guest_length = divide_ceil(length, RISCV_PAGE_SIZE) * RISCV_PAGE_SIZE;
            int host_flags = flags;

            if ((flags & MAP_FIXED) > 0) {
                if (addr != guest_addr) {
                    ret = -EINVAL;
                    goto end;
                }

                fix = true;
                host_flags &= (~MAP_FIXED);
            } // todo: replace

            if ((flags & NEUTRON_MAP_FIXED_NOREPLACE) > 0) { neutron_abort("MAP_FIXED_NOREPLACE not support!"); }

            if ((flags & NEUTRON_MAP_GROWSDOWN) > 0) { neutron_abort("MAP_GROWSDOWN not support!"); }

            if ((flags & NEUTRON_MAP_HUGETLB) > 0) { neutron_abort("MAP_HUGETLB not support!"); }

            if ((flags & NEUTRON_MAP_STACK) > 0) { neutron_abort("MAP_STACK not support!"); }

            map = mmap(nullptr, length, host_prot, host_flags, get_host_fd(fd), offset << 12);

            if (map != MAP_FAILED) {
                if (fix) {
                    ret = pcb.add_map_fix(guest_addr, map, guest_length, guest_prot);
                } else {
                    ret = pcb.add_map(guest_addr, map, guest_length, guest_prot);
                }

                if (ret == 0) {
                    munmap(map, length);
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
//                pcb.dump_map(debug_stream);
            }

            return ret;
        }

        XLenT sys_mprotect(UXLenT addr, UXLenT len, XLenT prot) {
            XLenT ret;

            if (addr % RISCV_PAGE_SIZE != 0) {
                ret = -EINVAL;
            } else {
                auto pair = prot_convert(prot);

                ret = pcb.set_protection(addr, len, pair.first, pair.second);
            }

            if (debug) {
                debug_stream << "system call: " << ret
                             << " = mprotect(<addr> " << addr
                             << ", <len> " << len
                             << ", <prot> " << prot
                             << ");" << std::endl;
//                pcb.dump_map(debug_stream);
            }

            return ret;
        }

        XLenT sys_prlimit64(XLenT pid, XLenT resource, UXLenT new_limit, UXLenT old_limit) {
            XLenT ret = -1;

            struct rlimit host_old_limit{};

            if (new_limit == 0) {
                ret = prlimit(pid, (__rlimit_resource) resource,
                              nullptr, &host_old_limit);

            } else {
                struct rlimit host_new_limit{};

                if (pcb.memory_copy_from_guest(&host_new_limit, new_limit,
                                               sizeof(host_new_limit)) != sizeof(host_new_limit)) {
                    ret = -EFAULT;
                } else {
                    ret = prlimit(pid, (__rlimit_resource) resource,
                                  &host_new_limit, &host_old_limit);
                }
            }

            if (ret != 0) {
                ret = -errno;
            } else {
                if (pcb.memory_copy_to_guest(old_limit, &host_old_limit,
                                             sizeof(host_old_limit)) != sizeof(host_old_limit)) {
                    ret = -EFAULT;
                }
            }

            if (debug) {
                debug_stream << "system call: " << ret
                             << " = prlimit64(<pid> " << pid
                             << ", <resource> " << resource
                             << ", <new_limit> " << new_limit
                             << ", <old_limit> " << old_limit
                             << ");" << std::endl;
//                pcb.dump_map(debug_stream);
            }

            return ret;
        }

        XLenT sys_statx(int dirfd, UXLenT pathname, XLenT flags, UXLenT mask, UXLenT statxbuf) {
            XLenT ret;
            std::string name{};

#if defined(__linux__)
            struct ::statx host_buf{};
#elif defined(__APPLE__)
            struct ::stat host_buf{};
#endif

            statx guest_buf{};

            if (pcb.string_copy_from_guest(pathname, name)) {
                auto real_name = file_name_resolve(name);

#if defined(__linux__)
                ret = ::statx(get_host_fd(dirfd), real_name.c_str(), flags, mask, &host_buf);
#elif defined(__APPLE__)
                if (name.size() == 0) {
                    if ((flags & NEUTRON_AT_EMPTY_PATH) > 0) {
                        ret = fstat(dirfd, &host_buf);
                    } else {
                        ret = fstat(dirfd, &host_buf);
                    }
                } else if (name[0] == '/') {
                    ret = stat(real_name.c_str(), &host_buf);
                } else if (dirfd == AT_FDCWD) {
                    ret = fstatat(AT_FDCWD, real_name.c_str(), &host_buf, 0);
                } else {
                    ret = fstatat(get_host_fd(dirfd), real_name.c_str(), &host_buf, 0);
                }
#endif

                if (ret == 0) {
#if defined(__linux__)
                    guest_buf.stx_mask = host_buf.stx_mask;
                    guest_buf.stx_blksize = host_buf.stx_blksize;
                    guest_buf.stx_attributes = host_buf.stx_attributes;
                    guest_buf.stx_nlink = host_buf.stx_nlink;
                    guest_buf.stx_uid = host_buf.stx_uid;
                    guest_buf.stx_gid = host_buf.stx_gid;
                    guest_buf.stx_mode = host_buf.stx_mode;
                    guest_buf.stx_ino = host_buf.stx_ino;
                    guest_buf.stx_size = host_buf.stx_size;
                    guest_buf.stx_blocks = host_buf.stx_blocks;
                    guest_buf.stx_attributes_mask = host_buf.stx_attributes_mask;
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
#elif defined(__APPLE__)
//                    guest_buf.stx_mask = host_buf.stx_mask;
                    guest_buf.stx_blksize = host_buf.st_blksize;
//                    guest_buf.stx_attributes = host_buf.stx_attributes;
                    guest_buf.stx_nlink = host_buf.st_nlink;
                    guest_buf.stx_uid = host_buf.st_uid;
                    guest_buf.stx_gid = host_buf.st_gid;
                    guest_buf.stx_mode = host_buf.st_mode;
                    guest_buf.stx_ino = host_buf.st_ino;
                    guest_buf.stx_size = host_buf.st_size;
                    guest_buf.stx_blocks = host_buf.st_blocks;
//                    guest_buf.stx_attributes_mask = host_buf.stx_attributes_mask;
                    guest_buf.stx_atime.tv_sec = host_buf.st_atimespec.tv_sec;
                    guest_buf.stx_atime.tv_nsec = host_buf.st_atimespec.tv_nsec;
//                    guest_buf.stx_btime.tv_sec = host_buf.st_btime.tv_sec;
//                    guest_buf.stx_btime.tv_nsec = host_buf.st_btime.tv_nsec;
                    guest_buf.stx_ctime.tv_sec = host_buf.st_ctimespec.tv_sec;
                    guest_buf.stx_ctime.tv_nsec = host_buf.st_ctimespec.tv_nsec;
                    guest_buf.stx_mtime.tv_sec = host_buf.st_mtimespec.tv_sec;
                    guest_buf.stx_mtime.tv_nsec = host_buf.st_mtimespec.tv_nsec;
//                    guest_buf.stx_rdev_major = host_buf.st_rdev_major;
//                    guest_buf.stx_rdev_minor = host_buf.st_rdev_minor;
//                    guest_buf.stx_dev_major = host_buf.st_dev_major;
//                    guest_buf.stx_dev_minor = host_buf.st_dev_minor;
#endif

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
                             << ", <pathname> \"" << name
                             << "\", <flags> " << flags
                             << ", <mask> " << mask
                             << ", <statxbuf> "
                             << ");" << std::endl;
            }

            return ret;
        }

        bool u_mode_environment_call_handler() {
            this->inc_pc(riscv_isa::ECALLInst::INST_WIDTH);

            switch (this->get_x(IntRegT::A7)) {
#define make_syscall(num, name) \
                case syscall::name: \
                    neutron_syscall(num, sub_type()->sys_##name); \
                    return true

                make_syscall(2, getcwd);
                make_syscall(3, fcntl);
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
                case syscall::exit_group: // todo
                    std::cout << std::endl << "[exit " << this->get_x(IntRegT::A0) << ']'
                              << std::endl;

                    return false;
                make_syscall(6, futex);
                make_syscall(0, sched_yield);
                make_syscall(1, uname);
                make_syscall(1, brk);
                make_syscall(0, getpid);
                make_syscall(0, getppid);
                make_syscall(0, getuid);
                make_syscall(0, geteuid);
                make_syscall(0, getgid);
                make_syscall(0, getegid);
                make_syscall(1, sysinfo);
                make_syscall(6, mmap);
                make_syscall(3, mprotect);
                make_syscall(4, prlimit64);
                make_syscall(5, statx);
                default:
                    std::cerr << "Invalid environment call number at " << std::hex << this->get_pc()
                              << ", call number " << std::dec << this->get_x(IntRegT::A7)
                              << std::endl;

                    return false;
#undef make_syscall
            }
        }

        bool break_point_handler(neutron_unused UXLenT addr) {
            this->inc_pc(riscv_isa::ECALLInst::INST_WIDTH);
            return true;
        }

        void start() { while (sub_type()->visit() || sub_type()->trap_handler()) {}}
    };
}


#endif //NEUTRON_RISCV_LINUX_HPP
