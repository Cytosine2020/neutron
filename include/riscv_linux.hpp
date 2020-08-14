#ifndef NEUTRON_RISCV_LINUX_HPP
#define NEUTRON_RISCV_LINUX_HPP


#include <cerrno>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <sys/sysinfo.h>
#include <sys/utsname.h>
#include <sys/syscall.h>
#include <sys/times.h>
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

        LinuxHart(UXLenT hart_id, LinuxProgram<xlen> &mem,
                  bool debug = false, std::ostream &debug_stream = std::cerr) :
                riscv_isa::Hart<SubT>{hart_id, mem.pc, mem.int_reg}, pcb{mem},
                riscv_sysroot{getenv("RISCV_SYSROOT")}, debug_stream{debug_stream}, debug{debug} {
            this->cur_level = riscv_isa::USER_MODE;

            pcb.debug = debug;

            pcb.fd_map.emplace(0, dup(0));
            pcb.fd_map.emplace(1, dup(1));
            pcb.fd_map.emplace(2, dup(2));
        }

        template<typename ValT>
        RetT mmu_load_int_reg(usize dest, UXLenT addr) {
            static_assert(sizeof(ValT) <= sizeof(UXLenT), "load width exceed bit width!");

            if ((addr & (sizeof(ValT) - 1)) != 0)
                return sub_type()->internal_interrupt(riscv_isa::trap::LOAD_ACCESS_FAULT, addr);

            const ValT *ptr = pcb.template address<ValT>(addr, riscv_isa::READ);
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

            ValT *ptr = pcb.template address<ValT>(addr, riscv_isa::READ_WRITE);
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

            const u16 *ptr = pcb.template address<u16>(addr + offset * sizeof(u16), riscv_isa::EXECUTE);
            if (ptr == nullptr) {
                return sub_type()->internal_interrupt(riscv_isa::trap::INSTRUCTION_PAGE_FAULT, addr);
            } else {
                memcpy(reinterpret_cast<u16 *>(&this->inst_buffer) + offset, ptr, 2);
                return true;
            }
        }

#if defined(__RV_EXTENSION_A__)

        template<typename ValT>
        RetT mmu_store_xlen(XLenT val, XLenT addr) {
            static_assert(sizeof(ValT) <= sizeof(UXLenT), "store width exceed bit width!");

            if ((addr & (sizeof(ValT) - 1)) != 0)
                return sub_type()->internal_interrupt(riscv_isa::trap::STORE_AMO_ACCESS_FAULT, addr);

            ValT *ptr = pcb.template address<ValT>(addr, riscv_isa::READ_WRITE);
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

        RetT visit_inst(riscv_isa::Instruction *inst) { return sub_type()->illegal_instruction(inst); }

        RetT visit_fence_inst(neutron_unused riscv_isa::FENCEInst *inst) {
            this->inc_pc(riscv_isa::FENCEInst::INST_WIDTH);
            return true; // todo
        }

        int get_host_fd(int fd) {
            if (fd < 0) return fd;

            auto ptr = pcb.fd_map.find(fd);

            if (ptr != pcb.fd_map.end()) {
                return ptr->second;
            } else {
                return -1;
            }
        }

        int get_guest_fd(int fd) {
            if (fd < 0) return fd;

            auto ptr = pcb.fd_map.rbegin();

            int ret;

            if (ptr != pcb.fd_map.rend()) {
                ret = ptr->first + 1;
            } else {
                ret = 0;
            }

            pcb.fd_map.emplace(ret, fd);

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

        XLenT sys_getcwd(UXLenT buf, UXLenT size) {
            Array<char> host_buf{size};

            XLenT ret = buf;

            const char *result = getcwd(host_buf.begin(), size);

            if (result != nullptr) {
                usize len = strlen(host_buf.begin());

                if (strncmp(result, riscv_sysroot.data(), riscv_sysroot.size()) == 0) {
                    result += riscv_sysroot.size();
                }

                if (*result == '\0') { result = "/"; }

                usize byte = pcb.memory_copy_to_guest(buf, result, host_buf.end() - result);
                if (byte != len) {
                    ret = -EFAULT;
                }
            } else {
                ret = -errno;
            }

            if (debug) {
                debug_stream << "system call: " << ret
                             << " = getcwd(<buf> \"" << result
                             << "\", <size> " << size
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
                             << " = fcntl(<fd> " << fd
                             << ", <cmd> " << cmd
                             << ", <arg> " << arg
                             << ");" << std::endl;
            }

            return ret;
        }

        XLenT sys_ioctl(int fd, UXLenT request, UXLenT argp) {
            UXLenT size = _IOC_SIZEMASK & (request >> _IOC_SIZESHIFT);
            XLenT ret;

            Array<u8> buf{size};

            if (pcb.memory_copy_from_guest(buf.begin(), argp, size) == size) {
                ret = ioctl(get_host_fd(fd), request, argp);
                if (ret == -1) { ret = -errno; }
            } else {
                ret = -EFAULT;
            }

            if (debug) {
                debug_stream << "system call: " << ret
                             << " = ioctl(<fd> " << fd
                             << ", <request> " << request
                             << ", <argp> " << argp
                             << ");" << std::endl;
            }

            return ret;
        }

        XLenT sys_faccessat(int dirfd, UXLenT pathname, XLenT mode) {
            XLenT ret;
            Array<char> name{};

            if (pcb.string_copy_from_guest(pathname, name)) {
                auto real_name = file_name_resolve(name.begin());

                ret = faccessat(get_host_fd(dirfd), real_name.c_str(), mode, 0);
                if (ret == -1) { ret = -errno; }
            } else {
                ret = -EFAULT;
            }

            if (debug) {
                debug_stream << "system call: " << ret
                             << " = faccessat(<dirfd> " << dirfd
                             << ", <pathname> \"" << name.begin()
                             << "\", <mode> " << mode
                             << ");" << std::endl;
            }

            return ret;
        }

        XLenT sys_openat(int dirfd, UXLenT pathname, XLenT flags, XLenT mode) {
            XLenT ret;
            Array<char> name{};

            if (pcb.string_copy_from_guest(pathname, name)) {
                auto real_name = file_name_resolve(name.begin());

                ret = openat(get_host_fd(dirfd), real_name.c_str(), flags, mode);
                if (ret == -1) { ret = -errno; }
                else { ret = get_guest_fd(ret); }
            } else {
                ret = -EFAULT;
            }

            if (debug) {
                debug_stream << "system call: " << ret
                             << " = openat(<dirfd> " << dirfd
                             << ", <pathname> \"" << name.begin()
                             << "\", <flags> " << flags
                             << ", <mode> " << mode
                             << ");" << std::endl;
            }

            return ret;
        }

        XLenT sys_close(int fd) {
            XLenT ret = close(get_host_fd(fd));

            if (ret != 0) { ret = -errno; }

            pcb.fd_map.erase(fd);

            if (debug) {
                debug_stream << "system call: " << ret
                             << " = close(<fd> " << fd
                             << ");" << std::endl;
            }

            return ret;
        }

        XLenT sys_pipe2(UXLenT pipefd, XLenT flags) {
            XLenT ret;

            int host_pipefd[2]{-1, -1};

            ret = pipe2(host_pipefd, flags);

            if (ret == -1) {
                ret = -errno;
            } else {
                host_pipefd[0] = get_guest_fd(host_pipefd[0]);
                host_pipefd[1] = get_guest_fd(host_pipefd[1]);

                if (pcb.memory_copy_to_guest(pipefd, &host_pipefd, sizeof(host_pipefd)) != sizeof(host_pipefd)) {
                    ret = -EFAULT;
                }
            }

            if (debug) {
                debug_stream << "system call: " << ret
                             << " = close(<pipefd> [" << host_pipefd[0] << ", " << host_pipefd[1]
                             << ", <flags>" << flags
                             << ");" << std::endl;
            }

            return ret;
        }

        // todo: this is different from 32 and 64
        XLenT sys_lseek(int fd, UXLenT offset_hi, UXLenT offset_lo, UXLenT result, XLenT whence) {
            i64 offset = (static_cast<u64>(offset_hi) << 32u) + offset_lo;

            i64 ret = lseek(get_host_fd(fd), offset, whence);

            XLenT guest_ret;

            if (ret == -1) {
                ret = -errno;
                guest_ret = -errno;
            } else {
                if (pcb.memory_copy_to_guest(result, &ret, sizeof(ret)) != sizeof(ret)) {
                    ret = -errno;
                    guest_ret = -EFAULT;
                } else {
                    guest_ret = 0;
                }
            }

            if (debug) {
                debug_stream << "system call: " << ret
                             << " = lseek(<fd> " << fd
                             << ", <offset> " << offset
                             << ", <whence> " << whence
                             << ");" << std::endl;
            }

            return guest_ret;
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

        XLenT sys_readlinkat(int dirfd, UXLenT pathname, UXLenT buf, UXLenT bufsiz) {
            XLenT ret;
            Array<char> name{};

            if (pcb.string_copy_from_guest(pathname, name)) {
                Array<char> host_buf{bufsiz};
                auto real_name = file_name_resolve(name.begin());

                ret = readlinkat(get_host_fd(dirfd), real_name.data(), host_buf.begin(), bufsiz);

                if (ret == -1) {
                    ret = -errno;
                } else {
                    if (pcb.memory_copy_to_guest(buf, host_buf.begin(), bufsiz) != bufsiz) {
                        ret = -EFAULT;
                    }
                }
            } else {
                ret = -EFAULT;
            }

            if (debug) {
                debug_stream << "system call: " << ret
                             << " = readlinkat(<dirfd> " << dirfd
                             << ", <pathname> " << name.begin()
                             << ", <buf> " << buf
                             << ", <bufsiz> " << bufsiz
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
                             << " = fstat(<fd> " << fd
                             << ", <addr> "
                             << ");" << std::endl;
            }

            return ret;
        }

        RetT sys_exit(XLenT status) {
            pcb.exit_value = status;
            return false;
        }

        RetT sys_exit_group(XLenT status) {
            pcb.exit_value = status; // todo: exit group
            return false;
        }

        XLenT sys_futex(UXLenT uaddr, XLenT futex_op, XLenT val,
                        UXLenT val2, UXLenT uaddr2, XLenT val3) {
            (void) val2;
            (void) uaddr2;
            (void) val3;

            XLenT ret = 0;

            // todo: not implement

            i32 *host_uaddr = pcb.template address<i32>(uaddr, riscv_isa::READ_WRITE);

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

        XLenT sys_times(UXLenT buf) {
            XLenT ret;

            struct ::tms host_buf{};
            tms guest_buf{};

            ret = times(&host_buf);

            if (ret != -1) {
                guest_buf.utime = host_buf.tms_utime;
                guest_buf.stime = host_buf.tms_stime;
                guest_buf.cutime = host_buf.tms_cutime;
                guest_buf.cstime = host_buf.tms_cstime;

                if (pcb.memory_copy_to_guest(buf, &guest_buf, sizeof(guest_buf)) != sizeof(guest_buf)) {
                    ret = -EFAULT;
                }
            } else {
                ret = -errno;
            }

            if (debug) {
                debug_stream << "system call: "
                             << " = times(" << buf
                             << ");" << std::endl;
            }

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
            XLenT ret;

            struct ::sysinfo host_info{};
            sysinfo guest_info{};

            ret = ::sysinfo(&host_info);

            if (ret == -1) {
                ret = -errno;
            } else {
                guest_info.uptime = host_info.uptime;
                guest_info.loads[0] = host_info.loads[0];
                guest_info.loads[1] = host_info.loads[1];
                guest_info.loads[2] = host_info.loads[2];
                guest_info.totalram = host_info.totalram;
                guest_info.freeram = host_info.freeram;
                guest_info.sharedram = host_info.sharedram;
                guest_info.bufferram = host_info.bufferram;
                guest_info.totalswap = host_info.totalswap;
                guest_info.freeswap = host_info.freeswap;
                guest_info.procs = host_info.procs;
                guest_info.totalhigh = host_info.totalhigh;
                guest_info.freehigh = host_info.freehigh;
                guest_info.mem_unit = host_info.mem_unit;

                if (pcb.memory_copy_to_guest(info, &guest_info, sizeof(guest_info)) != sizeof(guest_info)) {
                    ret = -EFAULT;
                }
            }

            if (debug) {
                debug_stream << "system call: "
                             << " = sysinfo(" << info
                             << ");" << std::endl;
            }

            return ret;
        }

        XLenT sys_brk(UXLenT addr) {
            XLenT ret = pcb.set_break(addr);

            if (debug) {
                debug_stream << "system call: " << ret
                             << " = brk(<addr> " << addr
                             << ");" << std::endl;
            }

            return ret;
        }

        XLenT sys_munmap(UXLenT addr, XLenT length) {
            XLenT ret = pcb.memory_unmap(addr, length);

            if (debug) {
                debug_stream << "system call: " << ret
                             << " = brk(<addr> " << addr
                             << " = brk(<length> " << length
                             << ");" << std::endl;
            }

            return ret;
        }

        XLenT sys_mmap(UXLenT addr, UXLenT length, XLenT prot, XLenT flags, XLenT fd, UXLenT offset) {
            XLenT ret = pcb.memory_map(addr, length, prot, flags, get_host_fd(fd), offset);

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
            XLenT ret = pcb.memory_protection(addr, len, prot);

            if (debug) {
                debug_stream << "system call: " << ret
                             << " = mprotect(<addr> " << addr
                             << ", <len> " << len
                             << ", <prot> " << prot
                             << ");" << std::endl;
            }

            return ret;
        }

        XLenT sys_prlimit64(XLenT pid, XLenT resource, UXLenT new_limit, UXLenT old_limit) {
            XLenT ret;

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
            }

            return ret;
        }

        XLenT sys_statx(int dirfd, UXLenT pathname, XLenT flags, UXLenT mask, UXLenT statxbuf) {
            XLenT ret;
            Array<char> name{};

#if defined(__linux__)
            struct ::statx host_buf{};
#elif defined(__APPLE__)
            struct ::stat host_buf{};
#endif

            statx guest_buf{};

            if (pcb.string_copy_from_guest(pathname, name)) {
                auto real_name = file_name_resolve(name.begin());

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
                             << ", <pathname> \"" << name.begin()
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
                make_syscall(3, ioctl);
                make_syscall(3, faccessat);
                make_syscall(4, openat);
                make_syscall(1, close);
                make_syscall(2, pipe2);
                make_syscall(5, lseek);
                make_syscall(3, read);
                make_syscall(3, write);
                make_syscall(3, readv);
                make_syscall(3, writev);
                make_syscall(4, readlinkat);
                make_syscall(2, fstat);
                case syscall::exit:
                    return sub_type()->sys_exit(this->get_x(IntRegT::A0));
                case syscall::exit_group:
                    return sub_type()->sys_exit_group(this->get_x(IntRegT::A0));
                make_syscall(6, futex);
                make_syscall(0, sched_yield);
                make_syscall(1, times);
                make_syscall(1, uname);
                make_syscall(0, getpid);
                make_syscall(0, getppid);
                make_syscall(0, getuid);
                make_syscall(0, geteuid);
                make_syscall(0, getgid);
                make_syscall(0, getegid);
                make_syscall(1, sysinfo);
                make_syscall(1, brk);
                make_syscall(2, munmap);
                make_syscall(6, mmap);
                make_syscall(3, mprotect);
                make_syscall(4, prlimit64);
                make_syscall(5, statx);
                default:
                    this->set_x(IntRegT::A0, -EPERM);
                    std::cerr << "Invalid environment call number at " << std::hex << this->get_pc()
                              << ", call number " << std::dec << this->get_x(IntRegT::A7)
                              << std::endl;

                    return true;
#undef make_syscall
            }
        }

        bool goto_main(UXLenT addr) {
            bool old_debug = debug;
            debug = false;

            while (static_cast<UXLenT>(this->get_pc()) != addr) {
                if (!sub_type()->visit() && !sub_type()->trap_handler()) return false;
            }

            debug = old_debug;

            return true;
        }

        void start() { while (sub_type()->visit() || sub_type()->trap_handler()) {}}
    };
}


#endif //NEUTRON_RISCV_LINUX_HPP
