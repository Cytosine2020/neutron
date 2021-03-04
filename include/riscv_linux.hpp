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
#include <sys/utsname.h>
#include <sys/syscall.h>
#include <sys/times.h>
#include <sys/resource.h>

#if defined(__linux__)
#include <sys/sysinfo.h>
#include <linux/futex.h>
#endif

#include <iostream>
#include <map>

#include "target/hart.hpp"
#include "target/dump.hpp"

#include "neutron_utility.hpp"
#include "riscv_linux_program.hpp"
#include "linux_std.hpp"


namespace neutron {
template<typename ...Args>
struct _LinuxHartDebug;

template<typename Arg, typename ...Args>
struct _LinuxHartDebug<const char *, Arg, Args...> {
    static void inner(std::ostream &stream, const char *name, Arg arg, Args...args) {
        _LinuxHartDebug<const char *, Arg>::inner(stream, name, arg);
        stream << ", ";
        _LinuxHartDebug<Args...>::inner(stream, args...);
    }
};

template<typename Arg>
struct _LinuxHartDebug<const char *, Arg> {
    static void inner(std::ostream &stream, const char *name, Arg arg) {
        stream << '<' << name << "> " << arg;
    }
};

template<>
struct _LinuxHartDebug<const char *, const char *> {
    static void inner(std::ostream &stream, const char *name, const char *arg) {
        stream << '<' << name << "> ";
        if (arg == nullptr) {
            stream << "nullptr";
        } else {
            stream << '\"' << arg << '\"';
        }
    }
};

template<>
struct _LinuxHartDebug<const char *, char *> {
    static void inner(std::ostream &stream, const char *name, char *arg) {
        _LinuxHartDebug<const char *, const char *>::inner(stream, name, arg);
    }
};

template<>
struct _LinuxHartDebug<> {
    static void inner(neutron_unused std::ostream &stream) {}
};

template<typename SubT, typename xlen>
class LinuxHart_ : public riscv_isa::Hart<SubT, xlen> {
public:
    using SuperT = riscv_isa::Hart<SubT, xlen>;

    using RetT = typename SuperT::RetT;
    using XLenT = typename SuperT::XLenT;
    using UXLenT = typename SuperT::UXLenT;
    using IntRegT = typename SuperT::IntRegT;
    using CSRRegT = typename SuperT::CSRRegT;

private:
    SubT *sub_type() { return static_cast<SubT *>(this); }

    SuperT *super() { return this; }

protected:
    LinuxProgram<xlen> &pcb;
    typename LinuxProgram<xlen>::MemoryArea execute_cache;
    typename LinuxProgram<xlen>::MemoryArea load_cache;
    typename LinuxProgram<xlen>::MemoryArea store_cache;
    std::ostream &debug_stream;
    bool debug;

public:
    LinuxHart_(UXLenT hart_id, LinuxProgram<xlen> &mem,
               bool debug = false, std::ostream &debug_stream = std::cerr) :
            SuperT{hart_id, mem.pc, mem.int_reg}, pcb{mem}, execute_cache{0, 0, nullptr},
            load_cache{0, 0, nullptr}, store_cache{0, 0, nullptr},
            debug_stream{debug_stream}, debug{debug} {
        this->cur_level = riscv_isa::PrivilegeLevel::USER_MODE;
    }

    void invalid_cache() {
        execute_cache = typename LinuxProgram<xlen>::MemoryArea{0, 0, nullptr};
        load_cache = typename LinuxProgram<xlen>::MemoryArea{0, 0, nullptr};
        store_cache = typename LinuxProgram<xlen>::MemoryArea{0, 0, nullptr};
    }

    template<typename ValT>
    const ValT *address_load(UXLenT addr) {
        if (load_cache.start <= addr && addr + sizeof(ValT) <= load_cache.end) {
            return reinterpret_cast<ValT *>(load_cache.shift + addr);
        } else {
            auto area = pcb.get_memory_area(addr, riscv_isa::MemoryProtection::READ);
            if (area.start == 0) {
                return nullptr;
            } else {
                load_cache = area;
                return reinterpret_cast<ValT *>(area.shift + addr);
            }
        }
    }

    template<typename ValT>
    ValT *address_store(UXLenT addr) {
        if (store_cache.start <= addr && addr + sizeof(ValT) <= store_cache.end) {
            return reinterpret_cast<ValT *>(store_cache.shift + addr);
        } else {
            auto area = pcb.get_memory_area(addr, riscv_isa::MemoryProtection::READ_WRITE);
            if (area.start == 0) {
                return nullptr;
            } else {
                store_cache = area;
                return reinterpret_cast<ValT *>(area.shift + addr);
            }
        }
    }

    template<typename ValT>
    const ValT *address_execute(UXLenT addr) {
        if (execute_cache.start <= addr && addr + sizeof(ValT) <= execute_cache.end) {
            return reinterpret_cast<ValT *>(execute_cache.shift + addr);
        } else {
            auto area = pcb.get_memory_area(addr, riscv_isa::MemoryProtection::EXECUTE);
            if (area.start == 0) {
                return nullptr;
            } else {
                execute_cache = area;
                return reinterpret_cast<ValT *>(area.shift + addr);
            }
        }
    }

#if defined(__RV_EXTENSION_ZICSR__)

    RetT get_csr_reg(UXLenT index) { return this->csr_reg[index]; }

    RetT set_csr_reg(neutron_unused UXLenT index, neutron_unused UXLenT val) { return true; }

#endif // defined(__RV_EXTENSION_ZICSR__)

    RetT visit_inst(const riscv_isa::Instruction *inst) {
        return sub_type()->illegal_instruction(inst);
    }

    RetT visit_fence_inst(neutron_unused const riscv_isa::FENCEInst *inst) {
        sub_type()->inc_pc(riscv_isa::FENCEInst::INST_WIDTH);
        return true; // todo
    }

    std::string get_host_file_name(const char *name) { return pcb.get_host_file_name(name); }

    /// dir_fd: guest fd
    std::string get_host_file_name(int dir_fd, const char *name) {
        return pcb.get_host_file_name(sub_type()->get_host_fd(dir_fd), name);
    }

    std::string get_guest_file_name(const char *name) { return pcb.get_guest_file_name(name); }

    int get_host_fd(int fd) { return pcb.get_host_fd(fd); }

    int get_guest_fd(int fd) { return pcb.get_guest_fd(fd); }

    template<typename ...Args>
    void syscall_debug(XLenT ret, const char *name, Args ...args) {
        if (debug) {
            debug_stream << "system call: " << ret << " = " << name << '(';
            _LinuxHartDebug<Args...>::inner(debug_stream, args...);
            debug_stream << ");" << std::endl;
        }
    }

    XLenT sys_getcwd(UXLenT buf, UXLenT size) {
        Array<char> host_buf{size};

        XLenT ret = buf;

        const char *result = getcwd(host_buf.begin(), size);

        if (result != nullptr) {
            std::string real_name = sub_type()->get_guest_file_name(result);

            if (!pcb.memory_copy_to_guest(buf, real_name.data(), real_name.size() + 1)) {
                ret = -EFAULT;
            }
        } else {
            ret = -errno;
        }

        syscall_debug(ret, "getcwd", "buf", result, "size", size);

        return ret;
    }

    XLenT sys_fcntl(int fd, XLenT cmd, XLenT arg) {
        XLenT ret;

        switch (cmd) {
            case NEUTRON_F_SETLK:
            case NEUTRON_F_SETLKW:
            case NEUTRON_F_OFD_SETLK:
            case NEUTRON_F_OFD_SETLKW: {
                struct ::flock host_buf{};
                flock guest_buf{};

                if (pcb.memory_copy_from_guest(&guest_buf, arg, sizeof(guest_buf))) {
                    host_buf.l_type = guest_buf.type;
                    host_buf.l_whence = guest_buf.whence;
                    host_buf.l_start = guest_buf.start;
                    host_buf.l_len = guest_buf.len;
                    host_buf.l_pid = guest_buf.pid;

                    ret = fcntl(sub_type()->get_host_fd(fd), cmd, &host_buf);

                    if (ret == -1) {
                        ret = -errno;
                    }
                } else {
                    ret = -EFAULT;
                }
            }
                break;
            case NEUTRON_F_GETLK:
            case NEUTRON_F_OFD_GETLK: {
                struct ::flock host_buf{};
                flock guest_buf{};

                if (pcb.memory_copy_from_guest(&guest_buf, arg, sizeof(guest_buf))) {
                    host_buf.l_type = guest_buf.type;
                    host_buf.l_whence = guest_buf.whence;
                    host_buf.l_start = guest_buf.start;
                    host_buf.l_len = guest_buf.len;
                    host_buf.l_pid = guest_buf.pid;

                    ret = fcntl(sub_type()->get_host_fd(fd), cmd, &host_buf);

                    if (ret == -1) {
                        ret = -errno;
                    } else {
                        guest_buf.type = host_buf.l_type;
                        guest_buf.whence = host_buf.l_whence;
                        guest_buf.start = host_buf.l_start;
                        guest_buf.len = host_buf.l_len;
                        guest_buf.pid = host_buf.l_pid;

                        if (!pcb.memory_copy_to_guest(arg, &guest_buf, sizeof(guest_buf))) {
                            ret = -EFAULT; // this should never happen.
                        }
                    }
                } else {
                    ret = -EFAULT;
                }
            }
                break;
            case NEUTRON_F_SETLK64:
//                case NEUTRON_F_SETLKW64: {
//                    struct ::flock64 host_buf{};
//                    flock64 guest_buf{};
//
//                    if (pcb.memory_copy_from_guest(&guest_buf, arg, sizeof(guest_buf))) {
//                        host_buf.type = guest_buf.type;
//                        host_buf.whence = guest_buf.whence;
//                        host_buf.start = guest_buf.start;
//                        host_buf.len = guest_buf.len;
//                        host_buf.pid = guest_buf.pid;
//
//                        ret = fcntl(sub_type()->get_host_fd(fd), cmd, &host_buf);
//
//                        if (ret == -1) {
//                            ret = -errno;
//                        }
//                    } else {
//                        ret = -EFAULT;
//                    }
//                }
//                    break;
//                case NEUTRON_F_GETLK64: {
//                    struct ::flock64 host_buf{};
//                    flock64 guest_buf{};
//
//                    if (pcb.memory_copy_from_guest(&guest_buf, arg, sizeof(guest_buf))) {
//                        host_buf.type = guest_buf.type;
//                        host_buf.whence = guest_buf.whence;
//                        host_buf.start = guest_buf.start;
//                        host_buf.len = guest_buf.len;
//                        host_buf.pid = guest_buf.pid;
//
//                        ret = fcntl(sub_type()->get_host_fd(fd), cmd, &host_buf);
//
//                        if (ret == -1) {
//                            ret = -errno;
//                        } else {
//                            guest_buf.type = host_buf.type;
//                            guest_buf.whence = host_buf.whence;
//                            guest_buf.start = host_buf.start;
//                            guest_buf.len = host_buf.len;
//                            guest_buf.pid = host_buf.pid;
//
//                            if (!pcb.memory_copy_to_guest(arg, &guest_buf, sizeof(guest_buf))) {
//                                ret = -EFAULT; // this should never happen.
//                            }
//                        }
//                    } else {
//                        ret = -EFAULT;
//                    }
//                }
//                    break;
//                case NEUTRON_F_GETOWN_EX: {
//                    struct ::f_owner_ex host_buf{};
//                    f_owner_ex guest_buf{};
//
//                    ret = fcntl(sub_type()->get_host_fd(fd), cmd, &host_buf);
//
//                    if (ret == -1) {
//                        ret = -errno;
//                    } else {
//                        guest_buf.type = static_cast<f_owner_ex::pid_type>(host_buf.type);
//                        guest_buf.pid = host_buf.pid;
//
//                        if (!pcb.memory_copy_to_guest(arg, &guest_buf, sizeof(guest_buf))) {
//                            ret = -EFAULT;
//                        }
//                    }
//                }
//                    break;
//                case NEUTRON_F_SETOWN_EX: {
//                    struct ::f_owner_ex host_buf{};
//                    f_owner_ex guest_buf{};
//
//                    if (pcb.memory_copy_from_guest(&guest_buf, arg, sizeof(guest_buf))) {
//                        host_buf.type = static_cast<__pid_type>(guest_buf.type);
//                        host_buf.pid = guest_buf.pid;
//
//                        ret = fcntl(sub_type()->get_host_fd(fd), cmd, &host_buf);
//
//                        if (ret == -1) {
//                            ret = -errno;
//                        }
//                    } else {
//                        ret = -EFAULT;
//                    }
//                }
//                    break;
            case NEUTRON_F_GET_RW_HINT:
            case NEUTRON_F_GET_FILE_RW_HINT: {
                u64 host_buf, guest_buf;
                ret = fcntl(sub_type()->get_host_fd(fd), cmd, &host_buf);

                if (ret == -1) {
                    ret = -errno;
                } else {
                    guest_buf = host_buf;
                    if (!pcb.memory_copy_to_guest(arg, &guest_buf, sizeof(guest_buf))) {
                        ret = -EFAULT;
                    }
                }
            }
                break;
            case NEUTRON_F_SET_RW_HINT:
            case NEUTRON_F_SET_FILE_RW_HINT: {
                u64 host_buf, guest_buf;

                if (pcb.memory_copy_from_guest(&guest_buf, arg, sizeof(guest_buf))) {
                    host_buf = guest_buf;
                    ret = fcntl(sub_type()->get_host_fd(fd), cmd, &host_buf);

                    if (ret == -1) {
                        ret = -errno;
                    }
                } else {
                    ret = -EFAULT;
                }
            }
                break;
            default:
                ret = fcntl(sub_type()->get_host_fd(fd), cmd, arg);

                if (ret == -1) {
                    ret = -errno;
                }
        }

        if (ret > 0) {
            switch (cmd) {
                case NEUTRON_F_DUPFD:
                    ret = sub_type()->get_guest_fd(ret);
                    break;
                case NEUTRON_F_DUPFD_CLOEXEC:
                    ret = sub_type()->get_guest_fd(ret);
                    pcb.set_close_exec(ret, true);
                    break;
                case NEUTRON_F_SETFD:
                    pcb.set_close_exec(fd, (arg & NEUTRON_FD_CLOEXEC) == NEUTRON_FD_CLOEXEC);
                    break;
            }
        }

        syscall_debug(ret, "fcntl", "fd", fd, "cmd", cmd, "arg", arg);

        return ret;
    }

    XLenT sys_ioctl(int fd, UXLenT request, UXLenT argp) {
#if defined(__linux__)
        UXLenT size = _IOC_SIZEMASK & (request >> _IOC_SIZESHIFT);
#elif defined(__APPLE__)
        UXLenT size = 0; // todo
#endif
        XLenT ret;

        Array<u8> buf{size};

        if (pcb.memory_copy_from_guest(buf.begin(), argp, size)) {
            ret = ioctl(sub_type()->get_host_fd(fd), request, buf.begin());
            if (ret == -1) {
                ret = -errno;
            }
        } else {
            ret = -EFAULT;
        }

        syscall_debug(ret, "ioctl", "fd", fd, "request", request, "argp", argp);

        return ret;
    }

    XLenT sys_faccessat(int dirfd, UXLenT pathname, XLenT mode) {
        XLenT ret;
        Array<char> name{};

        if (pcb.string_copy_from_guest(pathname, name)) {
            auto real_name = sub_type()->get_host_file_name(name.begin());
            ret = faccessat(sub_type()->get_host_fd(dirfd), real_name.c_str(), mode, 0);
            if (ret == -1) { ret = -errno; }
        } else {
            ret = -EFAULT;
        }

        syscall_debug(ret, "faccessat", "dirfd", dirfd, "pathname", name.begin(), "mode", mode);

        return ret;
    }

    XLenT sys_openat(int dirfd, UXLenT pathname, XLenT flags, XLenT mode) {
        XLenT ret;
        Array<char> name{};

        if (pcb.string_copy_from_guest(pathname, name)) {
            auto real_name = sub_type()->get_host_file_name(name.begin());
            ret = openat(sub_type()->get_host_fd(dirfd), real_name.c_str(), flags, mode);

            if (ret == -1) {
                ret = -errno;
            } else {
                ret = sub_type()->get_guest_fd(ret);
                pcb.set_close_exec(ret, (flags & NEUTRON_O_CLOEXEC) == NEUTRON_O_CLOEXEC);
            }
        } else {
            ret = -EFAULT;
        }

        syscall_debug(ret, "openat", "dirfd", dirfd, "flags", flags, "mode", mode);

        return ret;
    }

    XLenT sys_close(int fd) {
        XLenT ret = pcb.close_fd(fd);

        syscall_debug(ret, "close", "fd", fd);

        return ret;
    }

    XLenT sys_pipe2(UXLenT pipefd, XLenT flags) {
        XLenT ret;

#if defined(__linux__)
        int host_pipefd[2]{-1, -1};
        int guest_pipefd[2]{-1, -1};

        ret = pipe2(host_pipefd, flags);

        if (ret == -1) {
            ret = -errno;
        } else {
            guest_pipefd[0] = sub_type()->get_guest_fd(host_pipefd[0]);
            guest_pipefd[1] = sub_type()->get_guest_fd(host_pipefd[1]);

            pcb.set_close_exec(host_pipefd[0], (flags & NEUTRON_O_CLOEXEC) == NEUTRON_O_CLOEXEC);
            pcb.set_close_exec(host_pipefd[1], (flags & NEUTRON_O_CLOEXEC) == NEUTRON_O_CLOEXEC);

            if (!pcb.memory_copy_to_guest(pipefd, &guest_pipefd, sizeof(guest_pipefd))) {
                pcb.close_fd(guest_pipefd[0]);
                pcb.close_fd(guest_pipefd[1]);
                ret = -EFAULT;
            }
        }
#elif defined(__APPLE__)
        (void) pipefd;
        (void) flags;

        ret = -EINVAL;
#endif

        syscall_debug(ret, "pipe2", "pipefd", pipefd, "flags", flags);

        return ret;
    }

    // todo: this is different from 32 and 64

    /// This function is 64 bit version for 32 bit arch. The errno is returned as usual, but the seek result,
    /// a 64 bit number, is write to the result parameter as address.
    XLenT sys_lseek(int fd, UXLenT offset_hi, UXLenT offset_lo, UXLenT result, XLenT whence) {
        i64 offset = (static_cast<u64>(offset_hi) << 32u) + offset_lo;

        i64 ret = lseek(sub_type()->get_host_fd(fd), offset, whence);

        XLenT guest_ret;

        if (ret == -1) {
            ret = -errno;
            guest_ret = -errno;
        } else {
            if (!pcb.memory_copy_to_guest(result, &ret, sizeof(ret))) {
                ret = -EFAULT;
                guest_ret = -EFAULT;
            } else {
                guest_ret = 0;
            }
        }

        syscall_debug(ret, "lseek", "fd", fd, "offset", offset, "whence", whence);

        return guest_ret;
    }

    XLenT sys_read(int fd, UXLenT addr, UXLenT size) {
        XLenT ret;

        std::vector<::iovec> vec{};

        if (pcb.memory_get_vector(addr, size, riscv_isa::W_BIT, vec)) {
            ret = readv(sub_type()->get_host_fd(fd), vec.data(), vec.size());
            if (ret == -1) {
                ret = -errno;
            }
        } else {
            ret = -EFAULT;
        }

        syscall_debug(ret, "read", "fd", fd, "addr", addr, "size", size);

        return ret;
    }

    XLenT sys_write(int fd, UXLenT addr, UXLenT size) {
        XLenT ret;

        std::vector<::iovec> vec{};

        if (pcb.memory_get_vector(addr, size, riscv_isa::R_BIT, vec)) {
            ret = writev(sub_type()->get_host_fd(fd), vec.data(), vec.size());
            if (ret == -1) {
                ret = -errno;
            }
        } else {
            ret = -EFAULT;
        }

        syscall_debug(ret, "write", "fd", fd, "addr", addr, "size", size);

        return ret;
    }

    XLenT sys_readv(int fd, UXLenT iov, UXLenT iovcnt) {
        XLenT ret;

        std::vector<::iovec> vec{};

        if (pcb.memory_convert_io_vec(iov, iovcnt, riscv_isa::W_BIT, vec)) {
            ret = readv(sub_type()->get_host_fd(fd), vec.data(), vec.size());
            if (ret == -1) {
                ret = -errno;
            }
        } else {
            ret = -EFAULT;
        }

        syscall_debug(ret, "readv", "fd", fd, "iov", iov, "iovcnt", iovcnt);

        return ret;
    }

    XLenT sys_writev(int fd, UXLenT iov, UXLenT iovcnt) {
        XLenT ret;

        std::vector<::iovec> vec{};

        if (pcb.memory_convert_io_vec(iov, iovcnt, riscv_isa::R_BIT, vec)) {
            ret = writev(sub_type()->get_host_fd(fd), vec.data(), vec.size());
            if (ret == -1) {
                ret = -errno;
            }
        } else {
            ret = -EFAULT;
        }

        syscall_debug(ret, "writev", "fd", fd, "iov", iov, "iovcnt", iovcnt);

        return ret;
    }

    XLenT sys_readlinkat(int dirfd, UXLenT pathname, UXLenT buf, UXLenT bufsize) {
        XLenT ret;
        Array<char> name{};

        if (pcb.string_copy_from_guest(pathname, name)) {
            Array<char> host_buf{bufsize};
            auto real_name = sub_type()->get_host_file_name(name.begin());
            ret = readlinkat(sub_type()->get_host_fd(dirfd), real_name.data(), host_buf.begin(),
                             bufsize);

            if (ret == -1) {
                ret = -errno;
            } else {
                if (!pcb.memory_copy_to_guest(buf, host_buf.begin(), bufsize)) {
                    ret = -EFAULT;
                }
            }
        } else {
            ret = -EFAULT;
        }

        syscall_debug(ret, "readlinkat", "dirfd", dirfd, "pathname", name.begin(), "buf", buf,
                      "bufsize", bufsize);

        return ret;
    }

    XLenT sys_fstat(UXLenT fd, UXLenT addr) {
        struct ::stat host_buf{};
        stat guest_buf{};

        XLenT ret = fstat(sub_type()->get_host_fd(fd), &host_buf);

        if (ret == 0) {
            guest_buf.dev = host_buf.st_dev;
            guest_buf.ino = host_buf.st_ino;
            guest_buf.mode = host_buf.st_mode;
            guest_buf.nlink = host_buf.st_nlink;
            guest_buf.uid = host_buf.st_uid;
            guest_buf.gid = host_buf.st_gid;
            guest_buf.rdev = host_buf.st_rdev;
            guest_buf.size = host_buf.st_size;
            guest_buf.blksize = host_buf.st_blksize;
            guest_buf.blocks = host_buf.st_blocks;
#if defined(__linux__)
            guest_buf.atime.sec = host_buf.st_atim.tv_sec;
            guest_buf.atime.nsec = host_buf.st_atim.tv_nsec;
            guest_buf.mtime.sec = host_buf.st_mtim.tv_sec;
            guest_buf.mtime.nsec = host_buf.st_mtim.tv_nsec;
            guest_buf.ctime.sec = host_buf.st_ctim.tv_sec;
            guest_buf.ctime.nsec = host_buf.st_ctim.tv_nsec;
#elif defined(__APPLE__)
            guest_buf.atime.sec = host_buf.st_atimespec.tv_sec;
            guest_buf.atime.nsec = host_buf.st_atimespec.tv_nsec;
            guest_buf.mtime.sec = host_buf.st_mtimespec.tv_sec;
            guest_buf.mtime.nsec = host_buf.st_mtimespec.tv_nsec;
            guest_buf.ctime.sec = host_buf.st_ctimespec.tv_sec;
            guest_buf.ctime.nsec = host_buf.st_ctimespec.tv_nsec;
#endif

            if (!pcb.memory_copy_to_guest(addr, &guest_buf, sizeof(guest_buf))) {
                ret = -EFAULT;
            }
        } else {
            ret = -errno;
        }

        syscall_debug(ret, "fstat", "fd", fd, "addr", guest_buf);

        return ret;
    }

    void sys_exit(XLenT status) { pcb.exit_value = status; }

    // todo: exit group
    void sys_exit_group(XLenT status) { pcb.exit_value = status; }

    XLenT sys_futex(UXLenT uaddr, XLenT futex_op, XLenT val,
                    UXLenT val2, UXLenT uaddr2, XLenT val3) {
        (void) val2;
        (void) uaddr2;
        (void) val3;

        XLenT ret = 0;

        // todo: not implement

        i32 *host_uaddr = pcb.template address<i32>(uaddr, riscv_isa::MemoryProtection::READ_WRITE);

        switch (futex_op) {
            case NEUTRON_FUTEX_WAIT_PRIVATE:
                if (host_uaddr == nullptr) {
                    ret = -EINVAL;
                }

                *host_uaddr = 0;

//                    if (*host_uaddr != val) {
//                        ret = -EAGAIN;
//                    }

                break;
        }

        syscall_debug(ret, "futex", "uaddr", uaddr, "val", val, "val2", val2,
                      "uaddr2", uaddr2, "val3", val3);

        return ret;
    }

    XLenT sys_sched_yield() {
        XLenT ret = 0;

        // todo: real yield for multi-thread

        syscall_debug(ret, "sched_yield");

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

            if (!pcb.memory_copy_to_guest(buf, &guest_buf, sizeof(guest_buf))) {
                ret = -EFAULT;
            }
        } else {
            ret = -errno;
        }

        syscall_debug(ret, "times", "buf", buf);

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
            memcpy(guest_buf.machine, pcb.platform_string(),
                   std::min(sizeof(guest_buf.machine), strlen(pcb.platform_string())));

            if (!pcb.memory_copy_to_guest(buf, &guest_buf, sizeof(guest_buf))) {
                ret = -EFAULT;
            }
        } else {
            ret = -errno;
        }

        syscall_debug(ret, "uname", "buf", guest_buf);

        return ret;
    }

    XLenT sys_getpid() {
        XLenT ret = getpid();

        syscall_debug(ret, "getpid");

        return ret;
    }

    XLenT sys_getppid() {
        XLenT ret = getppid();

        syscall_debug(ret, "getppid");

        return ret;
    }

    XLenT sys_getuid() {
        XLenT ret = getuid();

        syscall_debug(ret, "getuid");

        return ret;
    }

    XLenT sys_geteuid() {
        XLenT ret = geteuid();

        syscall_debug(ret, "geteuid");

        return ret;
    }

    XLenT sys_getgid() {
        XLenT ret = getgid();

        syscall_debug(ret, "getgid");

        return ret;
    }

    XLenT sys_getegid() {
        XLenT ret = getegid();

        syscall_debug(ret, "getegid");

        return ret;
    }

    XLenT sys_sysinfo(UXLenT info) {
        XLenT ret;
        sysinfo guest_info{};

#if defined(__linux__)
        struct ::sysinfo host_info{};

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

            if (!pcb.memory_copy_to_guest(info, &guest_info, sizeof(guest_info))) {
                ret = -EFAULT;
            }
        }
#else
        (void) info;

        ret = -EINVAL; // todo
#endif

        syscall_debug(ret, "sysinfo", "info", guest_info);

        return ret;
    }

    XLenT sys_brk(UXLenT addr) {
        XLenT ret = pcb.set_break(addr);

        if (static_cast<UXLenT>(ret) == addr) {
            invalid_cache();
        }

        syscall_debug(ret, "brk", "addr", addr);

        return ret;
    }

    XLenT sys_munmap(UXLenT addr, UXLenT length) {
        XLenT ret;

        if (addr < pcb.MEM_BEGIN || length > pcb.MEM_BEGIN ||
            pcb.MEM_BEGIN - length < addr || addr % RISCV_PAGE_SIZE != 0) {
            ret = -EINVAL;
        } else {
            ret = pcb.memory_unmap(addr, divide_ceil(length, RISCV_PAGE_SIZE) * RISCV_PAGE_SIZE);
        }

        if (ret == 0) {
            invalid_cache();
        }

        syscall_debug(ret, "munmap", "addr", addr, "length", length);

        return ret;
    }

    /// the offset is counted in page, not byte!
    XLenT sys_mmap(UXLenT addr, UXLenT length, XLenT prot, XLenT flags, XLenT fd, UXLenT offset) {
        XLenT ret = pcb.memory_map(addr, length, prot, flags, fd, offset << 12);

        if (static_cast<UXLenT>(ret) <= static_cast<UXLenT>(-RISCV_PAGE_SIZE)) {
            invalid_cache();
        }

        syscall_debug(ret, "mmap", "addr", addr, "length", length, "prot", prot,
                      "flags", flags, "fd", fd, "offset", offset << 12);

        return ret;
    }

    XLenT sys_mprotect(UXLenT addr, UXLenT len, XLenT prot) {
        XLenT ret = pcb.memory_protection(addr, len, prot);

        if (static_cast<UXLenT>(ret) == 0) {
            invalid_cache();
        }

        syscall_debug(ret, "mprotect", "addr", addr, "len", len, "prot", prot);

        return ret;
    }

    XLenT sys_prlimit64(XLenT pid, XLenT resource, UXLenT new_limit, UXLenT old_limit) {
        XLenT ret; // todo

#if defined(__linux__)
        struct rlimit host_old_limit{};

        if (new_limit == 0) {
            ret = prlimit(pid, (__rlimit_resource) resource,
                          nullptr, &host_old_limit);

        } else {
            struct rlimit host_new_limit{};

            if (!pcb.memory_copy_from_guest(&host_new_limit, new_limit, sizeof(host_new_limit))) {
                ret = -EFAULT;
            } else {
                ret = prlimit(pid, (__rlimit_resource) resource,
                              &host_new_limit, &host_old_limit);
            }
        }

        if (ret != 0) {
            ret = -errno;
        } else {
            if (!pcb.memory_copy_to_guest(old_limit, &host_old_limit, sizeof(host_old_limit))) {
                ret = -EFAULT;
            }
        }
#elif defined(__APPLE__)
        (void) pid;
        (void) resource;
        (void) new_limit;
        (void) old_limit;

        ret = -EINVAL;
#endif

        syscall_debug(ret, "prlimit64", "pid", pid, "resource", resource, "new_limit", new_limit,
                      "old_limit", old_limit);

        return ret;
    }

    XLenT sys_statx(int dirfd, UXLenT pathname, XLenT flags, UXLenT mask, UXLenT statxbuf) {
        XLenT ret;
        Array<char> name{};

        statx guest_buf{};

#if defined(__linux__)
        struct ::statx host_buf{};
#elif defined(__APPLE__)
        struct ::stat host_buf{};
#endif

        if (pcb.string_copy_from_guest(pathname, name)) {
            auto real_name = sub_type()->get_host_file_name(name.begin());

#if defined(__linux__)
            ret = ::statx(sub_type()->get_host_fd(dirfd), real_name.c_str(), flags, mask, &host_buf);
#elif defined(__APPLE__)
            if (name.size() == 1) {
                if ((flags & NEUTRON_AT_EMPTY_PATH) > 0) {
                    ret = fstat(dirfd, &host_buf);
                } else {
                    ret = fstat(dirfd, &host_buf);
                }
            } else if (name[0] == '/') {
                ret = ::stat(real_name.c_str(), &host_buf);
            } else if (dirfd == AT_FDCWD) {
                ret = fstatat(AT_FDCWD, real_name.c_str(), &host_buf, 0);
            } else {
                ret = fstatat(sub_type()->get_host_fd(dirfd), real_name.c_str(), &host_buf, 0);
            }
#endif
            if (ret == 0) {
#if defined(__linux__)
                guest_buf.mask = host_buf.stx_mask;
                guest_buf.blksize = host_buf.stx_blksize;
                guest_buf.attributes = host_buf.stx_attributes;
                guest_buf.nlink = host_buf.stx_nlink;
                guest_buf.uid = host_buf.stx_uid;
                guest_buf.gid = host_buf.stx_gid;
                guest_buf.mode = host_buf.stx_mode;
                guest_buf.ino = host_buf.stx_ino;
                guest_buf.size = host_buf.stx_size;
                guest_buf.blocks = host_buf.stx_blocks;
                guest_buf.attributes_mask = host_buf.stx_attributes_mask;
                guest_buf.atime.sec = host_buf.stx_atime.tv_sec;
                guest_buf.atime.nsec = host_buf.stx_atime.tv_nsec;
                guest_buf.btime.sec = host_buf.stx_btime.tv_sec;
                guest_buf.btime.nsec = host_buf.stx_btime.tv_nsec;
                guest_buf.ctime.sec = host_buf.stx_ctime.tv_sec;
                guest_buf.ctime.nsec = host_buf.stx_ctime.tv_nsec;
                guest_buf.mtime.sec = host_buf.stx_mtime.tv_sec;
                guest_buf.mtime.nsec = host_buf.stx_mtime.tv_nsec;
                guest_buf.rdev_major = host_buf.stx_rdev_major;
                guest_buf.rdev_minor = host_buf.stx_rdev_minor;
                guest_buf.dev_major = host_buf.stx_dev_major;
                guest_buf.dev_minor = host_buf.stx_dev_minor;
#elif defined(__APPLE__)
//                guest_buf.mask = host_buf.mask;
                guest_buf.blksize = host_buf.st_blksize;
//                guest_buf.attributes = host_buf.attributes;
                guest_buf.nlink = host_buf.st_nlink;
                guest_buf.uid = host_buf.st_uid;
                guest_buf.gid = host_buf.st_gid;
                guest_buf.mode = host_buf.st_mode;
                guest_buf.ino = host_buf.st_ino;
                guest_buf.size = host_buf.st_size;
                guest_buf.blocks = host_buf.st_blocks;
//                guest_buf.attributes_mask = host_buf.attributes_mask;
                guest_buf.atime.sec = host_buf.st_atimespec.tv_sec;
                guest_buf.atime.nsec = host_buf.st_atimespec.tv_nsec;
//                guest_buf.btime.sec = host_buf.st_btime.sec;
//                guest_buf.btime.nsec = host_buf.st_btime.nsec;
                guest_buf.ctime.sec = host_buf.st_ctimespec.tv_sec;
                guest_buf.ctime.nsec = host_buf.st_ctimespec.tv_nsec;
                guest_buf.mtime.sec = host_buf.st_mtimespec.tv_sec;
                guest_buf.mtime.nsec = host_buf.st_mtimespec.tv_nsec;
//                guest_buf.rdev_major = host_buf.st_rdev_major;
//                guest_buf.rdev_minor = host_buf.st_rdev_minor;
//                guest_buf.dev_major = host_buf.st_dev_major;
//                guest_buf.dev_minor = host_buf.st_dev_minor;
#endif

                if (!pcb.memory_copy_to_guest(statxbuf, &guest_buf, sizeof(guest_buf))) {
                    ret = -EFAULT;
                }
            } else {
                ret = -errno;
            }
        } else {
            ret = -EFAULT;
        }

        syscall_debug(ret, "statx", "dirfd", dirfd, "pathname", name.begin(),
                      "flags", flags, "mask", mask, "statxbuf", guest_buf);

        return ret;
    }

    bool u_mode_environment_call_handler() {
        bool ret = false;

        switch (static_cast<SyscallNum>(sub_type()->get_x(IntRegT::A7))) {
#define make_syscall(num, name) \
            case SyscallNum::name: \
                neutron_syscall(num, sub_type()->sys_##name); \
                ret = true; \
                break

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
            case SyscallNum::exit:
                sub_type()->sys_exit(sub_type()->get_x(IntRegT::A0));
                ret = false;
                break;
            case SyscallNum::exit_group:
                sub_type()->sys_exit_group(sub_type()->get_x(IntRegT::A0));
                ret = false;
                break;
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
                std::cerr << "Invalid environment call number at " << std::hex
                          << sub_type()->get_pc()
                          << ", call number " << std::dec << sub_type()->get_x(IntRegT::A7)
                          << std::endl;

                ret = true;
#undef make_syscall
        }

        sub_type()->inc_pc(riscv_isa::ECALLInst::INST_WIDTH);

        return ret;
    }

    bool goto_main() {
        bool old_debug = debug;
        debug = false;

        while (static_cast<UXLenT>(sub_type()->get_pc()) != this->pcb.elf_main) {
            if (!sub_type()->visit() && !sub_type()->trap_handler()) return false;
        }

        debug = old_debug;

        return true;
    }
};

template<typename xlen>
class LinuxHart : public LinuxHart_<LinuxHart<xlen>, xlen> {
public:
    LinuxHart(typename xlen::UXLenT hart_id, LinuxProgram<xlen> &mem,
              bool debug = false, std::ostream &debug_stream = std::cerr) :
            LinuxHart_<LinuxHart<xlen>, xlen>{hart_id, mem, debug, debug_stream} {}
};
}


#endif //NEUTRON_RISCV_LINUX_HPP
