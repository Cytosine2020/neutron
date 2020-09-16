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
#include <linux/futex.h>

#include <iostream>
#include <map>

#include "target/hart.hpp"
#include "target/dump.hpp"
#include "translator.hpp"

#include "neutron_utility.hpp"
#include "riscv_linux_program.hpp"
#include "linux_std.hpp"

#include "dynamic_translation.h"

namespace neutron {
    template<typename SubT, typename xlen>
    class LinuxHart_ : public riscv_isa::Hart<SubT, xlen> {
    public:
        using SuperT = riscv_isa::Hart<SubT, xlen>;

        using RetT = typename SuperT::RetT;
        using XLenT = typename SuperT::XLenT;
        using UXLenT = typename SuperT::UXLenT;
        using IntRegT = typename SuperT::IntRegT;
        using CSRRegT = typename SuperT::CSRRegT;

        using TranslateT = Translator<Emitter<xlen>, xlen>;

    private:
        SubT *sub_type() { return static_cast<SubT *>(this); }

        SuperT *super() { return this; }

    protected:
        LinuxProgram<xlen> &pcb;
        typename LinuxProgram<xlen>::MemoryArea execute_cache;
        typename LinuxProgram<xlen>::MemoryArea load_cache;
        typename LinuxProgram<xlen>::MemoryArea store_cache;
        std::unordered_map<UXLenT, void *> code_cache;
        std::ostream &debug_stream;
        bool debug;

    public:
        LinuxHart_(UXLenT hart_id, LinuxProgram<xlen> &mem,
                   bool debug = false, std::ostream &debug_stream = std::cerr) :
                SuperT{hart_id, mem.pc, mem.int_reg}, pcb{mem}, execute_cache{0, 0, nullptr},
                load_cache{0, 0, nullptr}, store_cache{0, 0, nullptr},
                debug_stream{debug_stream}, debug{debug} {
            this->cur_level = riscv_isa::USER_MODE;
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
                auto area = pcb.get_memory_area(addr, riscv_isa::READ);
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
                auto area = pcb.get_memory_area(addr, riscv_isa::READ_WRITE);
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
                auto area = pcb.get_memory_area(addr, riscv_isa::EXECUTE);
                if (area.start == 0) {
                    return nullptr;
                } else {
                    execute_cache = area;
                    return reinterpret_cast<ValT *>(area.shift + addr);
                }
            }
        }

        static bool neutron_mmu_execute_fast_call(struct dynamic_info *info, UXLenT addr) {
            LinuxProgram<xlen> &pcb = reinterpret_cast<SubT *>(info->core)->pcb;

            auto area = pcb.get_memory_area(addr, riscv_isa::EXECUTE);

            if (area.start == 0) {
                return false;
            } else {
                info->execute_cache.start = area.start;
                info->execute_cache.end = area.end;
                info->execute_cache.shift = reinterpret_cast<usize>(area.shift);
                return true;
            }
        }

        static bool neutron_mmu_load_fast_call(struct dynamic_info *info, UXLenT addr) {
            LinuxProgram<xlen> &pcb = reinterpret_cast<SubT *>(info->core)->pcb;

            auto area = pcb.get_memory_area(addr, riscv_isa::READ);

            if (area.start == 0) {
                return false;
            } else {
                info->load_cache.start = area.start;
                info->load_cache.end = area.end;
                info->load_cache.shift = reinterpret_cast<usize>(area.shift);
                return true;
            }
        }

        static bool neutron_mmu_store_fast_call(struct dynamic_info *info, UXLenT addr) {
            LinuxProgram<xlen> &pcb = reinterpret_cast<SubT *>(info->core)->pcb;

            auto area = pcb.get_memory_area(addr, riscv_isa::READ_WRITE);

            if (area.start == 0) {
                return false;
            } else {
                info->store_cache.start = area.start;
                info->store_cache.end = area.end;
                info->store_cache.shift = reinterpret_cast<usize>(area.shift);
                return true;
            }
        }

#if defined(__RV_EXTENSION_ZICSR__)

        RetT get_csr_reg(UXLenT index) { return this->csr_reg[index]; }

        RetT set_csr_reg(neutron_unused UXLenT index, neutron_unused UXLenT val) { return true; }

#endif // defined(__RV_EXTENSION_ZICSR__)

        RetT visit_inst(const riscv_isa::Instruction *inst) { return sub_type()->illegal_instruction(inst); }

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

            switch (cmd) {
                case NEUTRON_F_SETLK:
                case NEUTRON_F_SETLKW:
                case NEUTRON_F_OFD_SETLK:
                case NEUTRON_F_OFD_SETLKW: {
                    struct ::flock host_buf{};
                    flock guest_buf{};

                    if (pcb.memory_copy_from_guest(&guest_buf, arg, sizeof(guest_buf))) {
                        host_buf.l_type = guest_buf.l_type;
                        host_buf.l_whence = guest_buf.l_whence;
                        host_buf.l_start = guest_buf.l_start;
                        host_buf.l_len = guest_buf.l_len;
                        host_buf.l_pid = guest_buf.l_pid;

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
                        host_buf.l_type = guest_buf.l_type;
                        host_buf.l_whence = guest_buf.l_whence;
                        host_buf.l_start = guest_buf.l_start;
                        host_buf.l_len = guest_buf.l_len;
                        host_buf.l_pid = guest_buf.l_pid;

                        ret = fcntl(sub_type()->get_host_fd(fd), cmd, &host_buf);

                        if (ret == -1) {
                            ret = -errno;
                        } else {
                            guest_buf.l_type = host_buf.l_type;
                            guest_buf.l_whence = host_buf.l_whence;
                            guest_buf.l_start = host_buf.l_start;
                            guest_buf.l_len = host_buf.l_len;
                            guest_buf.l_pid = host_buf.l_pid;

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
                case NEUTRON_F_SETLKW64: {
                    struct ::flock64 host_buf{};
                    flock64 guest_buf{};

                    if (pcb.memory_copy_from_guest(&guest_buf, arg, sizeof(guest_buf))) {
                        host_buf.l_type = guest_buf.l_type;
                        host_buf.l_whence = guest_buf.l_whence;
                        host_buf.l_start = guest_buf.l_start;
                        host_buf.l_len = guest_buf.l_len;
                        host_buf.l_pid = guest_buf.l_pid;

                        ret = fcntl(sub_type()->get_host_fd(fd), cmd, &host_buf);

                        if (ret == -1) {
                            ret = -errno;
                        }
                    } else {
                        ret = -EFAULT;
                    }
                }
                    break;
                case NEUTRON_F_GETLK64: {
                    struct ::flock64 host_buf{};
                    flock64 guest_buf{};

                    if (pcb.memory_copy_from_guest(&guest_buf, arg, sizeof(guest_buf))) {
                        host_buf.l_type = guest_buf.l_type;
                        host_buf.l_whence = guest_buf.l_whence;
                        host_buf.l_start = guest_buf.l_start;
                        host_buf.l_len = guest_buf.l_len;
                        host_buf.l_pid = guest_buf.l_pid;

                        ret = fcntl(sub_type()->get_host_fd(fd), cmd, &host_buf);

                        if (ret == -1) {
                            ret = -errno;
                        } else {
                            guest_buf.l_type = host_buf.l_type;
                            guest_buf.l_whence = host_buf.l_whence;
                            guest_buf.l_start = host_buf.l_start;
                            guest_buf.l_len = host_buf.l_len;
                            guest_buf.l_pid = host_buf.l_pid;

                            if (!pcb.memory_copy_to_guest(arg, &guest_buf, sizeof(guest_buf))) {
                                ret = -EFAULT; // this should never happen.
                            }
                        }
                    } else {
                        ret = -EFAULT;
                    }
                }
                    break;
                case NEUTRON_F_GETOWN_EX: {
                    struct ::f_owner_ex host_buf{};
                    f_owner_ex guest_buf{};

                    ret = fcntl(sub_type()->get_host_fd(fd), cmd, &host_buf);

                    if (ret == -1) {
                        ret = -errno;
                    } else {
                        guest_buf.type = static_cast<f_owner_ex::pid_type>(host_buf.type);
                        guest_buf.pid = host_buf.pid;

                        if (!pcb.memory_copy_to_guest(arg, &guest_buf, sizeof(guest_buf))) {
                            ret = -EFAULT;
                        }
                    }
                }
                    break;
                case NEUTRON_F_SETOWN_EX: {
                    struct ::f_owner_ex host_buf{};
                    f_owner_ex guest_buf{};

                    if (pcb.memory_copy_from_guest(&guest_buf, arg, sizeof(guest_buf))) {
                        host_buf.type = static_cast<__pid_type>(guest_buf.type);
                        host_buf.pid = guest_buf.pid;

                        ret = fcntl(sub_type()->get_host_fd(fd), cmd, &host_buf);

                        if (ret == -1) {
                            ret = -errno;
                        }
                    } else {
                        ret = -EFAULT;
                    }
                }

                    break;
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

            if (pcb.memory_copy_from_guest(buf.begin(), argp, size)) {
                ret = ioctl(sub_type()->get_host_fd(fd), request, buf.begin());
                if (ret == -1) {
                    ret = -errno;
                }
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
                auto real_name = sub_type()->get_host_file_name(name.begin());
                ret = faccessat(sub_type()->get_host_fd(dirfd), real_name.c_str(), mode, 0);
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
            XLenT ret = pcb.close_fd(fd);

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

            if (debug) {
                debug_stream << "system call: " << ret
                             << " = close(<pipefd> [" << host_pipefd[0] << ", " << host_pipefd[1]
                             << ", <flags>" << flags
                             << ");" << std::endl;
            }

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
                ret = readv(sub_type()->get_host_fd(fd), vec.data(), vec.size());
                if (ret == -1) {
                    ret = -errno;
                }
            } else {
                ret = -EFAULT;
            }

            if (debug) {
                char content[11]{};

                if (ret > 0) {
                    UXLenT read_size = std::min(10, ret);

                    if (!pcb.memory_copy_from_guest(content, addr, read_size)) {
                        neutron_unreachable("");
                    }
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
                ret = writev(sub_type()->get_host_fd(fd), vec.data(), vec.size());
                if (ret == -1) {
                    ret = -errno;
                }
            } else {
                ret = -EFAULT;
            }

            if (debug) {
                char content[11]{};

                if (ret > 0) {
                    UXLenT read_size = std::min(10, ret);

                    if (!pcb.memory_copy_from_guest(content, addr, read_size)) {
                        neutron_unreachable("");
                    }
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
                ret = readv(sub_type()->get_host_fd(fd), vec.data(), vec.size());
                if (ret == -1) {
                    ret = -errno;
                }
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
                ret = writev(sub_type()->get_host_fd(fd), vec.data(), vec.size());
                if (ret == -1) {
                    ret = -errno;
                }
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
                auto real_name = sub_type()->get_host_file_name(name.begin());
                ret = readlinkat(sub_type()->get_host_fd(dirfd), real_name.data(), host_buf.begin(), bufsiz);

                if (ret == -1) {
                    ret = -errno;
                } else {
                    if (!pcb.memory_copy_to_guest(buf, host_buf.begin(), bufsiz)) {
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

            XLenT ret = fstat(sub_type()->get_host_fd(fd), &host_buf);

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

                if (!pcb.memory_copy_to_guest(addr, &guest_buf, sizeof(guest_buf))) {
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

            i32 *host_uaddr = pcb.template address<i32>(uaddr, riscv_isa::READ_WRITE);

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

                if (!pcb.memory_copy_to_guest(buf, &guest_buf, sizeof(guest_buf))) {
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
                memcpy(guest_buf.machine, pcb.platform_string,
                       std::min(sizeof(guest_buf.machine), sizeof(pcb.platform_string)));

                if (!pcb.memory_copy_to_guest(buf, &guest_buf, sizeof(guest_buf))) {
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

                if (!pcb.memory_copy_to_guest(info, &guest_info, sizeof(guest_info))) {
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

            if (static_cast<UXLenT>(ret) == addr) {
                invalid_cache();
            }

            if (debug) {
                debug_stream << "system call: " << ret
                             << " = brk(<addr> " << addr
                             << ");" << std::endl;
            }

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

            if (debug) {
                debug_stream << "system call: " << ret
                             << " = brk(<addr> " << addr
                             << " = brk(<length> " << length
                             << ");" << std::endl;
            }

            return ret;
        }

        /// the offset is counted in page, not byte!
        XLenT sys_mmap(UXLenT addr, UXLenT length, XLenT prot, XLenT flags, XLenT fd, UXLenT offset) {
            XLenT ret = pcb.memory_map(addr, length, prot, flags, fd, offset);

            if (static_cast<UXLenT>(ret) <= static_cast<UXLenT>(-RISCV_PAGE_SIZE)) {
                invalid_cache();
            }

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

            if (static_cast<UXLenT>(ret) == 0) {
                invalid_cache();
            }

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
            XLenT ret; // todo:

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
                auto real_name = sub_type()->get_host_file_name(name.begin());

#if defined(__linux__)
                ret = ::statx(sub_type()->get_host_fd(dirfd), real_name.c_str(), flags, mask, &host_buf);
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
                    ret = fstatat(sub_type()->get_host_fd(dirfd), real_name.c_str(), &host_buf, 0);
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

                    if (!pcb.memory_copy_to_guest(statxbuf, &guest_buf, sizeof(guest_buf))) {
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
            bool ret = false;

            switch (sub_type()->get_x(IntRegT::A7)) {
#define make_syscall(num, name) \
                case syscall::name: \
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
                case syscall::exit:
                    sub_type()->sys_exit(sub_type()->get_x(IntRegT::A0));
                    ret = false;
                    break;
                case syscall::exit_group:
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
                    std::cerr << "Invalid environment call number at " << std::hex << sub_type()->get_pc()
                              << ", call number " << std::dec << sub_type()->get_x(IntRegT::A7)
                              << std::endl;

                    ret = true;
#undef make_syscall
            }

            sub_type()->inc_pc(riscv_isa::ECALLInst::INST_WIDTH);

            return ret;
        }

        RetT visit_jal_inst(const riscv_isa::JALInst *inst) {
            return super()->visit_jal_inst(inst);
        }

        RetT visit_jalr_inst(const riscv_isa::JALRInst *inst) {
            return super()->visit_jalr_inst(inst);
        }

        RetT visit_beq_inst(const riscv_isa::BEQInst *inst) {
            return super()->visit_beq_inst(inst);
        }

        RetT visit_bne_inst(const riscv_isa::BNEInst *inst) {
            return super()->visit_bne_inst(inst);
        }

        RetT visit_blt_inst(const riscv_isa::BLTInst *inst) {
            return super()->visit_blt_inst(inst);
        }

        RetT visit_bge_inst(const riscv_isa::BGEInst *inst) {
            return super()->visit_bge_inst(inst);
        }

        RetT visit_bltu_inst(const riscv_isa::BLTUInst *inst) {
            return super()->visit_bltu_inst(inst);
        }

        RetT visit_bgeu_inst(const riscv_isa::BGEUInst *inst) {
            return super()->visit_bgeu_inst(inst);
        }

        void *get_host_pc(UXLenT guest_pc) {
            auto ptr = code_cache.find(guest_pc);

            if (ptr == code_cache.end()) {
                return nullptr;
            } else {
                return ptr->second;
            }
        }

        void dynamic_translate_execute() {
            UXLenT pc = sub_type()->get_pc();
            void *host_pc = get_host_pc(pc);

            if (host_pc == nullptr) { return; }

            struct dynamic_info info{
                    .int_reg = {},
                    .core = this,
                    .execute_cache = {execute_cache.start,
                                      execute_cache.end,
                                      reinterpret_cast<usize>(execute_cache.shift)},
                    .load_cache = {load_cache.start,
                                   load_cache.end,
                                   reinterpret_cast<usize>(load_cache.shift)},
                    .store_cache = {store_cache.start,
                                    store_cache.end,
                                    reinterpret_cast<usize>(store_cache.shift)},

#if defined(__RV_EXTENSION_A__)
                    .reserve_address = this->reserve_address,
                    .reserve_value = this->reserve_value,
#endif

                    .fast_call_return_addr = nullptr};

            for (usize i = 0; i < IntRegT::INTEGER_REGISTER_NUM; ++i) {
                info.int_reg[TranslateT::int_reg_guest_to_ir(i)] = sub_type()->get_x(i);
            }

            register usize rax asm ("rax") = reinterpret_cast<usize>(host_pc);
            register usize rdx asm ("rdx") = info.int_reg[IntRegT::RA];
            register usize rbx asm ("rbx") = info.int_reg[IntRegT::SP];
            register usize rcx asm ("rcx") = reinterpret_cast<usize>(&info);
            register usize rsi asm ("rsi") = info.int_reg[IntRegT::T0];
            register usize rdi asm ("rdi") = info.int_reg[IntRegT::T1];
            register usize r8 asm ("r8") = info.int_reg[IntRegT::A0];
            register usize r9 asm ("r9") = info.int_reg[IntRegT::A1];
            register usize r10 asm ("r10") = info.int_reg[IntRegT::A2];
            register usize r11 asm ("r11") = info.int_reg[IntRegT::A3];
            register usize r12 asm ("r12") = info.int_reg[IntRegT::A4];
            register usize r13 asm ("r13") = info.int_reg[IntRegT::A5];
            register usize r14 asm ("r14") = info.int_reg[IntRegT::A6];
            register usize r15 asm ("r15") = info.int_reg[IntRegT::A7];

            asm volatile (
            "push %%rbp;"
            "mov %%rcx, %%rbp;"
            "call *%%rax;"
            "pop %%rbp;"
            : "+r" (rax), "+r" (rdx), "+r" (rbx), "+r" (rcx), "+r" (rsi), "+r" (rdi),
            "+r" (r8), "+r" (r9), "+r" (r10), "+r" (r11),
            "+r" (r12), "+r" (r13), "+r" (r14), "+r" (r15)
            :
            :"cc", "memory"
            );

            info.int_reg[IntRegT::RA] = rdx;
            info.int_reg[IntRegT::SP] = rbx;
            info.int_reg[IntRegT::T0] = rsi;
            info.int_reg[IntRegT::T1] = rdi;
            info.int_reg[IntRegT::A0] = r8;
            info.int_reg[IntRegT::A1] = r9;
            info.int_reg[IntRegT::A2] = r10;
            info.int_reg[IntRegT::A3] = r11;
            info.int_reg[IntRegT::A4] = r12;
            info.int_reg[IntRegT::A5] = r13;
            info.int_reg[IntRegT::A6] = r14;
            info.int_reg[IntRegT::A7] = r15;

            pc = rax;

            for (usize i = 0; i < IntRegT::INTEGER_REGISTER_NUM; ++i) {
                sub_type()->set_x(i, info.int_reg[TranslateT::int_reg_guest_to_ir(i)]);
            }

            execute_cache.start = info.execute_cache.start;
            execute_cache.end = info.execute_cache.end;
            execute_cache.shift = reinterpret_cast<u8 *>(info.execute_cache.shift);

            load_cache.start = info.load_cache.start;
            load_cache.end = info.load_cache.end;
            load_cache.shift = reinterpret_cast<u8 *>(info.load_cache.shift);

            store_cache.start = info.store_cache.start;
            store_cache.end = info.store_cache.end;
            store_cache.shift = reinterpret_cast<u8 *>(info.store_cache.shift);

#if defined(__RV_EXTENSION_A__)
            this->reserve_value = info.reserve_value;
            this->reserve_address = info.reserve_address;
#endif

            sub_type()->jump_to_addr(pc);
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

//        void start() {
//            TranslateT translator{pcb, static_cast<UXLenT>(sub_type()->get_pc())};
//
//            translator.visit();
//
//            do {
//                sub_type()->dynamic_translate_execute();
//            } while (sub_type()->visit() || sub_type()->trap_handler());
//        }
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
