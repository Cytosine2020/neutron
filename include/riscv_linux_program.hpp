#ifndef NEUTRON_RISCV_LINUX_PROGRAM_HPP
#define NEUTRON_RISCV_LINUX_PROGRAM_HPP


#include <unistd.h>
#include <zconf.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <map>
#include <vector>

#include "elf_header.hpp"
#include "auxvec.hpp"


namespace neutron {
    template<typename UXLenT>
    struct AuxiliaryEntry {
        UXLenT type;
        UXLenT value;

        AuxiliaryEntry(UXLenT type, UXLenT value) : type{type}, value{value} {}
    };

    template<typename xlen=riscv_isa::xlen_trait>
    class LinuxProgram {
    private:
        using XLenT = typename xlen::XLenT;
        using UXLenT = typename xlen::UXLenT;

    public:
        static constexpr UXLenT MEM_BEGIN = 0x8000;
        static constexpr UXLenT MEM_END = 0xC0000000;

        static constexpr UXLenT STACK_END = 0xBFFFF000;
        static constexpr UXLenT STACK_SIZE = 0xA00000;

        static constexpr UXLenT MMAP_BEGIN = 0x80000000;
        static constexpr UXLenT MMAP_END = 0xBF5FB000;

        static constexpr UXLenT SAFE_AREA_SIZE = RISCV_PAGE_SIZE * 4;

        struct iovec {
            UXLenT iov_base;        /* Starting address */
            UXLenT iov_len;         /* Number of bytes to transfer */
        };

    private:
        struct MemArea {
            void *physical;
            UXLenT size;
            riscv_isa::MemoryProtection protection;
            // todo: add info
        };

        static bool str_start_with(const char *a, const char *b) { return strncmp(a, b, strlen(b)) == 0; }

        bool load_section(elf::MappedFileVisitor &visitor, elf32::ExecutableHeader *loadable, XLenT shift) {
            if (MEM_END <= loadable->mem_size || loadable->virtual_address >= MEM_END - loadable->mem_size)
                return false;

            bool execute = loadable->is_execute();
            bool write = loadable->is_write();
            bool read = loadable->is_read();

            riscv_isa::MemoryProtection guest_protect;

            if (execute) {
                if (write) guest_protect = riscv_isa::EXECUTE_READ_WRITE;
                else if (read) guest_protect = riscv_isa::EXECUTE_READ;
                else guest_protect = riscv_isa::EXECUTE;
            } else {
                if (write) guest_protect = riscv_isa::READ_WRITE;
                else guest_protect = riscv_isa::READ;
            }

            return memory_map(
                    loadable->virtual_address + shift,
                    loadable->mem_size,
                    guest_protect,
                    true,
                    visitor.get_fd(),
                    loadable->offset,
                    loadable->file_size) != 0;
        }

        bool load_stack() {
            // todo: rand
            void *stack = mmap(nullptr, STACK_SIZE, PROT_WRITE | PROT_READ, MAP_ANONYMOUS | MAP_SHARED, -1, 0);

            if (stack == MAP_FAILED) return false;

            return add_map(STACK_END - STACK_SIZE, stack, STACK_SIZE, riscv_isa::READ_WRITE, true) != 0;
        }

        bool load_aux_vec(int argc, char **argv, char **envp, int auxc, void *auxv) {
            UXLenT stack_ptr = STACK_END - xlen::XLEN_BYTE;

            // arguments
            std::vector<UXLenT> arg_vec{};
            arg_vec.reserve(argc + 1);
            usize arg_vec_size = sizeof(UXLenT) * (argc + 1);

            for (usize i = 0; i < static_cast<usize>(argc); ++i) {
                usize len = strlen(argv[i]);
                stack_ptr -= len + 1;

                if (memory_copy_to_guest(stack_ptr, argv[i], len) != len) { return false; }

                arg_vec[i] = stack_ptr;
            }

            arg_vec[argc] = 0;

            // environment

            std::map<std::string, std::string> environment{}, new_environment{};

            for (usize envc = 0; envp[envc] != nullptr; ++envc) {
                char *key = envp[envc];
                char *value = strchr(envp[envc], '=');

                environment.emplace(std::string{key, value}, std::string{value + 1});
            }

            environment.erase("LD_LIBRARY_PATH");
            environment.erase("RISCV_SYSROOT");

            for (auto pair: environment) {
                if (pair.first.rfind("NEUTRON_", 0) == 0) {
                    new_environment[pair.first.substr(strlen("NEUTRON_"))] = pair.second;
                } else {
                    new_environment[pair.first] = pair.second;
                }
            }

            std::vector<UXLenT> env_vec{};
            env_vec.reserve(new_environment.size() + 1);
            usize env_vec_count = 0;

            for (auto pair: new_environment) {
                std::string env = pair.first + '=' + pair.second;
                const char *real_env = env.c_str();
                usize len = env.length();

                stack_ptr -= len + 1;

                if (memory_copy_to_guest(stack_ptr, real_env, len) != len) { return false; }
                env_vec[env_vec_count++] = stack_ptr;
            }

            env_vec[env_vec_count++] = 0;
            usize env_vec_size = sizeof(UXLenT) * env_vec_count;

            // auxiliary vector

            usize aux_vec_size = sizeof(AuxiliaryEntry<UXLenT>) * auxc;

            // align to XLEN
            stack_ptr &= ~(xlen::XLEN_BYTE - 1);

            // auxvec
            stack_ptr -= aux_vec_size;
            if (memory_copy_to_guest(stack_ptr, auxv, aux_vec_size) != aux_vec_size) { return false; }

            // envp
            stack_ptr -= env_vec_size;
            if (memory_copy_to_guest(stack_ptr, env_vec.data(), env_vec_size) != env_vec_size) { return false; }

            // argv
            stack_ptr -= arg_vec_size;
            if (memory_copy_to_guest(stack_ptr, arg_vec.data(), arg_vec_size) != arg_vec_size) { return false; }

            // argc
            stack_ptr -= xlen::XLEN_BYTE;
            auto ptr = address_write<u32>(stack_ptr);
            if (ptr == nullptr) return false;
            *ptr = argc;

            int_reg.set_x(riscv_isa::IntegerRegister<xlen>::SP, stack_ptr);

            return true;
        }

        XLenT load_program(elf::MappedFileVisitor &visitor, elf32::ELFHeader *header) {
            std::vector<elf32::ExecutableHeader *> elf_load{};

            for (auto &program: header->programs(visitor)) {
                auto *loadable = elf32::ProgramHeader::cast<elf32::ExecutableHeader>(&program, visitor);
                if (loadable != nullptr) elf_load.emplace_back(loadable);
            }

            UXLenT elf_start = -RISCV_PAGE_SIZE, elf_end = 0;

            for (auto &loadable: elf_load) {
                elf_start = std::min(elf_start, loadable->virtual_address);
                if (MEM_END - loadable->mem_size < loadable->virtual_address) return -header->entry_point;
                elf_end = std::max(elf_end, loadable->mem_size + loadable->virtual_address);
            }

            if (elf_start >= elf_end) { return -header->entry_point; }

            elf_start = elf_start / RISCV_PAGE_SIZE * RISCV_PAGE_SIZE;
            elf_end = divide_ceil(elf_end, RISCV_PAGE_SIZE) * RISCV_PAGE_SIZE;

            XLenT shift = brk - elf_start; // todo: rand
            brk += elf_end - elf_start;

            for (auto &loadable: elf_load) {
                if (!load_section(visitor, loadable, shift)) {
                    return -header->entry_point;
                }
            }

            return shift;
        }

        UXLenT memory_map(
                UXLenT addr, UXLenT mem_len, riscv_isa::MemoryProtection prot, bool fix,
                int fd, size_t offset, size_t file_len
        ) {
            UXLenT mem_addr = addr;
            UXLenT mem_addr_map = mem_addr / RISCV_PAGE_SIZE * RISCV_PAGE_SIZE;
            UXLenT start_padding = mem_addr - mem_addr_map;
            UXLenT mem_size = mem_len;
            mem_size += start_padding;
            UXLenT mem_page = divide_ceil(mem_size, RISCV_PAGE_SIZE);
            if (mem_page >= xlen::UXLenMax / RISCV_PAGE_SIZE) return 0;
            UXLenT mem_map = mem_page * RISCV_PAGE_SIZE;

            void *mem_ptr = nullptr;
            int map_prot = 0;
            int file_map_flag = MAP_PRIVATE;

            if ((prot & riscv_isa::R_BIT) > 0) {
                map_prot |= PROT_READ;
            }

            UXLenT file_map = 0, file_size = 0, file_addr = 0;

            if (fd != -1) {
                // todo: file not page aligned
                if ((offset - addr) % RISCV_PAGE_SIZE != 0) return 0;
                file_addr = offset - start_padding;
                file_size = file_len < mem_len ? file_len : mem_len;
                file_size += start_padding;
                UXLenT file_page = divide_ceil(file_size, RISCV_PAGE_SIZE);
                file_map = file_page * RISCV_PAGE_SIZE;
            }

            if ((prot & riscv_isa::W_BIT) > 0) {
                map_prot |= PROT_WRITE;
            }

            if (fd != -1) {
                if (start_padding > 0 || file_map > file_size) {
                    map_prot |= PROT_WRITE;
                }
            }

            if (fd == -1 || mem_map > file_map) {
                mem_ptr = mmap(nullptr, mem_map, map_prot, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
                if (mem_ptr == MAP_FAILED) return 0;
                file_map_flag |= MAP_FIXED;
            }

            if (fd != -1) {
                void *file_ptr = mmap(mem_ptr, file_map, map_prot, file_map_flag, fd, file_addr);
                if (file_ptr == MAP_FAILED) {
                    munmap(mem_ptr, mem_map);
                    return 0;
                }
                mem_ptr = file_ptr;

                if (start_padding > 0) memset(static_cast<u8 *>(mem_ptr), 0, start_padding);
                if (file_map > file_size) memset(static_cast<u8 *>(mem_ptr) + file_size, 0, file_map - file_size);

                if ((prot & riscv_isa::W_BIT) == 0) {
                    if (start_padding > 0 || file_map > file_size) {
                        mprotect(mem_ptr, mem_map, PROT_READ);
                    }
                }
            }

            if (debug) {
                debug_stream << "file: " << file_addr << ':' << file_addr + file_map
                             << "; mem: " << mem_addr_map << ':' << mem_addr_map + mem_map << std::endl;
            }

            return add_map(mem_addr_map, mem_ptr, mem_map, prot, fix);
        }

        usize host_page_size;
        std::map<UXLenT, MemArea> mem_areas;
        UXLenT brk;
        UXLenT start_brk, end_brk;
        std::ostream &debug_stream;
        bool debug;

    public:
        riscv_isa::IntegerRegister<riscv_isa::xlen_trait> int_reg;
        XLenT pc;

        LinuxProgram() :
                host_page_size{0}, mem_areas{}, brk{MEM_BEGIN},
                debug_stream{std::cout}, debug{true}, int_reg{}, pc{0} {
            mem_areas.emplace(0, MemArea{nullptr, MEM_BEGIN, riscv_isa::NOT_PRESENT});
            mem_areas.emplace(0xC0000000, MemArea{nullptr, 0x40000000, riscv_isa::NOT_PRESENT});
        }

        LinuxProgram(const LinuxProgram &other) = delete;

        LinuxProgram &operator=(const LinuxProgram &other) = delete;

        bool load_elf(const char *elf_name, int argc, char **argv, char **envp) {
            host_page_size = sysconf(_SC_PAGE_SIZE);
            u32 clock_per_second = sysconf(_SC_CLK_TCK);
            if (host_page_size <= 0) return false;

            /// get elf header

            auto elf_visitor = elf::MappedFileVisitor::open_elf(elf_name);
            if (elf_visitor.get_fd() == -1) neutron_abort("Failed to open ELF file!");

            auto *elf_header = elf32::ELFHeader::read(elf_visitor);
//            if (elf_header == nullptr || elf_header->file_type != elf32::ELFHeader::EXECUTABLE) return false;

            /// get first interpreter files

            elf::MappedFileVisitor int_visitor{};
            elf32::ELFHeader *int_header = nullptr;

            for (auto &program: elf_header->programs(elf_visitor)) {
                auto *inter_path_name = elf32::ProgramHeader::cast<elf32::InterPathHeader>(&program, elf_visitor);
                if (inter_path_name == nullptr) continue;

                std::string sysroot = std::getenv("RISCV_SYSROOT") ?: "";

                auto lib_path = sysroot + inter_path_name->get_path_name(elf_visitor);
                int_visitor = elf::MappedFileVisitor::open_elf(lib_path.c_str());
                if (int_visitor.get_fd() == -1) return false;

                int_header = elf32::ELFHeader::read(int_visitor);
//                if (int_header == nullptr || int_header->file_type != elf32::ELFHeader::SHARED) return false;

                break;
            }

            /// load elf

            XLenT elf_shift = load_program(elf_visitor, elf_header);
            UXLenT elf_entry = elf_header->entry_point + elf_shift;
            if (elf_entry == 0) return false;

            if (debug) { debug_stream << "elf shift: " << elf_shift << std::endl; }

            UXLenT elf_header_addr;

            for (auto &program: elf_header->programs(elf_visitor)) {
                if (elf_header->program_header_offset > program.offset &&
                    elf_header->program_header_offset - program.offset < program.file_size) {

                    elf_header_addr = elf_header->program_header_offset - program.offset + program.virtual_address;
                    elf_header_addr += elf_shift;
                }
            }

            /// load interpreter files

            XLenT int_shift = 0;
            UXLenT int_entry = 0;

            if (int_header != nullptr) {
                int_shift = load_program(int_visitor, int_header);
                int_entry = int_header->entry_point + int_shift;
                if (int_entry == 0) return false;

                if (debug) { debug_stream << "int_shift: " << int_shift << std::endl; }
            }

            /// load stack

            start_brk = brk;
            end_brk = STACK_END - STACK_SIZE;

            if (!load_stack()) return false;

            /// build auxiliary vectors

            std::vector<AuxiliaryEntry<UXLenT>> auxv{};

            auxv.emplace_back(AT_PAGESZ, RISCV_PAGE_SIZE);
            auxv.emplace_back(AT_CLKTCK, clock_per_second);
            auxv.emplace_back(AT_PHDR, elf_header_addr);
            auxv.emplace_back(AT_PHENT, elf_header->program_header_size);
            auxv.emplace_back(AT_PHNUM, elf_header->program_header_num);
            if (int_header != nullptr) {
                auxv.emplace_back(AT_BASE, int_shift);
            }
            auxv.emplace_back(AT_FLAGS, 0);
            auxv.emplace_back(AT_ENTRY, elf_entry);
            auxv.emplace_back(AT_UID, getuid());
            auxv.emplace_back(AT_EUID, geteuid());
            auxv.emplace_back(AT_GID, getgid());
            auxv.emplace_back(AT_EGID, getegid());
//            auxv.emplace_back(AT_SECURE,	bprm->secureexec); // todo
//            auxv.emplace_back(AT_EXECFN,	bprm->exec); // todo
            auxv.emplace_back(AT_NULL, 0);

            if (!load_aux_vec(argc, argv, envp, auxv.size(), auxv.data())) return false;

            /// initialize registers
            pc = static_cast<XLenT>(int_header == nullptr ? elf_entry : int_entry);
            return (pc & (RISCV_IALIGN / 8 - 1)) == 0; // check instruction align
        }

        /// must be aligned
        template<typename T>
        T *address_read(UXLenT addr) {
            auto before = --mem_areas.upper_bound(addr);
            if (addr - before->first >= before->second.size) return nullptr;
            if ((before->second.protection & riscv_isa::R_BIT) == 0) return nullptr;
            return reinterpret_cast<T *>(static_cast<u8 *>(before->second.physical) + (addr - before->first));
        }

        /// must be aligned
        template<typename T>
        T *address_write(UXLenT addr) {
            auto before = --mem_areas.upper_bound(addr);
            if (addr - before->first >= before->second.size) return nullptr;
            if ((before->second.protection & riscv_isa::W_BIT) == 0) return nullptr;
            return reinterpret_cast<T *>(static_cast<u8 *>(before->second.physical) + (addr - before->first));
        }

        /// must be aligned
        template<typename T>
        T *address_execute(UXLenT addr) {
            auto before = --mem_areas.upper_bound(addr);
            if (addr - before->first >= before->second.size) return nullptr;
            if ((before->second.protection & riscv_isa::X_BIT) == 0) return nullptr;
            return reinterpret_cast<T *>(static_cast<u8 *>(before->second.physical) + (addr - before->first));
        }

        UXLenT memory_copy_to_guest(UXLenT dest, const void *src, UXLenT size) {
            if (MEM_END - dest < size) return 0;

            UXLenT count = 0;

            while (size > 0) {
                auto before = --mem_areas.upper_bound(dest);
                if (dest - before->first >= before->second.size) return 0;
                if ((before->second.protection & riscv_isa::W_BIT) == 0) return 0;

                UXLenT byte = std::min(before->second.size, size);
                memcpy(reinterpret_cast<u8 *>(before->second.physical) - before->first + dest, src, byte);

                count += byte;
                dest += byte;
                src = reinterpret_cast<const u8 *>(src) + byte;
                size -= byte;
            }

            return count;
        }

        UXLenT memory_copy_from_guest(void *dest, UXLenT src, UXLenT size) {
            if (MEM_END - src < size) return 0;

            UXLenT count = 0;

            while (size > 0) {
                auto before = --mem_areas.upper_bound(src);
                if (src - before->first >= before->second.size) return 0;
                if ((before->second.protection & riscv_isa::R_BIT) == 0) return 0;

                UXLenT byte = std::min(before->second.size, size);
                memcpy(dest, reinterpret_cast<u8 *>(before->second.physical) - before->first + src, byte);

                count += byte;
                dest = reinterpret_cast<u8 *>(src) + byte;
                src += byte;
                size -= byte;
            }

            return count;
        }

        bool memory_convert_io_vec(UXLenT iov, UXLenT iovcnt, UXLenT prot, std::vector<::iovec> &buf) {
            bool ret = false;

            auto *vec = new iovec[iovcnt]{};
            usize vec_size = iovcnt * sizeof(iovec);

            if (memory_copy_from_guest(vec, iov, vec_size) == vec_size) {
                buf.reserve(iovcnt);

                for (usize i = 0; i < iovcnt; ++i) {
                    UXLenT base = vec[i].iov_base;
                    UXLenT size = vec[i].iov_len;

                    while (size > 0) {
                        auto before = --mem_areas.upper_bound(base);
                        if (base - before->first >= before->second.size) goto end;
                        if ((before->second.protection & prot) == 0) goto end;

                        UXLenT byte = std::min(before->second.size, size);

                        buf.emplace_back(::iovec{
                                reinterpret_cast<u8 *>(before->second.physical) - before->first + base,
                                byte
                        });

                        base += byte;
                        size -= byte;
                    }
                }

                ret = true;
            }

            end:

            delete[] vec; // todo

            return ret;
        }

        bool memory_get_vector(UXLenT base, UXLenT size, UXLenT prot, std::vector<::iovec> &buf) {
            while (size > 0) {
                auto before = --mem_areas.upper_bound(base);
                if (base - before->first >= before->second.size) return false;
                if ((before->second.protection & prot) == 0) return false;

                UXLenT byte = std::min(before->second.size, size);

                buf.emplace_back(::iovec{
                        reinterpret_cast<u8 *>(before->second.physical) - before->first + base,
                        byte
                });

                base += byte;
                size -= byte;
            }

            return true;
        }

        bool string_copy_from_guest(UXLenT src, std::string &buf) {
            UXLenT addr = src; // todo: optimize
            char *ptr = nullptr;

            do {
                ptr = address_read<char>(addr++);
                if (ptr == nullptr) { return false; }
            } while (*ptr != '\0');

            usize len = addr - src;
            char *dest = new char[len];

            if (memory_copy_from_guest(dest, src, len) != len) { neutron_unreachable(""); }

            buf = dest;

            delete[] dest; // todo

            return true;
        }
        /// must be aligned to page
        UXLenT add_map(UXLenT offset, void *src, UXLenT length, riscv_isa::MemoryProtection protection, bool fix) {
            if (MEM_END - length < offset) return 0;

            if (offset == 0) {
                if (fix) {
                    return 0;
                } else {
                    offset = MMAP_BEGIN;
                }
            }

            auto before = --mem_areas.upper_bound(offset);

            if (fix) {
                if (offset - before->first < before->second.size) return 0;
                if (++before != mem_areas.end() && before->first < offset + length) return 0;

                mem_areas.emplace(offset, MemArea{src, length, protection});

                return offset;
            } else {
                auto prev = before;
                auto next = before;
                ++next;

                while (next != mem_areas.end()) {
                    usize interval = next->first - prev->second.size - prev->first - 2 * SAFE_AREA_SIZE;

                    if (interval >= length) {
                        if (offset + length > next->first - SAFE_AREA_SIZE) {
                            offset = next->first - SAFE_AREA_SIZE - length;
                        } else if (prev->first + prev->second.size > offset - SAFE_AREA_SIZE) {
                            offset = prev->first + prev->second.size + SAFE_AREA_SIZE;
                        }

                        mem_areas.emplace(offset, MemArea{src, length, protection});

                        return offset;
                    }

                    ++prev;
                    ++next;
                }

                prev = before;
                next = before;
                --prev;

                while (prev != mem_areas.begin()) {
                    usize interval = next->first - prev->second.size - prev->first - 2 * SAFE_AREA_SIZE;

                    if (interval >= length) {
                        if (offset + length > next->first - SAFE_AREA_SIZE) {
                            offset = next->first - SAFE_AREA_SIZE - length;
                        } else if (prev->first + prev->second.size > offset - SAFE_AREA_SIZE) {
                            offset = prev->first + prev->second.size + SAFE_AREA_SIZE;
                        }

                        mem_areas.emplace(offset, MemArea{src, length, protection});

                        return offset;
                    }

                    --next;
                    --prev;
                }
            }

            return 0;
        }

        UXLenT set_brk(UXLenT addr) {
            if (addr < start_brk || addr > end_brk) return brk;

            if (addr < brk) {
                brk = addr;
                return brk;
            }

            UXLenT addr_page = divide_ceil(addr, RISCV_PAGE_SIZE) * RISCV_PAGE_SIZE;
            UXLenT brk_page = divide_ceil(brk, RISCV_PAGE_SIZE) * RISCV_PAGE_SIZE;

            if (addr_page <= brk_page) return brk;
            void *area = mmap(nullptr, addr_page - brk_page, PROT_READ | PROT_WRITE,
                              MAP_SHARED | MAP_ANONYMOUS, -1, 0);
            if (area == MAP_FAILED) return brk;
            if (add_map(brk_page, area, addr_page - brk_page, riscv_isa::READ_WRITE, true) == 0) return brk;

            brk = addr;

            return brk;
        }

        ~LinuxProgram() {
            for (auto &area: mem_areas) {
                if (area.second.physical != nullptr) {
                    munmap(area.second.physical, area.second.size);
                }
            }
        }
    };
}


#endif //NEUTRON_RISCV_LINUX_PROGRAM_HPP
