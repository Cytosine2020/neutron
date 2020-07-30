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
        static constexpr UXLenT R_BIT = 2;
        static constexpr UXLenT W_BIT = 4;
        static constexpr UXLenT X_BIT = 8;

        enum MemoryProtection : UXLenT {
            NOT_PRESENT = 0,
            READ = R_BIT,
            READ_WRITE = R_BIT | W_BIT,
            EXECUTE = X_BIT,
            EXECUTE_READ = X_BIT | R_BIT,
            EXECUTE_READ_WRITE = X_BIT | R_BIT | W_BIT,
        };

        static constexpr UXLenT MEM_END = 0xC0000000;
        static constexpr UXLenT MEM_BEGIN = 0x8000;

        static constexpr UXLenT STACK_END = 0xBFFFF000;
        static constexpr UXLenT STACK_SIZE = 0xA00000;

        static constexpr UXLenT MMAP_END = 0xBF5FB000;

        static constexpr UXLenT SAFE_AREA_SIZE = RISCV_PAGE_SIZE * 4;

    private:
        struct MemArea {
            void *physical;
            UXLenT size;
            MemoryProtection protection;
            // todo: add info
        };

        bool load_section(elf::MappedFileVisitor &visitor, elf32::ExecutableHeader *loadable, XLenT shift) {
            if (MEM_END <= loadable->mem_size || loadable->virtual_address >= MEM_END - loadable->mem_size)
                return false;

            bool execute = loadable->is_execute();
            bool write = loadable->is_write();
            bool read = loadable->is_read();

            MemoryProtection guest_protect;

            if (execute) {
                if (write) guest_protect = LinuxProgram::EXECUTE_READ_WRITE;
                else if (read) guest_protect = LinuxProgram::EXECUTE_READ;
                else guest_protect = LinuxProgram::EXECUTE;
            } else {
                if (write) guest_protect = LinuxProgram::READ_WRITE;
                else guest_protect = LinuxProgram::READ;
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

            return add_map(STACK_END - STACK_SIZE, stack, STACK_SIZE, READ_WRITE, true) != 0;
        }

        bool load_aux_vec(int argc, char **argv, char **envp, int auxc, void *auxv) {
            UXLenT stack_ptr = STACK_END - xlen::XLEN_BYTE;

            // arguments
            std::vector<UXLenT> arg_vec(argc + 1);
            usize arg_vec_size = sizeof(UXLenT) * (argc + 1);

            for (usize i = 0; i < static_cast<usize>(argc); ++i) {
                usize len = strlen(argv[i]);
                stack_ptr -= len + 1;

                if (memory_copy_to_guest(stack_ptr, argv[i], len) != len) { return false; }

                arg_vec[i] = stack_ptr;
            }

            arg_vec[argc] = 0;

            // enviroment todo: remove RISCV_SYSROOT

            usize envc = 0;
            while (envp[envc] != nullptr) { ++envc; }

            std::vector<UXLenT> env_vec(envc + 1);
            usize env_vec_size = sizeof(UXLenT) * (envc + 1);

            for (usize i = 0; i < envc; ++i) {
                usize len = strlen(envp[i]);

                if (strncmp(envp[i], "NEUTRON_", 8) == 0) {
                    len -= 8;
                    stack_ptr -= len + 1;
                    if (memory_copy_to_guest(stack_ptr, envp[i] + 8, len) != len) { return false; }
                } else {
                    stack_ptr -= len + 1;
                    if (memory_copy_to_guest(stack_ptr, envp[i], len) != len) { return false; }
                }

                env_vec[i] = stack_ptr;
            }

            env_vec[envc] = 0;

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

        /// must be aligned to page
        UXLenT add_map(UXLenT offset, void *src, UXLenT length, MemoryProtection protection, bool fix) {
            if (MEM_END - length < offset) return 0;

            if (offset == 0) {
                if (fix) {
                    return 0;
                } else {
                    offset = MMAP_END;
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

                while (next->first != MEM_END) {
                    if (offset - prev->first >= prev->second.size - SAFE_AREA_SIZE &&
                        before->first + SAFE_AREA_SIZE <= offset + length) {
                        offset += SAFE_AREA_SIZE;

                        mem_areas.emplace(offset, MemArea{src, length, protection});

                        return offset;
                    }

                    ++prev;
                    ++next;

                    offset = prev->first + prev->second.size;
                }

                prev = before;
                next = before;
                --prev;

                while (prev != mem_areas.begin()) {
                    if (offset - prev->first >= prev->second.size - SAFE_AREA_SIZE &&
                        before->first + SAFE_AREA_SIZE <= offset + length) {
                        offset += SAFE_AREA_SIZE;

                        mem_areas.emplace(offset, MemArea{src, length, protection});

                        return offset;
                    }

                    --next;
                    --prev;

                    offset = prev->first + prev->second.size;
                }
            }

            return 0;
        }

        usize host_page_size;
        std::map<UXLenT, MemArea> mem_areas;
        UXLenT brk;
        UXLenT start_brk, end_brk;
        bool debug;

    public:
        riscv_isa::IntegerRegister<riscv_isa::xlen_trait> int_reg;
        XLenT pc;

        LinuxProgram() : host_page_size{0}, mem_areas{}, brk{MEM_BEGIN}, debug{true}, int_reg{}, pc{0} {
            mem_areas.emplace(0, MemArea{nullptr, MEM_BEGIN, NOT_PRESENT});
            mem_areas.emplace(0xC0000000, MemArea{nullptr, 0x40000000, NOT_PRESENT});
        }

        LinuxProgram(const LinuxProgram &other) = delete;

        LinuxProgram &operator=(const LinuxProgram &other) = delete;

        bool load_elf(elf::MappedFileVisitor &elf_visitor, int argc, char **argv, char **envp) {
            host_page_size = sysconf(_SC_PAGE_SIZE);
            u32 clock_per_second = sysconf(_SC_CLK_TCK);
            if (host_page_size <= 0) return false;

            /// get elf header

            auto *elf_header = elf32::ELFHeader::read(elf_visitor);
            if (elf_header == nullptr || elf_header->file_type != elf32::ELFHeader::EXECUTABLE) return false;

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
                if (int_header == nullptr || int_header->file_type != elf32::ELFHeader::SHARED) return false;

                break;
            }

            /// load elf

            XLenT elf_shift = load_program(elf_visitor, elf_header);
            UXLenT elf_entry = elf_header->entry_point + elf_shift;
            if (elf_entry == 0) return false;

            if (debug) {
                std::cout << "elf shift: " << elf_shift << std::endl;
            }


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

                if (debug) {
                    std::cout << "int_shift: " << int_shift << std::endl;
                }

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
            if ((before->second.protection & R_BIT) == 0) return nullptr;
            return reinterpret_cast<T *>(static_cast<u8 *>(before->second.physical) + (addr - before->first));
        }

        /// must be aligned
        template<typename T>
        T *address_write(UXLenT addr) {
            auto before = --mem_areas.upper_bound(addr);
            if (addr - before->first >= before->second.size) return nullptr;
            if ((before->second.protection & W_BIT) == 0) return nullptr;
            return reinterpret_cast<T *>(static_cast<u8 *>(before->second.physical) + (addr - before->first));
        }

        /// must be aligned
        template<typename T>
        T *address_execute(UXLenT addr) {
            auto before = --mem_areas.upper_bound(addr);
            if (addr - before->first >= before->second.size) return nullptr;
            if ((before->second.protection & X_BIT) == 0) return nullptr;
            return reinterpret_cast<T *>(static_cast<u8 *>(before->second.physical) + (addr - before->first));
        }

        UXLenT memory_copy_to_guest(UXLenT dest, const void *src, UXLenT size) {
            if (MEM_END - dest < size) return 0;

            UXLenT count = 0;

            while (size > 0) {
                auto before = --mem_areas.upper_bound(dest);
                if (dest - before->first >= before->second.size) return 0;
                if ((before->second.protection & W_BIT) == 0) return count;

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
                if ((before->second.protection & R_BIT) == 0) return count;

                UXLenT byte = std::min(before->second.size, size);
                memcpy(dest, reinterpret_cast<u8 *>(before->second.physical) - before->first + src, byte);

                count += byte;
                dest = reinterpret_cast<u8 *>(src) + byte;
                src += byte;
                size -= byte;
            }

            return count;
        }

        /// user are responsible for release the string
        char *string_copy_from_guest(UXLenT src) {
            UXLenT addr = src;
            char *ptr = nullptr;

            do {
                ptr = address_read<char>(addr++);
                if (ptr == nullptr) { return nullptr; }
            } while (*ptr != '\0');

            usize len = addr - src;
            char *dest = new char[len];

            if (memory_copy_from_guest(dest, src, len) != len) { neutron_unreachable(""); }

            return dest;
        }

        UXLenT memory_map(
                UXLenT addr, UXLenT mem_len, MemoryProtection prot, bool fix,
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

            if ((prot & R_BIT) > 0) {
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


            if ((prot & W_BIT) > 0) {
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

                if ((prot & W_BIT) == 0) {
                    if (start_padding > 0 || file_map > file_size) {
                        mprotect(mem_ptr, mem_map, PROT_READ);
                    }
                }
            }

            if (debug) {
                std::cout << "file: " << file_addr << ':' << file_addr + file_map
                          << "; mem: " << mem_addr_map << ':' << mem_addr_map + mem_map << std::endl;
            }

            return add_map(mem_addr_map, mem_ptr, mem_map, prot, fix);
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
            if (add_map(brk_page, area, addr_page - brk_page, READ_WRITE, true) == 0) return brk;

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
