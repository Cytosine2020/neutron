#ifndef NEUTRON_RISCV_LINUX_PROGRAM_HPP
#define NEUTRON_RISCV_LINUX_PROGRAM_HPP


#include <unistd.h>
#include <zconf.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>

#include <map>
#include <unordered_set>
#include <vector>
#include <iomanip>
#include <random>
#include <sstream>

#include "riscv_isa_utility.hpp"
#include "register/register.hpp"

#include "elf_header.hpp"
#include "linux_std.hpp"
#include "neutron_argument.hpp"


namespace neutron {
template<typename xlen>
struct _PlatformString;

template<>
struct _PlatformString<riscv_isa::xlen_32_trait> {
    static const char *inner() { return "riscv32"; }
};

template<>
struct _PlatformString<riscv_isa::xlen_64_trait> {
    static const char *inner() { return "riscv64"; }
};


template<typename xlen>
class LinuxProgram {
private:
    using XLenT = typename xlen::XLenT;
    using UXLenT = typename xlen::UXLenT;

public:
    static constexpr UXLenT MEM_BEGIN = 0x8000;
    static constexpr UXLenT MEM_END = 0xC0000000;

    static constexpr UXLenT STACK_END = 0xBFFFF000;
    static constexpr UXLenT STACK_SIZE = 0xA00000;

    static constexpr UXLenT MMAP_BEGIN = 0x90000000;
    static constexpr UXLenT MMAP_END = 0xBF5FB000;

    static constexpr UXLenT GUARD_PAGE_SIZE = RISCV_PAGE_SIZE * 4;

    static const char *platform_string() { return _PlatformString<xlen>::inner(); }

    struct MemoryArea {
        UXLenT start;
        UXLenT end;
        u8 *shift;
    };

private:
    struct MemArea {
        void *physical;
        UXLenT size;
        riscv_isa::MemoryProtection protection;
    };

    void drop() {
        for (auto &area: mem_areas) {
            if (area.second.physical != nullptr) {
                if (munmap(area.second.physical, area.second.size) != 0) {
                    std::stringstream buf{};

                    buf << std::hex << "Memory area 0x"
                        << reinterpret_cast<usize>(area.second.physical) << " to 0x"
                        << reinterpret_cast<usize>(area.second.physical) + area.second.size
                        << " failed to release!"
                        << std::dec << std::endl;

                    neutron_warn(buf.str().c_str());
                }
            }
        }

        for (auto &item: fd_map) { close(item.second); }
    }

    riscv_isa::MemoryProtection prot_convert_to_guest(int prot) {
        if ((prot & NEUTRON_PROT_EXEC) > 0) {
            if ((prot & NEUTRON_PROT_WRITE) > 0) {
                return riscv_isa::MemoryProtection::EXECUTE_READ_WRITE;
            } else if ((prot & PROT_READ) > 0) {
                return riscv_isa::MemoryProtection::EXECUTE_READ;
            } else {
                return riscv_isa::MemoryProtection::EXECUTE;
            }
        } else {
            if ((prot & NEUTRON_PROT_WRITE) > 0) {
                return riscv_isa::MemoryProtection::READ_WRITE;
            } else if ((prot & NEUTRON_PROT_READ) > 0) {
                return riscv_isa::MemoryProtection::READ;
            }
        }

        return riscv_isa::MemoryProtection::NOT_PRESENT;
    }

    int prot_convert_to_host(int prot) {
        if (gdb) {
            return PROT_READ | PROT_WRITE;
        } else {
            if ((prot & NEUTRON_PROT_EXEC) > 0) {
                if ((prot & NEUTRON_PROT_WRITE) > 0) {
                    return PROT_READ | PROT_WRITE;
                } else {
                    return PROT_READ;
                }
            } else {
                if ((prot & NEUTRON_PROT_WRITE) > 0) {
                    return PROT_READ | PROT_WRITE;
                } else if ((prot & NEUTRON_PROT_READ) > 0) {
                    return PROT_READ;
                }
            }
        }

        return PROT_NONE;
    }

    void add_map(UXLenT offset, void *src, UXLenT length, riscv_isa::MemoryProtection protection) {
        mem_areas.emplace(offset, MemArea{src, length, protection});
    }

    UXLenT guest_memory_allocate(UXLenT offset, UXLenT length) {
        if (MEM_END - length < offset) return 0;

        if (offset == 0) { offset = MMAP_BEGIN; }

        auto before = --mem_areas.upper_bound(offset);

        auto prev = before;
        auto next = before;
        ++next;

        while (next != mem_areas.end()) {
            if (next->first > length &&
                next->first - length >= prev->second.size + prev->first + 2 * GUARD_PAGE_SIZE) {
                if (offset + length > next->first - GUARD_PAGE_SIZE) {
                    offset = next->first - GUARD_PAGE_SIZE - length;
                } else if (prev->first + prev->second.size > offset - GUARD_PAGE_SIZE) {
                    offset = prev->first + prev->second.size + GUARD_PAGE_SIZE;
                }

                return offset;
            }

            ++prev;
            ++next;
        }

        prev = before;
        next = before;
        --prev;

        while (prev != mem_areas.begin()) {
            if (next->first > length &&
                next->first - length >= prev->second.size + prev->first + 2 * GUARD_PAGE_SIZE) {
                if (offset + length > next->first - GUARD_PAGE_SIZE) {
                    offset = next->first - GUARD_PAGE_SIZE - length;
                } else if (prev->first + prev->second.size > offset - GUARD_PAGE_SIZE) {
                    offset = prev->first + prev->second.size + GUARD_PAGE_SIZE;
                }

                return offset;
            }

            --next;
            --prev;
        }

        return 0;
    }

    bool load_section(elf::MappedFileVisitor &visitor,
                      elf::ExecutableHeader<UXLenT> *loadable, XLenT shift) {
        UXLenT mem_addr = loadable->virtual_address + shift;
        UXLenT file_addr = loadable->offset;
        if ((file_addr - mem_addr) % RISCV_PAGE_SIZE != 0) {
            return false; // segment not page aligned
        }
        UXLenT mem_addr_page = mem_addr / RISCV_PAGE_SIZE * RISCV_PAGE_SIZE;
        UXLenT start_padding = mem_addr - mem_addr_page;
        UXLenT file_addr_page = file_addr - start_padding;

        UXLenT mem_size = loadable->mem_size + start_padding;
        UXLenT file_size = loadable->file_size + start_padding;
        file_size = file_size < mem_size ? file_size : mem_size;
        UXLenT mem_size_page = divide_ceil(mem_size, RISCV_PAGE_SIZE) * RISCV_PAGE_SIZE;
        UXLenT file_size_page = divide_ceil(file_size, RISCV_PAGE_SIZE) * RISCV_PAGE_SIZE;

        riscv_isa::MemoryProtection guest_protect;

        if (loadable->is_execute()) {
            if (loadable->is_write()) {
                guest_protect = riscv_isa::MemoryProtection::EXECUTE_READ_WRITE;
            } else if (loadable->is_read()) {
                guest_protect = riscv_isa::MemoryProtection::EXECUTE_READ;
            } else {
                guest_protect = riscv_isa::MemoryProtection::EXECUTE;
            }
        } else {
            if (loadable->is_write()) {
                guest_protect = riscv_isa::MemoryProtection::READ_WRITE;
            } else if (loadable->is_read()) {
                guest_protect = riscv_isa::MemoryProtection::READ;
            } else {
                guest_protect = riscv_isa::MemoryProtection::NOT_PRESENT;
            }
        }

        void *mem_ptr = nullptr;
        int map_prot = gdb ? PROT_READ | PROT_WRITE : 0;
        int file_map_flag = MAP_PRIVATE;

        if ((static_cast<u8>(guest_protect) & riscv_isa::R_BIT) > 0) { map_prot |= PROT_READ; }

        if ((static_cast<u8>(guest_protect) & riscv_isa::W_BIT) > 0) { map_prot |= PROT_WRITE; }

        if (start_padding > 0 || file_size_page > file_size) { map_prot |= PROT_WRITE; }

        if (mem_size_page > file_size_page) {
            file_map_flag |= MAP_FIXED;
            mem_ptr = mmap(nullptr, mem_size_page, map_prot, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
            if (mem_ptr == MAP_FAILED) { return false; }
        }

        void *file_ptr = mmap(mem_ptr, file_size_page, map_prot, file_map_flag,
                              visitor.get_fd(), file_addr_page);
        if (file_ptr == MAP_FAILED) {
            munmap(mem_ptr, mem_size_page);
            return false;
        }
        mem_ptr = file_ptr;

        if (start_padding > 0) {
            memset(static_cast<u8 *>(mem_ptr), 0, start_padding);
        }

        if (file_size_page > file_size) {
            memset(static_cast<u8 *>(mem_ptr) + file_size, 0, file_size_page - file_size);
        }

        if (!gdb) {
            if ((static_cast<u8>(guest_protect) & riscv_isa::W_BIT) == 0) {
                if (start_padding > 0 || file_size_page > file_size) {
                    mprotect(mem_ptr, mem_size_page, PROT_READ);
                }
            }
        }

        add_map(mem_addr_page, mem_ptr, mem_size_page, guest_protect);

        return true;
    }

    bool load_aux_vec(const ArgumentT &argument, const EnviromentT &environment,
                      AuxiliaryT<UXLenT> &auxv) {
        UXLenT stack_ptr = STACK_END - xlen::XLEN_BYTE;

        // arguments
        std::vector<UXLenT> arg_vec(argument.size() + 1);
        usize arg_vec_count = 0;

        for (auto &item: argument) {
            usize len = item.size() + 1;
            stack_ptr -= len;

            if (!memory_copy_to_guest(stack_ptr, item.data(), len)) { return false; }

            arg_vec[arg_vec_count++] = stack_ptr;
        }

        arg_vec[arg_vec_count++] = 0;
        usize arg_vec_size = sizeof(UXLenT) * arg_vec_count;

        // environment

        std::vector<UXLenT> env_vec(environment.size() + 1);
        usize env_vec_count = 0;

        for (auto pair: environment) {
            std::string env = pair.first + '=' + pair.second;
            const char *real_env = env.c_str();
            usize len = env.length() + 1;

            stack_ptr -= len;

            if (!memory_copy_to_guest(stack_ptr, real_env, len)) { return false; }
            env_vec[env_vec_count++] = stack_ptr;
        }

        env_vec[env_vec_count++] = 0;
        usize env_vec_size = sizeof(UXLenT) * env_vec_count;

        // auxiliary vector

        // file name
        auxv.emplace_back(NEUTRON_AT_EXECFN, arg_vec[0]);

        // platform
        usize len = strlen(platform_string()) + 1;

        stack_ptr -= len;
        if (!memory_copy_to_guest(stack_ptr, platform_string(), len)) { return false; }
        auxv.emplace_back(NEUTRON_AT_PLATFORM, stack_ptr);

        // random
        std::random_device engine{};
        std::uniform_int_distribution<UXLenT> dist{};
        UXLenT rand = dist(engine);
        const char *string = reinterpret_cast<const char *>(&rand);
        len = sizeof(rand);

        stack_ptr -= len;
        if (!memory_copy_to_guest(stack_ptr, string, len)) { return false; }
        auxv.emplace_back(NEUTRON_AT_RANDOM, stack_ptr);
        auxv.emplace_back(NEUTRON_AT_NULL, 0);

        // align to XLEN todo: rand
        stack_ptr &= ~(xlen::XLEN_BYTE - 1);

        // auxvec
        usize aux_vec_size = sizeof(AuxiliaryEntry<UXLenT>) * auxv.size();

        stack_ptr -= aux_vec_size;
        if (!memory_copy_to_guest(stack_ptr, auxv.data(), aux_vec_size)) { return false; }

        // envp
        stack_ptr -= env_vec_size;
        if (!memory_copy_to_guest(stack_ptr, env_vec.data(), env_vec_size)) { return false; }

        // argv
        stack_ptr -= arg_vec_size;
        if (!memory_copy_to_guest(stack_ptr, arg_vec.data(), arg_vec_size)) { return false; }

        // argc
        stack_ptr -= xlen::XLEN_BYTE;
        auto ptr = address<UXLenT>(stack_ptr, riscv_isa::MemoryProtection::READ_WRITE);
        if (ptr == nullptr) { return false; }
        *ptr = arg_vec_count - 1;

        int_reg.set_x(riscv_isa::IntegerRegister<xlen>::SP, stack_ptr);

        return true;
    }

    XLenT
    load_program(elf::MappedFileVisitor &visitor, elf::ELFHeader<UXLenT> *header, bool is_exec) {
        std::vector<elf::ExecutableHeader<UXLenT> *> elf_load{};

        for (auto &program: header->programs(visitor)) {
            auto *loadable = elf::ProgramHeader<UXLenT>::template
            cast<elf::ExecutableHeader<UXLenT>>(&program, visitor);
            if (loadable != nullptr) elf_load.emplace_back(loadable);
        }

        UXLenT elf_start = -RISCV_PAGE_SIZE, elf_end = 0;

        for (auto &loadable: elf_load) {
            elf_start = std::min(elf_start, loadable->virtual_address);
            if (MEM_END - loadable->mem_size < loadable->virtual_address) {
                return -header->entry_point;
            }
            elf_end = std::max(elf_end, loadable->mem_size + loadable->virtual_address);
        }

        if (elf_start >= elf_end) { return -header->entry_point; }

        elf_start = elf_start / RISCV_PAGE_SIZE * RISCV_PAGE_SIZE;
        elf_end = divide_ceil(elf_end, RISCV_PAGE_SIZE) * RISCV_PAGE_SIZE;

        XLenT shift;

        if (is_exec) {
            shift = 0; // todo: cannot relocate
            brk = elf_end + shift + GUARD_PAGE_SIZE;
            start_brk = brk;
        } else {
            UXLenT addr = guest_memory_allocate(MMAP_BEGIN, elf_end - elf_start);
            shift = addr - elf_start; // todo: rand
        }

        for (auto &loadable: elf_load) {
            if (!load_section(visitor, loadable, shift)) {
                return -header->entry_point;
            }
        }

        return shift;
    }

    std::string sysroot;
    std::map<UXLenT, MemArea> mem_areas;
    std::map<int, int> fd_map;
    std::unordered_set<int> close_execute; // contains guest fd
    int fd_free_lower_bound;
    UXLenT brk;
    UXLenT start_brk;

public:
    UXLenT elf_shift, elf_entry, elf_main, exit_value;
    riscv_isa::IntegerRegister<riscv_isa::xlen_trait> int_reg;
    XLenT pc;
    bool gdb;

    explicit LinuxProgram(bool gdb = false) :
            sysroot{std::getenv("RISCV_SYSROOT") ?: ""}, mem_areas{},
            fd_map{}, close_execute{}, fd_free_lower_bound{0}, brk{0}, start_brk{0},
            elf_shift{0}, elf_entry{0}, elf_main{0}, exit_value{0},
            int_reg{}, pc{0}, gdb{gdb} {
        add_map(0, nullptr, MEM_BEGIN, riscv_isa::MemoryProtection::NOT_PRESENT);
        add_map(0xC0000000, nullptr, 0x40000000, riscv_isa::MemoryProtection::NOT_PRESENT);
        fd_map.emplace(0, dup(0));
        fd_map.emplace(1, dup(1));
        fd_map.emplace(2, dup(2));

        // todo: regularize sysroot
    }

    LinuxProgram(const LinuxProgram &other) = delete;

    LinuxProgram &operator=(const LinuxProgram &other) = delete;

    bool
    load_elf(elf::MappedFileVisitor &elf_visitor, const ArgumentT &arg, const EnviromentT &env) {
        /// get elf header

        auto *elf_header = elf::ELFHeader<UXLenT>::read(elf_visitor);
        if (elf_header == nullptr || (elf_header->file_type != elf::ELFHeader<UXLenT>::EXECUTABLE &&
                                      elf_header->file_type != elf::ELFHeader<UXLenT>::SHARED)) {
            neutron_warn("file not elf or executable!");
            return false;
        }

        /// load stack

        void *stack = mmap(nullptr, STACK_SIZE, PROT_WRITE | PROT_READ, MAP_ANONYMOUS | MAP_SHARED,
                           -1, 0);

        if (stack == MAP_FAILED) {
            neutron_warn("stack failed to load!");
            return false;
        }

        add_map(STACK_END - STACK_SIZE, stack, STACK_SIZE, riscv_isa::MemoryProtection::READ_WRITE);

        /// get first interpreter files

        elf::MappedFileVisitor int_visitor{};
        elf::ELFHeader<UXLenT> *int_header = nullptr;

        for (auto &program: elf_header->programs(elf_visitor)) {
            auto *inter_path_name = elf::ProgramHeader<UXLenT>::template
            cast<elf::InterPathHeader<UXLenT>>(&program, elf_visitor);
            if (inter_path_name == nullptr) { continue; }

            auto lib_path = sysroot + inter_path_name->get_path_name(elf_visitor);
            int_visitor = elf::MappedFileVisitor::open_elf(lib_path.c_str());
            if (int_visitor.get_fd() == -1) {
                neutron_warn("failed to open elf interpreter!");
                return false;
            }

            int_header = elf::ELFHeader<UXLenT>::read(int_visitor);
            if (int_header == nullptr ||
                (int_header->file_type != elf::ELFHeader<UXLenT>::EXECUTABLE &&
                 int_header->file_type != elf::ELFHeader<UXLenT>::SHARED)) {
                neutron_warn("interpreter not elf or executable!");
                return false;
            }

            break;
        }

        /// load elf

        elf_shift = load_program(elf_visitor, elf_header, true);
        elf_entry = elf_header->entry_point + elf_shift;
        elf_main = elf_entry;
        if (elf_entry == 0) {
            neutron_warn("failed to load elf file!");
            return false;
        }

        // get the main function
        auto *symtab_header = elf_header->template
                get_section_header<elf::SymbolTableHeader<UXLenT>>(".symtab", elf_visitor);
        auto *strtab_header = elf_header->template
                get_section_header<elf::StringTableHeader<UXLenT>>(".strtab", elf_visitor);
        if (symtab_header != nullptr && strtab_header != nullptr) {
            auto symbol_table = symtab_header->get_table(elf_visitor);
            auto string_table = strtab_header->get_table(elf_visitor);

            for (auto &symbol: symbol_table) {
                if (strcmp(string_table.get_str(symbol.name), "main") == 0) {
                    elf_main = symbol.value + elf_shift;
                    break;
                }
            }
        }

        UXLenT elf_header_addr = 0;
        for (auto &program: elf_header->programs(elf_visitor)) {
            if (elf_header->program_header_offset > program.offset &&
                elf_header->program_header_offset - program.offset < program.file_size) {

                elf_header_addr = elf_header->program_header_offset - program.offset +
                                  program.virtual_address;
                elf_header_addr += elf_shift;
            }
        }

        /// load interpreter files

        UXLenT int_shift = 0;
        UXLenT int_entry = 0;

        if (int_header != nullptr) {
            int_shift = load_program(int_visitor, int_header, false);
            int_entry = int_header->entry_point + int_shift;
            if (int_entry == 0) {
                neutron_warn("failed to load interpreter!");
                return false;
            }
        }

        /// build auxiliary vectors

        std::vector<AuxiliaryEntry<UXLenT>> auxv{};

        auxv.emplace_back(NEUTRON_AT_PAGESZ, RISCV_PAGE_SIZE);
        auxv.emplace_back(NEUTRON_AT_CLKTCK, sysconf(_SC_CLK_TCK));
        auxv.emplace_back(NEUTRON_AT_PHDR, elf_header_addr);
        auxv.emplace_back(NEUTRON_AT_PHENT, elf_header->program_header_size);
        auxv.emplace_back(NEUTRON_AT_PHNUM, elf_header->program_header_num);
        if (int_header != nullptr) { auxv.emplace_back(NEUTRON_AT_BASE, int_shift); }
//            auxv.emplace_back(NEUTRON_AT_FLAGS, 0);
        auxv.emplace_back(NEUTRON_AT_ENTRY, elf_entry);
        auxv.emplace_back(NEUTRON_AT_UID, getuid());
        auxv.emplace_back(NEUTRON_AT_EUID, geteuid());
        auxv.emplace_back(NEUTRON_AT_GID, getgid());
        auxv.emplace_back(NEUTRON_AT_EGID, getegid());
//            auxv.emplace_back(NEUTRON_AT_SECURE, 0);

        if (!load_aux_vec(arg, env, auxv)) {
            neutron_warn("failed to build argument, environment or auxiliary information!");
            return false;
        }

        /// initialize registers
        pc = static_cast<XLenT>(int_header == nullptr ? elf_entry : int_entry);
        return (pc & (RISCV_IALIGN / 8 - 1)) == 0; // check instruction align
    }

    bool load_elf(const char *elf_name, const ArgumentT &arg, const EnviromentT &env) {
        auto elf_visitor = elf::MappedFileVisitor::open_elf(elf_name);
        if (elf_visitor.get_fd() == -1) {
            neutron_warn("Failed to open ELF file!");
            return false;
        }

        return load_elf(elf_visitor, arg, env);
    }

    template<typename T>
    T *address(UXLenT addr, riscv_isa::MemoryProtection prot) {
        static_assert(sizeof(T) == 1 || sizeof(T) == 2 || sizeof(T) == 4 ||
                      sizeof(T) == 8 || sizeof(T) == 16, "wrong type!");
        if (addr & (sizeof(T) - 1)) { return nullptr; }
        auto before = --mem_areas.upper_bound(addr);
        if (addr >= before->first + before->second.size) { return nullptr; }
        if ((static_cast<u8>(before->second.protection) & static_cast<u8>(prot)) !=
            static_cast<u8>(prot)) { return nullptr; }
        return reinterpret_cast<T *>(static_cast<u8 *>(before->second.physical) -
                                     before->first + addr);
    }

    MemoryArea get_memory_area(UXLenT addr, riscv_isa::MemoryProtection prot) {
        auto before = --mem_areas.upper_bound(addr);
        if (addr >= before->first + before->second.size) { return MemoryArea{0, 0, nullptr}; }
        if ((static_cast<u8>(before->second.protection) & static_cast<u8>(prot)) !=
            static_cast<u8>(prot)) { return MemoryArea{0, 0, nullptr}; }
        return MemoryArea{
               /* start */ before->first,
               /* end */ before->first + before->second.size,
               /* shift */ static_cast<u8 *>(before->second.physical) - before->first,
        };
    }

    bool memory_copy_to_guest(UXLenT dest, const void *src, UXLenT size) {
        if (MEM_END - dest < size) { return false; }

        std::vector<::iovec> buf{};
        if (!memory_get_vector(dest, size, riscv_isa::W_BIT, buf)) { return false; }

        for (auto &item: buf) {
            memcpy(item.iov_base, src, item.iov_len);
            src = reinterpret_cast<const u8 *>(src) + item.iov_len;
        }

        return true;
    }

    bool memory_copy_from_guest(void *dest, UXLenT src, UXLenT size) {
        if (MEM_END - src < size) return false;

        std::vector<::iovec> buf{};
        if (!memory_get_vector(src, size, riscv_isa::R_BIT, buf)) return false;

        for (auto &item: buf) {
            memcpy(dest, item.iov_base, item.iov_len);
            dest = reinterpret_cast<u8 *>(dest) + item.iov_len;
        }

        return true;
    }

    bool string_copy_from_guest(UXLenT src, Array<char> &buf) {
        auto before = --mem_areas.upper_bound(src);
        UXLenT addr = src;
        UXLenT len = 0;

        while (true) {
            if (addr - before->first >= before->second.size) { return false; }
            if ((static_cast<u8>(before->second.protection) & riscv_isa::R_BIT) == 0) {
                return false;
            }

            UXLenT offset = addr - before->first;
            UXLenT size = before->second.size - offset;
            const char *ptr = reinterpret_cast<const char *>(before->second.physical) + offset;
            UXLenT this_len = strnlen(ptr, size);
            len += this_len;

            if (this_len != size) {
                ++len;
                break;
            }

            ++before;
            addr += len;
        }

        Array<char> dest{len};

        if (!memory_copy_from_guest(dest.begin(), src, len)) { neutron_unreachable(""); }

        buf = std::move(dest);

        return true;
    }

    bool memory_convert_io_vec(UXLenT iov, UXLenT iovcnt, UXLenT prot, std::vector<::iovec> &buf) {
        bool ret = false;

        Array<iovec<xlen>> vec{iovcnt};
        usize vec_size = iovcnt * sizeof(iovec<xlen>);

        if (memory_copy_from_guest(vec.begin(), iov, vec_size)) {
            buf.reserve(iovcnt);

            for (usize i = 0; i < iovcnt; ++i) {
                UXLenT base = vec[i].base;
                UXLenT size = vec[i].len;

                auto before = --mem_areas.upper_bound(base);

                while (size > 0) {
                    if (base - before->first >= before->second.size) { return ret; }
                    if ((static_cast<u8>(before->second.protection) & prot) == 0) { return ret; }

                    UXLenT byte = std::min(before->second.size + before->first - base, size);

                    buf.emplace_back(::iovec{
                            reinterpret_cast<u8 *>(before->second.physical) - before->first + base,
                            byte
                    });

                    base += byte;
                    size -= byte;
                    ++before;
                }
            }

            ret = true;
        }

        return ret;
    }

    bool memory_get_vector(UXLenT base, UXLenT size, UXLenT prot, std::vector<::iovec> &buf) {
        auto before = --mem_areas.upper_bound(base);

        while (size > 0) {
            if (base - before->first >= before->second.size) return false;
            if ((static_cast<u8>(before->second.protection) & prot) == 0) return false;

            UXLenT byte = std::min(before->second.size + before->first - base, size);

            buf.emplace_back(::iovec{
                    reinterpret_cast<u8 *>(before->second.physical) - before->first + base,
                    byte
            });

            base += byte;
            size -= byte;
            ++before;
        }

        return true;
    }

    UXLenT set_break(UXLenT addr) {
        if (addr < start_brk) return brk;

        UXLenT addr_page = divide_ceil(addr, RISCV_PAGE_SIZE) * RISCV_PAGE_SIZE;
        UXLenT brk_page = divide_ceil(brk, RISCV_PAGE_SIZE) * RISCV_PAGE_SIZE;

        if (addr_page < brk_page) {
            if (memory_unmap(addr_page, brk_page - addr_page) != 0) {
                return brk;
            }
        } else if (addr_page > brk_page) {
            auto before = mem_areas.upper_bound(addr_page);
            if (before->first < addr_page) { return brk; }

            void *area = mmap(nullptr, addr_page - brk_page, PROT_READ | PROT_WRITE,
                              MAP_SHARED | MAP_ANONYMOUS, -1, 0);
            if (area == MAP_FAILED) { return brk; }

            add_map(brk_page, area, addr_page - brk_page, riscv_isa::MemoryProtection::READ_WRITE);
        }

        brk = addr;
        return brk;
    }

    UXLenT
    memory_map(UXLenT addr, UXLenT length, XLenT prot, XLenT flags, XLenT fd, UXLenT offset) {
        if (MEM_END - length < offset) return -EINVAL;

        bool fix = false;
        void *map = MAP_FAILED;

        auto guest_prot = prot_convert_to_guest(prot);
        auto host_prot = prot_convert_to_host(prot);

        UXLenT guest_addr = addr / RISCV_PAGE_SIZE * RISCV_PAGE_SIZE;
        UXLenT guest_length = divide_ceil(length, RISCV_PAGE_SIZE) * RISCV_PAGE_SIZE;
        int host_flags = 0;

        if ((flags & NEUTRON_MAP_SHARED) > 0) { host_flags |= MAP_SHARED; }
        if ((flags & NEUTRON_MAP_PRIVATE) > 0) { host_flags |= MAP_PRIVATE; }
        if ((flags & NEUTRON_MAP_FIXED) > 0) {
            if (addr != guest_addr) {
                return -EINVAL;
            }

            fix = true;
        }
        if ((flags & NEUTRON_MAP_ANONYMOUS) > 0) { host_flags |= MAP_ANONYMOUS; }
        if ((flags & NEUTRON_MAP_GROWSDOWN) > 0) { neutron_abort("MAP_GROWSDOWN not support!"); }
        if ((flags & NEUTRON_MAP_LOCKED) > 0) { neutron_abort("MAP_LOCKED not support!"); }
        if ((flags & NEUTRON_MAP_NORESERVE) > 0) { host_flags |= MAP_NORESERVE; }
        if ((flags & NEUTRON_MAP_POPULATE) > 0) { neutron_abort("MAP_POPULATE not support!"); }
        if ((flags & NEUTRON_MAP_NONBLOCK) > 0) { neutron_abort("MAP_NONBLOCK not support!"); }
        if ((flags & NEUTRON_MAP_STACK) > 0) { neutron_abort("MAP_STACK not support!"); }
        if ((flags & NEUTRON_MAP_HUGETLB) > 0) { neutron_abort("MAP_HUGETLB not support!"); }
        if ((flags & NEUTRON_MAP_SYNC) > 0) { neutron_abort("MAP_SYNC not support!"); }
        if ((flags & NEUTRON_MAP_FIXED_NOREPLACE) > 0) {
            neutron_abort("MAP_FIXED_NOREPLACE not support!");
        }

        if (fix) {
            UXLenT ret = memory_unmap(guest_addr, guest_length);
            if (ret != 0) { return ret; }
        } else {
            guest_addr = guest_memory_allocate(guest_addr, guest_length);
            if (guest_addr == 0) { return -ENOMEM; }
        }

        map = mmap(nullptr, length, host_prot, host_flags, get_host_fd(fd), offset);

        if (map != MAP_FAILED) {
            add_map(guest_addr, map, guest_length, guest_prot);
            return guest_addr;
        } else {
            return -errno;
        }
    }

    XLenT memory_protection(UXLenT offset, UXLenT length, XLenT prot) {
        if (offset % RISCV_PAGE_SIZE != 0 || MEM_END - length < offset) return -EINVAL;

        auto guest_prot = prot_convert_to_guest(prot);
        auto host_prot = prot_convert_to_host(prot);

        auto before = --mem_areas.upper_bound(offset);

        std::vector<std::pair<UXLenT, MemArea>> new_area{};

        while (length > 0) {
            if (offset >= before->first + before->second.size) return -EINVAL;

            UXLenT size = std::min(length, before->first + before->second.size - offset);

            if (mprotect(
                    static_cast<u8 *>(before->second.physical) + offset - before->first,
                    size, host_prot) == -1) {
                return -errno;
            }

            if (before->second.protection != guest_prot) {
                if (offset == before->first) {
                    if (offset + size >= before->second.size + before->first) {
                        before->second.protection = guest_prot;
                    } else {
                        new_area.emplace_back(offset + size, MemArea{
                                /* physical */ static_cast<u8 *>(before->second.physical) +
                                               offset + size - before->first,
                                /* size */ before->second.size + before->first - offset - size,
                                /* protection */ before->second.protection,
                        });

                        before->second.size = offset + size - before->first;
                        before->second.protection = guest_prot;
                    }
                } else {
                    if (offset + size >= before->second.size + before->first) {
                        new_area.emplace_back(offset, MemArea{
                                /* physical */ static_cast<u8 *>(before->second.physical) +
                                               offset - before->first,
                                /* size */ size,
                                /* protection */ guest_prot,
                        });

                        before->second.size = offset - before->first;
                    } else {
                        new_area.emplace_back(offset, MemArea{
                                /* physical */ static_cast<u8 *>(before->second.physical) +
                                               offset - before->first,
                                /* size */ size,
                                /* protection */ guest_prot,
                        });
                        new_area.emplace_back(offset + size, MemArea{
                                /* physical */ static_cast<u8 *>(before->second.physical) +
                                               offset + size - before->first,
                                /* size */ before->second.size + before->first - offset - size,
                                /* protection */ before->second.protection,
                        });

                        before->second.size = offset - before->first;
                    }
                }
            }

            length -= size;
            offset += size;
            ++before;
        }

        for (auto &item: new_area) { mem_areas.emplace(item); }

        return 0;
    }

    XLenT memory_unmap(UXLenT offset, UXLenT length) {
        auto before = --mem_areas.upper_bound(offset);

        std::vector<std::pair<UXLenT, MemArea>> new_area{};
        std::vector<typename std::map<UXLenT, MemArea>::iterator> old_area{};

        while (before != mem_areas.end()) {
            if (offset >= before->first + before->second.size) {
                ++before;
                continue;
            }

            if (offset + length <= before->first) {
                break;
            }

            offset = std::max(offset, before->first);
            UXLenT size = std::min(length, before->first + before->second.size - offset);

            if (munmap(static_cast<u8 *>(before->second.physical) + offset
                       - before->first, size) == -1) {
                return -errno;
            }

            if (offset == before->first) {
                if (offset + size >= before->second.size + before->first) {
                    old_area.emplace_back(before);
                } else {
                    old_area.emplace_back(before);

                    new_area.emplace_back(offset + size, MemArea{
                            /* physical */ static_cast<u8 *>(before->second.physical) +
                                           offset + size - before->first,
                            /* size */ before->second.size + before->first - offset - size,
                            /* protection */ before->second.protection,
                    });
                }
            } else {
                if (offset + size >= before->second.size + before->first) {
                    before->second.size = offset - before->first;
                } else {
                    new_area.emplace_back(offset + size, MemArea{
                            /* physical */ static_cast<u8 *>(before->second.physical) +
                                           offset + size - before->first,
                            /* size */ before->second.size + before->first - offset - size,
                            /* protection */ before->second.protection,
                    });

                    before->second.size = offset - before->first;
                }
            }

            ++before;
        }

        for (auto &item: old_area) { mem_areas.erase(item); }

        for (auto &item: new_area) { mem_areas.emplace(item); }

        return 0;
    }

    void dump_map(std::ostream &stream) {
        for (auto &item: mem_areas) {
            stream << std::hex
                   << std::setw(sizeof(UXLenT) * 2) << std::setfill('0') << item.first << ':'
                   << std::setw(sizeof(UXLenT) * 2) << std::setfill('0')
                   << item.first + item.second.size << ':'
                   << std::setw(sizeof(UXLenT) * 2) << std::setfill('0') << item.second.size << ' '
                   << ((item.second.protection & riscv_isa::R_BIT) > 0 ? 'R' : ' ')
                   << ((item.second.protection & riscv_isa::W_BIT) > 0 ? 'W' : ' ')
                   << ((item.second.protection & riscv_isa::X_BIT) > 0 ? 'X' : ' ')
                   << std::dec << std::endl;
        }
    }

    std::string get_host_file_name(const char *name) {
        // todo: regularize file name

        std::string sysroot_name = sysroot + name;

        if (name[0] == '/') {
            if (strncmp(name, "/etc", 4) == 0 ||
                access(sysroot_name.c_str(), F_OK) == 0) {
                return sysroot_name;
            }
        }

        return name;
    }

    /// dir_fd: host fd
    std::string get_host_file_name(int dir_fd, const char *name) {
        if (name[0] == '/') {
            return get_host_file_name(name);
        } else {
            // todo: errno

            std::stringstream tmp{};
            tmp << "/proc/self/fd/" << dir_fd;

            char buf[PATH_MAX]{};
            isize num = readlink(tmp.str().c_str(), buf, PATH_MAX);
            if (num == -1) return "";

            std::stringstream abs_name{};
            abs_name << buf << name;
            return get_host_file_name(abs_name.str().c_str());
        }
    }

    std::string get_guest_file_name(const char *name) {
        // todo: regularize name

        if (strncmp(name, sysroot.data(), sysroot.size()) == 0) {
            name += sysroot.size();
        }

        if (name[0] == '\0') {
            name = "/";
        }

        return name;
    }

    int get_host_fd(int fd) {
        if (fd < 0) { return fd; }

        auto ptr = fd_map.find(fd);

        if (ptr != fd_map.end()) {
            return ptr->second;
        } else {
            return -1;
        }
    }

    int get_guest_fd(int fd) {
        if (fd < 0) return fd;

        int ret = fd_free_lower_bound;
        for (auto &item: fd_map) {
            if (item.first == ret) {
                ++ret;
            } else {
                break;
            }
        }

        fd_map.emplace(ret, fd);

        fd_free_lower_bound = ret + 1;

        return ret;
    }

    void set_close_exec(int fd, bool flag) {
        if (flag) {
            close_execute.emplace(fd);
        } else {
            close_execute.erase(fd);
        }
    }

    /// close guest fd
    int close_fd(int fd) {
        int ret;

        if (fd < 0) {
            return -EBADF;
        } else {
            auto ptr = fd_map.find(fd);

            if (ptr != fd_map.end()) {
                ret = close(ptr->second);

                if (ret == -1) {
                    ret = -errno;
                }

                fd_map.erase(fd);
                close_execute.erase(fd);

                fd_free_lower_bound = std::min(fd_free_lower_bound, fd);
            } else {
                ret = -EBADF;
            }
        }

        return ret;
    }

    ~LinuxProgram() { drop(); }
};
}


#endif //NEUTRON_RISCV_LINUX_PROGRAM_HPP
