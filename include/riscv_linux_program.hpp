#ifndef NEUTRON_RISCV_LINUX_PROGRAM_HPP
#define NEUTRON_RISCV_LINUX_PROGRAM_HPP


#include <sys/stat.h>


namespace neutron {
    template<typename xlen=xlen_trait>
    class LinuxProgram {
    private:
        using XLenT = typename xlen::XLenT;
        using UXLenT = typename xlen::UXLenT;

    public:
        static constexpr UXLenT R_BIT = 2;
        static constexpr UXLenT W_BIT = 4;
        static constexpr UXLenT X_BIT = 8;

        enum MemoryProtection : UXLenT {
            READ = R_BIT,
            READ_WRITE = R_BIT | W_BIT,
            EXECUTE = X_BIT,
            EXECUTE_READ = X_BIT | R_BIT,
            EXECUTE_READ_WRITE = X_BIT | R_BIT | W_BIT,
        };

        static constexpr UXLenT MEM_TOP = 0xC0000000;

        // todo: just random number
        static constexpr UXLenT STACK_TOP = 0xBFFF0000;
        static constexpr UXLenT STACK_SIZE = 0xA00000;

        static constexpr UXLenT PROGRAM_TOP = 0xB0000000;
        static constexpr UXLenT HEAP_TOP = 0xBFFF0000;

    private:
        struct MemArea {
            void *physical;
            UXLenT size;
            MemoryProtection protection;
        };

        usize host_page_size;
        std::map<UXLenT, MemArea> mem_areas;
        UXLenT brk;
        UXLenT start_brk, end_brk;

    public:
        IntegerRegister<xlen_trait> int_reg;
        XLenT pc;

        LinuxProgram() : mem_areas{}, brk{0}, int_reg{}, pc{0} {
            host_page_size = sysconf(_SC_PAGE_SIZE);
            if (host_page_size <= 0) riscv_isa_abort("cannot get host page size!");
        }

        LinuxProgram(const LinuxProgram &other) = delete;

        LinuxProgram &operator=(const LinuxProgram &other) = delete;

        bool load_elf(MappedFileVisitor &visitor) {
            auto *elf_header = ELF32Header::read(visitor);
            if (elf_header == nullptr || elf_header->file_type != ELF32Header::EXECUTABLE) return false;

            auto *section_header_string_table_header = ELF32SectionHeader::cast<ELF32StringTableHeader>(
                    &elf_header->sections(visitor)[elf_header->string_table_index], visitor);
            if (section_header_string_table_header == nullptr) return false;

            for (auto &program: elf_header->programs(visitor)) {
                auto *loadable = ELF32ProgramHeader::cast<ELF32ExecutableHeader>(&program, visitor);
                if (loadable == nullptr) continue;

                if (PROGRAM_TOP <= loadable->mem_size ||
                    loadable->virtual_address >= PROGRAM_TOP - loadable->mem_size)
                    return false;

                UXLenT mem_addr = loadable->virtual_address;
                UXLenT mem_addr_map = mem_addr / RISCV_PAGE_SIZE * RISCV_PAGE_SIZE;
                UXLenT start_padding = mem_addr - mem_addr_map;

                UXLenT file_addr = loadable->offset - start_padding; // todo: file not page aligned

                UXLenT file_size = loadable->file_size < loadable->mem_size ? loadable->file_size : loadable->mem_size;
                UXLenT mem_size = loadable->mem_size;

                file_size += start_padding;
                mem_size += start_padding;

                UXLenT file_page = divide_ceil(file_size, RISCV_PAGE_SIZE);
                UXLenT mem_page = divide_ceil(mem_size, RISCV_PAGE_SIZE);

                if (mem_page >= xlen_trait::UXLenMax / RISCV_PAGE_SIZE) return false;

                UXLenT file_map = file_page * RISCV_PAGE_SIZE;
                UXLenT mem_map = mem_page * RISCV_PAGE_SIZE;

                bool execute = loadable->is_execute();
                bool write = loadable->is_write();
                bool read = loadable->is_read();

                void *mem_ptr = mmap(nullptr, mem_map, PROT_WRITE | PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
                if (mem_ptr == MAP_FAILED) return false;

                if (mmap(mem_ptr, file_map, PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_FIXED, visitor.get_fd(),
                         file_addr) != mem_ptr)
                    return false;

                if (start_padding > 0) memset(static_cast<u8 *>(mem_ptr), 0, start_padding);
                if (file_map > file_size) memset(static_cast<u8 *>(mem_ptr) + file_size, 0, file_map - file_size);

                if (!write) mprotect(mem_ptr, mem_map, PROT_READ);

                LinuxProgram<>::MemoryProtection guest_protect;

                if (execute) {
                    if (write) guest_protect = LinuxProgram<>::EXECUTE_READ_WRITE;
                    else if (read) guest_protect = LinuxProgram<>::EXECUTE_READ;
                    else guest_protect = LinuxProgram<>::EXECUTE;
                } else {
                    if (write) guest_protect = LinuxProgram<>::READ_WRITE;
                    else guest_protect = LinuxProgram<>::READ;
                }

                add_map(loadable->virtual_address, mem_ptr, mem_map, guest_protect);

                brk = brk > mem_addr_map + mem_size ? brk : mem_addr_map + mem_size;
            }

            if (brk == 0) return false;

            start_brk = brk;
            end_brk = STACK_TOP;

            void *stack = mmap(nullptr, STACK_SIZE, PROT_WRITE | PROT_READ, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
            if (stack == MAP_FAILED) return false;
            add_map(STACK_TOP - STACK_SIZE, stack, STACK_SIZE, LinuxProgram<>::READ_WRITE);

            int_reg.set_x(IntegerRegister<>::SP, STACK_TOP - RISCV_PAGE_SIZE);
            pc = static_cast<xlen_trait::XLenT>(elf_header->entry_point);
            return (pc & (RISCV_IALIGN / 8 - 1)) == 0; // check instruction align
        }

        template<typename T>
        T *address_read(UXLenT addr) {
            auto before = mem_areas.upper_bound(addr);
            if (before == mem_areas.begin() || --before == mem_areas.end())
                return nullptr;
            if (addr >= before->first + before->second.size)
                return nullptr;
            if ((before->second.protection & R_BIT) == 0)
                return nullptr;
            return reinterpret_cast<T *>(static_cast<u8 *>(before->second.physical) + (addr - before->first));
        }

        template<typename T>
        T *address_write(UXLenT addr) {
            auto before = mem_areas.upper_bound(addr);
            if (before == mem_areas.begin() || --before == mem_areas.end())
                return nullptr;
            if (addr >= before->first + before->second.size)
                return nullptr;
            if ((before->second.protection & W_BIT) == 0)
                return nullptr;
            return reinterpret_cast<T *>(static_cast<u8 *>(before->second.physical) + (addr - before->first));
        }

        template<typename T>
        T *address_execute(UXLenT addr) {
            auto before = mem_areas.upper_bound(addr);
            if (before == mem_areas.begin() || --before == mem_areas.end()) return nullptr;
            if (addr >= before->first + before->second.size) return nullptr;
            if ((before->second.protection & X_BIT) == 0) return nullptr;
            return reinterpret_cast<T *>(static_cast<u8 *>(before->second.physical) + (addr - before->first));
        }

        bool add_map(UXLenT offset, void *src, UXLenT length, MemoryProtection protection) {
//            if (offset == 0) return false; // todo
//
//            auto after = mem_areas.upper_bound(offset);
//            if (after == mem_areas.begin()) {
//
//            } else {
//
//            }

            mem_areas.emplace(offset, MemArea{src, length, protection});

            return true;
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
            void *area = mmap(nullptr, addr_page - brk_page, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
            if (area == MAP_FAILED) return brk;
            if (!add_map(brk_page, area, addr_page - brk_page, READ_WRITE)) return brk;

            brk = addr;

            return brk;
        }

        ~LinuxProgram() { for (auto &area: mem_areas) munmap(area.second.physical, area.second.size); }
    };
}


#endif //NEUTRON_RISCV_LINUX_PROGRAM_HPP
