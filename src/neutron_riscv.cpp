#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "riscv_linux.hpp"

using namespace neutron;


int main(int argc, char **argv) {
    if (argc != 2) riscv_isa_abort("receive one file name!");

    usize page_size = sysconf(_SC_PAGE_SIZE);

    int fd = open(argv[1], O_RDONLY | O_SHLOCK);
    if (fd == -1) riscv_isa_abort("open file failed!");

    struct stat file_stat{};
    if (fstat(fd, &file_stat) != 0) riscv_isa_abort("fstat file failed!");
    usize size = file_stat.st_size;

    void *file = mmap(nullptr, size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (file == MAP_FAILED) riscv_isa_abort("Memory mapped io failed!");

    MappedFileVisitor visitor{file, size};

    auto *elf_header = ELF32Header::read(visitor);
    if (elf_header == nullptr) riscv_isa_abort("Incompatible format or broken file!");
    if (elf_header->file_type != ELF32Header::EXECUTABLE) riscv_isa_abort("Not an executable file!");

//    std::cout << *elf_header << std::endl;

    auto *section_header_string_table_header = ELF32SectionHeader::cast<ELF32StringTableHeader>(
            &elf_header->sections(visitor)[elf_header->string_table_index], visitor);
    if (section_header_string_table_header == nullptr) riscv_isa_abort("Broken section header string table!");
//    auto section_header_string_table = section_header_string_table_header->get_string_table(visitor);

    LinuxMemory<> mem{};

    for (auto &program: elf_header->programs(visitor)) {
//        std::cout << program << std::endl;

        auto *loadable = ELF32ProgramHeader::cast<ELF32ExecutableHeader>(&program, visitor);

        if (loadable != nullptr) {
            u32 file_size = loadable->file_size < loadable->mem_size ? loadable->file_size : loadable->mem_size;
            u32 mem_size = loadable->mem_size;

            u32 file_page = file_size == 0 ? 0 : (file_size - 1) / page_size + 1;
            u32 mem_page = mem_size == 0 ? 0 : (mem_size - 1) / page_size + 1;

            if (mem_page >= xlen_trait::UXLenMax / page_size) riscv_isa_abort("ELF file broken!");

            u32 file_map = file_page * page_size;
            u32 mem_map = mem_page * page_size;

            bool execute = loadable->is_execute();
            bool write = loadable->is_write();
            bool read = loadable->is_read();

            void *mem_ptr = mmap(nullptr, mem_map, PROT_WRITE | PROT_READ, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
            if (mem_ptr == MAP_FAILED) riscv_isa_abort("Loading program failed!");

            if (mmap(mem_ptr, file_map, PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_FIXED, fd, program.offset) != mem_ptr)
                riscv_isa_abort("Loading program failed!");

            if (file_map > file_size) memset(static_cast<u8 *>(mem_ptr) + file_size, 0, file_map - file_size);

            mprotect(mem_ptr, mem_map, write ? PROT_WRITE | PROT_READ : PROT_READ);

            LinuxMemory<>::MemoryProtection guest_protect;

            if (execute) {
                if (write) guest_protect = LinuxMemory<>::EXECUTE_READ_WRITE;
                else if (read) guest_protect = LinuxMemory<>::EXECUTE_READ;
                else guest_protect = LinuxMemory<>::EXECUTE;
            } else {
                if (write) guest_protect = LinuxMemory<>::READ_WRITE;
                else guest_protect = LinuxMemory<>::READ;
            }

            mem.add_map(loadable->virtual_address, mem_ptr, mem_map, guest_protect);
        }
    }

//    ELF32StringTableHeader *string_table_header = nullptr;
//
//    for (auto &section: elf_header->sections(visitor)) {
//        char *name = section_header_string_table.get_str(section.name);
//        if (name == nullptr) riscv_isa_abort("Broken section header string table!");
//        std::cout << section_header_string_table.get_str(section.name) << ": " << section.section_type
//                  << ", " << section.size << std::endl;
//
//        if (strcmp(name, ".strtab") == 0) {
//            if (string_table_header != nullptr) riscv_isa_abort("Multiple string table!");
//            string_table_header = ELF32SectionHeader::cast<ELF32StringTableHeader>(&section, visitor);
//            if (string_table_header == nullptr) riscv_isa_abort("Broken string table!");
//        }
//    }
//
//    if (string_table_header == nullptr) riscv_isa_abort("No string table!");
//    auto shared_string_table = string_table_header->get_string_table(visitor);
//
//    for (auto &section: elf_header->sections(visitor)) {
//        auto *symbol_table_header = ELF32SectionHeader::cast<ELF32SymbolTableHeader>(&section, visitor);
//        if (symbol_table_header != nullptr) {
//            for (auto &symbol: symbol_table_header->get_symbol_table(visitor)) {
//                const char *name = symbol.name == 0 ? "[no name]" : shared_string_table.get_str(symbol.name);
//                if (name == nullptr) riscv_isa_abort("Broken string table!");
//                std::cout << symbol.get_type() << '\t' << symbol.get_bind() << '\t' << symbol.get_visibility()
//                          << '\t' << name << std::endl;
//            }
//        }
//    }

    constexpr u32 STACK_TOP = 0xBFFF0000;
    constexpr u32 STACK_SIZE = 0xA00000;

    void *stack = mmap(nullptr, STACK_SIZE, PROT_WRITE | PROT_READ, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    if (stack == MAP_FAILED) riscv_isa_abort("Loading program failed!");

    mem.add_map(STACK_TOP - STACK_SIZE, stack, STACK_SIZE, LinuxMemory<>::READ_WRITE);

    IntegerRegister<> reg{};
    reg.set_x(IntegerRegister<>::SP, STACK_TOP - 0x1000);
    LinuxHart core{static_cast<xlen_trait::XLenT>(elf_header->entry_point), reg, mem};

    munmap(file, size);

    mem.brk_init();
    core.start();

    if (close(fd) != 0) riscv_isa_abort("Close file failed!");
}
