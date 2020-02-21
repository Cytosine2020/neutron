#include <fcntl.h>
#include <map>
#include <unordered_map>
#include <riscv_linux_fuzzer.hpp>

#include "riscv_linux_fuzzer.hpp"

using namespace neutron;

#include "target/dump.hpp"

using namespace riscv_isa;


struct BranchTable {
    using UXLenT = xlen_trait::UXLenT;

    std::vector<std::pair<UXLenT, UXLenT>> true_branch, false_branch;
};


int main(int argc, char **argv) {
    if (argc != 2) riscv_isa_abort("receive one file name!");

    int fd = open(argv[1], O_RDONLY | O_SHLOCK);
    if (fd == -1) riscv_isa_abort("open file failed!");

    MappedFileVisitor visitor{};
    if (!visitor.load_file(fd)) riscv_isa_abort("memory map file failed!");

    auto *elf_header = ELF32Header::read(visitor);
    if (elf_header == nullptr) riscv_isa_abort("ELF header broken!");
    if (elf_header->file_type != ELF32Header::EXECUTABLE) riscv_isa_abort("ELF file not executable!");

    auto *section_string_table_header = elf_header->get_section_string_table_header(visitor);
    if (section_string_table_header == nullptr) riscv_isa_abort("Broken section header string table!");
    auto section_string_table = section_string_table_header->get_string_table(visitor);

    ELF32StringTableHeader *string_table_header = nullptr;

    for (auto &section: elf_header->sections(visitor)) {
        char *name = section_string_table.get_str(section.name);

        if (strcmp(name, ".strtab") == 0) {
            if (string_table_header != nullptr) riscv_isa_abort("more than one string table!");
            string_table_header = ELF32SectionHeader::cast<ELF32StringTableHeader>(&section, visitor);
            if (string_table_header == nullptr) riscv_isa_abort("broken string table!");
        }
    }

    if (string_table_header == nullptr) riscv_isa_abort("no string table!");
    auto string_table = string_table_header->get_string_table(visitor);

    std::map<u32, ELF32SymbolTableHeader::SymbolTableEntry &> objects, functions;

    for (auto &section: elf_header->sections(visitor)) {
        auto *symbol_table_header = ELF32SectionHeader::cast<ELF32SymbolTableHeader>(&section, visitor);
        if (symbol_table_header == nullptr) continue;

        for (auto &symbol: symbol_table_header->get_symbol_table(visitor)) {
            switch (symbol.get_type()) {
                case ELF32SymbolTableHeader::OBJECT:
                    objects.emplace(symbol.value, symbol);
                    break;
                case ELF32SymbolTableHeader::FUNC:
                    functions.emplace(symbol.value, symbol);
                    break;
                default:
                    break;
            }
        }
    }

    Dump dump{std::cout};

    for (auto &section: elf_header->sections(visitor)) {
        if (section.section_type != ELF32SectionHeader::PROGRAM_BITS) continue;

        char *section_name = section_string_table.get_str(section.name);
        if (section_name == nullptr) riscv_isa_abort("Broken section header string table!");
//        std::cout << std::endl << "Disassembly of section " << section_name << ":\n" << std::endl;

        for (auto &item: functions) {
            auto &func = item.second;

            if (&section != &elf_header->sections(visitor)[func.section_header_index]) continue;

            const char *name = func.name == 0 ? "[no name]" : string_table.get_str(func.name);
            if (name == nullptr) riscv_isa_abort("Broken string table!");

//            std::cout << std::hex << func.value << std::dec << " <" << name << ">:" << std::endl;

            void *start = visitor.address((func.value - section.address) + section.offset, func.size);
            if (start == nullptr) riscv_isa_abort("Broken symbol table!");

//            usize offset = 0;
//            while (offset < func.size) {
//                std::cout << std::hex << func.value + offset << std::dec << '\t';
//                // todo: deal with out of boundary
//                offset += dump.visit(reinterpret_cast<Instruction *>(static_cast<u8 *>(start) + offset));
//                std::cout << std::endl;
//            }

//            std::cout << std::endl;
        }
    }

    LinuxProgram<> mem{};
    if (!mem.load_elf(visitor)) riscv_isa_abort("ELF file broken!");

    LinuxRecordHart record_hart{0, mem};
    ExecuteRecord record = record_hart.start();

    LinuxProgram<> mem_2{};
    if (!mem_2.load_elf(visitor)) riscv_isa_abort("ELF file broken!");

    LinuxCompareHart compare_hart{0, mem_2, record, 0, static_cast<u8>(rand())};
    compare_hart.start();

    if (close(fd) != 0) riscv_isa_abort("Close file failed!");
}
