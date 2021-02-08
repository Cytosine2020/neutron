#ifndef NEUTRON_OBJDUMP_HPP
#define NEUTRON_OBJDUMP_HPP


#include <map>
#include <unordered_map>

#include "neutron_utility.hpp"
#include "target/dump.hpp"
#include "elf_header.hpp"


namespace neutron {
template<typename xlen>
bool riscv_objdump(int fd) {
    using UXLenT = typename xlen::UXLenT;

    elf::MappedFileVisitor visitor{};
    if (!visitor.load_file(fd)) return false;

    auto *elf_header = elf::ELFHeader<UXLenT>::read(visitor);
    if (elf_header == nullptr) return false;
    if (elf_header->file_type != elf::ELFHeader<UXLenT>::EXECUTABLE) return false;


    elf::StringTableHeader<xlen> *string_table_header =
            elf_header->get_section_string_table_header(visitor);
    if (string_table_header == nullptr) return false;
    auto string_table = string_table_header->get_table(visitor);

    std::map<UXLenT, typename elf::SymbolTableHeader<UXLenT>::SymbolTableEntry &> objects, functions;

    for (auto &section: elf_header->sections(visitor)) {
        auto *symbol_table_header = elf::SectionHeader<UXLenT>::template
        cast<elf::SymbolTableHeader<UXLenT>>(&section, visitor);
        if (symbol_table_header == nullptr) continue;

        for (auto &symbol: symbol_table_header->get_table(visitor)) {
            switch (symbol.get_type()) {
                case elf::SymbolTableHeader<UXLenT>::OBJECT:
                    objects.emplace(symbol.value, symbol);
                    break;
                case elf::SymbolTableHeader<UXLenT>::FUNCTION:
                    functions.emplace(symbol.value, symbol);
                    break;
                default:
                    break;
            }
        }
    }

    riscv_isa::Dump dump{std::cout};

    for (auto &section: elf_header->sections(visitor)) {
        if (section.section_type != elf::SectionHeader<UXLenT>::PROGRAM_BITS) continue;

        char *section_name = section_string_table.get_str(section.name);
        if (section_name == nullptr) return false;
        std::cout << std::endl << "Disassembly of section " << section_name << ":\n" << std::endl;

        for (auto &item: functions) {
            auto &func = item.second;

            if (&section != &elf_header->sections(visitor)[func.section_header_index]) continue;

            const char *name = string_table.get_str(func.name);
            if (name == nullptr) return false;

            std::cout << std::hex << func.value << std::dec << " <" << name << ">:" << std::endl;

            void *start = visitor.address((func.value - section.address) + section.offset,
                                          func.size);
            if (start == nullptr) return false;

            usize offset = 0;
            while (offset < func.size) {
                std::cout << std::hex << func.value + offset << std::dec << '\t';
                usize inc = dump.visit(
                        reinterpret_cast<riscv_isa::Instruction *>(static_cast<u8 *>(start) +
                                                                   offset),
                        func.size - offset);
                if (inc == 0) break;
                offset += inc;
                std::cout << std::endl;
            }

            std::cout << std::endl;
        }
    }

    return true;
}
}


#endif //NEUTRON_OBJDUMP_HPP
