#include <fcntl.h>
#include <map>
#include <set>

#include "neutron_utility.hpp"
#include "riscv_blocking.hpp"
#include "riscv_linux_fuzzer.hpp"

using namespace neutron;


struct BranchTable {
    using UXLenT = riscv_isa::xlen_trait::UXLenT;

    std::vector<std::pair<UXLenT, UXLenT>> true_branch, false_branch;
};


using UXLenT = riscv_isa::xlen_trait::UXLenT;
using XLenT = riscv_isa::xlen_trait::XLenT;


int main(int argc, char **argv) {
    if (argc != 2) neutron_abort("receive one file name!");

    int fd = open(argv[1], O_RDONLY | O_SHLOCK);
    if (fd == -1) neutron_abort("open file failed!");

    elf::MappedFileVisitor visitor{};
    if (!visitor.load_file(fd)) neutron_abort("memory map file failed!");

    auto *elf_header = elf::ELF32Header::read(visitor);
    if (elf_header == nullptr) neutron_abort("ELF header broken!");
    if (elf_header->file_type != elf::ELF32Header::EXECUTABLE) neutron_abort("ELF file not executable!");

    elf::ELF32StringTableHeader *string_table_header = elf_header->get_string_table_header(visitor);
    if (string_table_header == nullptr) neutron_abort("ELF file broken!");
    auto string_table = string_table_header->get_string_table(visitor);

    std::map<u32, elf::ELF32SymbolTableHeader::SymbolTableEntry &> objects, functions;

    for (auto &section: elf_header->sections(visitor)) {
        auto *symbol_table_header = elf::ELF32SectionHeader::cast<elf::ELF32SymbolTableHeader>(&section, visitor);
        if (symbol_table_header == nullptr) continue;

        for (auto &symbol: symbol_table_header->get_symbol_table(visitor)) {
            switch (symbol.get_type()) {
                case elf::ELF32SymbolTableHeader::OBJECT:
                    objects.emplace(symbol.value, symbol);
                    break;
                case elf::ELF32SymbolTableHeader::FUNC:
                    functions.emplace(symbol.value, symbol);
                    break;
                default:
                    break;
            }
        }
    }

    for (auto &section: elf_header->sections(visitor)) {
        if (section.section_type != elf::ELF32SectionHeader::PROGRAM_BITS) continue;

        for (auto &function: functions) {
            auto &func = function.second;
            if (&section != &elf_header->sections(visitor)[func.section_header_index]) continue;

            const char *name = string_table.get_str(func.name, "[no name]");
            if (name == nullptr) neutron_abort("ELF file broken!");

            std::cout << std::hex << func.value << std::dec << " <" << name << ">:" << std::endl;

            void *start = visitor.address((func.value - section.address) + section.offset, func.size);
            if (start == nullptr) neutron_abort("ELF file broken!");

            auto blocks = BlockVisitor{}.blocking(func.value, start, func.size);

            for (auto &block: blocks) {
                std::cout << std::hex << block.first << '\t' << block.second.first;
                if (block.second.first != block.second.second)
                    std::cout << '\t' << block.second.second;
                std::cout << std::dec << std::endl;
            }
            std::cout << std::endl;

            std::map<UXLenT, std::set<UXLenT>> pos_dominator{};
            std::set<UXLenT> all{};

            for (auto &block: blocks) all.emplace(block.first);
            all.emplace(0);

            for (auto &block: blocks) pos_dominator[block.first] = all;
            pos_dominator[0].emplace(0);

            for (bool flag = true; flag;) {
                flag = false;
                for (auto item = blocks.rbegin(); item != blocks.rend(); ++item) {
                    auto &origin_set = pos_dominator[item->first];
                    usize origin_size = origin_set.size();

                    std::set<UXLenT> intersection{};

                    if (item->second.first == item->second.second) {
                        intersection = pos_dominator[item->second.first];
                    } else {
                        auto &successor1 = pos_dominator[item->second.first];
                        auto &successor2 = pos_dominator[item->second.second];

                        std::set_intersection(successor1.begin(), successor1.end(),
                                              successor2.begin(), successor2.end(),
                                              std::inserter(intersection, intersection.begin()));
                    }

                    intersection.emplace(item->first);
                    origin_set = std::move(intersection);

                    if (origin_size != origin_set.size()) flag = true;
                }
            }

            pos_dominator.erase(0);

            for (auto &item: pos_dominator) item.second.erase(item.first);

            std::map<UXLenT, UXLenT> sync_point{};

            for (bool flag = true; flag;) {
                std::map<UXLenT, UXLenT> new_set{};

                for (auto &item: pos_dominator)
                    if (item.second.size() == 1)
                        new_set.emplace(item.first, *item.second.begin());

                flag = !new_set.empty();

                for(auto &item: new_set) {
                    for (auto &set: pos_dominator)
                        set.second.erase(item.second);
                    sync_point.emplace(item.first, item.second);
                    pos_dominator.erase(item.first);
                }
            }

            for (auto &item: pos_dominator)
                sync_point[item.first] = 0;

            for (auto &item: sync_point)
                std::cout << std::hex << item.first << '\t' << item.second << std::dec << std::endl;
            std::cout << std::endl;

            // todo: bitset opt
        }
    }

    LinuxProgram<> mem{};
    if (!mem.load_elf(visitor)) neutron_abort("ELF file broken!");

    LinuxRecordHart record_hart{0, mem};
    ExecuteRecord record = record_hart.start();

    LinuxProgram<> mem_2{};
    if (!mem_2.load_elf(visitor)) neutron_abort("ELF file broken!");

    LinuxCompareHart compare_hart{0, mem_2, record, 0, static_cast<u8>(rand())};
    compare_hart.start();

    if (close(fd) != 0) neutron_abort("Close file failed!");
}
