#include <fcntl.h>
#include <iostream>
#include <sstream>

#include "neutron_utility.hpp"
#include "linux_std.hpp"
#include "riscv_blocking.hpp"
#include "riscv_linux_fuzzer.hpp"
#include "dominator_tree.hpp"

using namespace neutron;


using xlen = riscv_isa::xlen_trait;
using UXLenT = riscv_isa::xlen_trait::UXLenT;
using XLenT = riscv_isa::xlen_trait::XLenT;


class RecordCompare { // todo: record not synchronized
private:
    class Status {
    public:
        std::vector<BranchRecord>::iterator ptr, end;
        std::vector<UXLenT> stack;

        explicit Status(std::vector<BranchRecord> &record) : ptr{record.begin()}, end{record.end()}, stack{0} {}

        void stack_seek(UXLenT target) {
            if (stack.back() == 0) return;
            if (target != stack.back()) neutron_abort("");
            stack.pop_back();

//    isize i = stack.size() - 1;
//    for (; i >= 0; --i)
//        if (target == stack[i])
//            break;
//
//    if (i >= 0)
//        stack.resize(i, 0);
        }

        bool terminate() const { return ptr == end || stack.empty(); }

        bool step(UXLenT stack_top = 0) {
            bool ret = false;

            switch (ptr->type) {
                case BranchRecord::BEQ:
                case BranchRecord::BNE:
                case BranchRecord::BLT:
                case BranchRecord::BGE:
                case BranchRecord::BLTU:
                case BranchRecord::BGEU:
                    break;
                case BranchRecord::JAL:
                    if (is_link(ptr->get_jal_rd()))
                        stack.emplace_back(ptr->address + riscv_isa::JALInst::INST_WIDTH);

                    break;
                case BranchRecord::JALR:
                    if (is_link(ptr->get_jalr_rd())) {
                        if (is_link(ptr->get_jalr_rs1()) && ptr->get_jalr_rd() != ptr->get_jalr_rs1()) {
                            stack_seek(ptr->get_target());
                            if (ptr->get_target() == stack_top)
                                ret = true;
                        }

                        stack.emplace_back(ptr->address + riscv_isa::JALRInst::INST_WIDTH);
                    } else {
                        if (is_link(ptr->get_jalr_rs1())) {
                            stack_seek(ptr->get_target());
                            if (ptr->get_target() == stack_top)
                                ret = true;
                        }
                    }
                    break;
                default:
                    neutron_unreachable("unknown type");
            }

            ++ptr;
            return ret;
        }

        void break_within_function(UXLenT addr) {
            UXLenT stack_top = stack.back();

            while (!terminate()) {
                if (ptr->address == addr || step(stack_top)) break;
            }
        }
    };

    Status origin, modified;
    std::map<UXLenT, UXLenT> &sync_point;
    std::vector<UXLenT> affected_address;
    UXLenT sync_address; // zero stands for return to caller
    bool sync;

    static bool is_link(usize reg) { return reg == 1 || reg == 5; }

    template<typename OP>
    void compare_record_branch() {
        if (origin.ptr->get_op1() != modified.ptr->get_op1() || origin.ptr->get_op2() != modified.ptr->get_op2())
            affected_address.emplace_back(origin.ptr->address);

        if (OP::op(origin.ptr->get_op1(), origin.ptr->get_op2()) !=
            OP::op(modified.ptr->get_op1(), modified.ptr->get_op2())) {
            sync_address = sync_point.find(origin.ptr->address)->second;
            sync = false;
        }
    }

    RecordCompare(std::vector<BranchRecord> &origin, std::vector<BranchRecord> &modified,
                  std::map<UXLenT, UXLenT> &sync_point) :
            origin{origin}, modified{modified}, sync_point{sync_point}, affected_address{}, sync_address{0},
            sync{true} {}

    std::vector<UXLenT> compare() {
        while (true) {
            if (modified.terminate()) {
                while (!origin.terminate()) {
                    origin.step(); // todo: finish origin if modified finished
                }
            }

            if (origin.terminate()) break;

            if (sync) {
                if (origin.ptr->address != modified.ptr->address) neutron_abort("unexpected");
                if (origin.ptr->type != modified.ptr->type) neutron_abort("unexpected");

                switch (origin.ptr->type) {
                    case BranchRecord::BEQ:
                        compare_record_branch<riscv_isa::operators::EQ<xlen>>();
                        break;
                    case BranchRecord::BNE:
                        compare_record_branch<riscv_isa::operators::NE<xlen>>();
                        break;
                    case BranchRecord::BLT:
                        compare_record_branch<riscv_isa::operators::LT<xlen>>();
                        break;
                    case BranchRecord::BGE:
                        compare_record_branch<riscv_isa::operators::GE<xlen>>();
                        break;
                    case BranchRecord::BLTU:
                        compare_record_branch<riscv_isa::operators::LTU<xlen>>();
                        break;
                    case BranchRecord::BGEU:
                        compare_record_branch<riscv_isa::operators::GEU<xlen>>();
                        break;
                    case BranchRecord::JAL:
                        break;
                    case BranchRecord::JALR:
                        if (origin.ptr->get_target() != modified.ptr->get_target()) {
                            affected_address.emplace_back(origin.ptr->address);
                            sync_address = 0;
                            sync = false;
                        }
                        break;
                    default:
                        neutron_unreachable("unknown type");
                }

                origin.step();
                modified.step();
            } else {
                origin.break_within_function(sync_address);
                modified.break_within_function(sync_address);
                sync = true;
            }
        }

        return std::move(affected_address);
    }

public:

    static std::vector<UXLenT> build(std::vector<BranchRecord> &origin, std::vector<BranchRecord> &modified,
                                     std::map<UXLenT, UXLenT> &sync_point) {
        return RecordCompare{origin, modified, sync_point}.compare();
    }
};


bool get_sync_point_for_elf(elf::MappedFileVisitor &visitor, std::map<UXLenT, UXLenT> &sync_point, UXLenT shift) {
    auto *elf_header = elf32::ELFHeader::read(visitor);
    if (elf_header == nullptr) return false;
    auto *strtab_header = elf_header->get_section_header<elf32::StringTableHeader>(".strtab", visitor);
    auto *shstrtab_header = elf_header->get_section_header<elf32::StringTableHeader>(".shstrtab", visitor);
    if (strtab_header == nullptr || shstrtab_header == nullptr) return false;
    auto string_table = strtab_header->get_table(visitor);

    std::map<u32, elf32::SymbolTableHeader::SymbolTableEntry &> functions;

    for (auto &section: elf_header->sections(visitor)) {
        auto *symbol_table_header = elf32::SectionHeader::cast<elf32::SymbolTableHeader>(&section, visitor);
        if (symbol_table_header == nullptr) continue;
        for (auto &symbol: symbol_table_header->get_table(visitor)) {
            switch (symbol.get_type()) {
                case elf32::SymbolTableHeader::FUNCTION:
                    functions.emplace(symbol.value, symbol);
                    break;
                default:
                    break;
            }
        }
    }

    for (auto &function: functions) {
        auto &func = function.second;
        if (func.section_header_index == 0) continue;
        auto &section = elf_header->sections(visitor)[func.section_header_index];

        std::cout << string_table.get_str(func.name) << ':' << std::endl;

        void *start = visitor.address((func.value - section.address) + section.offset, func.size);
        if (start == nullptr) return false;

        auto blocks = BlockVisitor::build(func.value, start, func.size);


        for (auto vertex = blocks.begin(); vertex != blocks.end(); ++vertex) {
            UXLenT first = vertex.get_vertex();
            if (first == 0) continue;
            std::cout << std::hex << '\t' << first + shift << ':';
            for (auto successor: vertex.get_successor()) {
                std::cout << ' ' << (successor == 0 ? 0 : successor + shift);
            }
            std::cout << std::dec << std::endl;
        }

        auto pos_dominator = PosDominatorTree<UXLenT>::build(blocks, 0);

        for (auto &item: pos_dominator) {
            UXLenT first = item.first + shift;
            UXLenT second = item.second == 0 ? 0 : item.second + shift;
            sync_point.emplace(first, second);
            std::cout << '\t' << std::hex << first << ' ' << second << std::dec << std::endl;
        }
    }

    return true;
}

bool get_dynamic_library(elf::MappedFileVisitor &visitor,
                         LinuxProgram<xlen> &pcb,
                         std::vector<std::pair<Array<char>, UXLenT>> &result
) {
    auto *elf_header = elf32::ELFHeader::read(visitor);
    if (elf_header == nullptr) return false;

    auto *dynamic_header = elf_header->get_section_header<elf32::DynLinkingTableHeader>(".dynamic", visitor);
    if (dynamic_header == nullptr) return false;

    UXLenT debug_addr = 0;

    for (auto &program: elf_header->programs(visitor)) {
        if (program.offset <= dynamic_header->offset && dynamic_header->size <= program.file_size &&
            dynamic_header->offset - program.offset <= program.file_size - dynamic_header->size) {

            usize virtual_address = program.virtual_address - program.offset + dynamic_header->offset;

            usize i = 0;
            for (auto &item: dynamic_header->get_table(visitor)) {
                if (item.tag == elf32::DynLinkingTableHeader::DEBUG) { break; }
                ++i;
            }

            debug_addr = virtual_address + dynamic_header->entry_size * i;

            break;
        }
    }

    elf32::DynLinkingTableHeader::Entry debug_entry{};
    if (pcb.memory_copy_from_guest(&debug_entry, debug_addr, sizeof(debug_entry)) != sizeof(debug_entry))
        return false;

    DebugInfo<UXLenT> debug_info{};
    if (pcb.memory_copy_from_guest(&debug_info, debug_entry.val, sizeof(debug_info)) != sizeof(debug_info))
        return false;

    DebugMap<UXLenT> debug_map{};
    for (UXLenT item = debug_info.map; item != 0; item = debug_map.next) {
        if (pcb.memory_copy_from_guest(&debug_map, item, sizeof(debug_map)) != sizeof(debug_map))
            return false;

        Array<char> name{};
        if (!pcb.string_copy_from_guest(debug_map.name, name)) return false;

        if (debug_map.addr != 0) { result.emplace_back(std::move(name), debug_map.addr); }
    }

    return true;
}

int main(int argc, char **argv) {
    if (argc < 2) neutron_abort("receive one file name!");

    elf::MappedFileVisitor visitor = elf::MappedFileVisitor::open_elf(argv[1]);
    if (visitor.get_fd() == -1) neutron_abort("memory map file failed!");

    auto *elf_header = elf32::ELFHeader::read(visitor);
    if (elf_header == nullptr) neutron_abort("ELF header broken!");

    std::vector<u8> origin_input{};
    LinuxProgram<xlen> mem1{true};
    if (!mem1.load_elf(argv[1], argc - 1, argv + 1, environ)) neutron_abort("ELF file broken!");
    auto origin_record = LinuxFuzzerCore{0, mem1, origin_input}.start();

    std::vector<std::pair<Array<char>, UXLenT>> result{};
    if (!get_dynamic_library(visitor, mem1, result)) neutron_warn("Failed to get debug info!");

    const char *system_root = getenv("RISCV_SYSROOT");

    std::map<UXLenT, UXLenT> sync_point{};
    get_sync_point_for_elf(visitor, sync_point, mem1.elf_shift);

    for (auto &item: result) {
        const char *name = item.first.begin();
        UXLenT shift = item.second;
        std::stringstream buf{};
        buf << system_root << name;

        elf::MappedFileVisitor lib_visitor = elf::MappedFileVisitor::open_elf(buf.str().c_str());
        get_sync_point_for_elf(lib_visitor, sync_point, shift);
    }

    for (usize i = 0; i < origin_input.size(); ++i) {
        std::vector<u8> modified_input = origin_input;
        modified_input[i] = static_cast<u8>(rand());

        LinuxProgram<xlen> mem2{};
        if (!mem2.load_elf(argv[1], argc - 1, argv + 1, environ)) neutron_abort("ELF file broken!");
        auto modified_record = LinuxFuzzerCore{0, mem2, modified_input}.start();

        auto affected_address = RecordCompare::build(origin_record, modified_record, sync_point);

        std::cout << "byte " << i << ": " << std::hex;
        for (auto &item: affected_address) {
            std::cout << item << ' ';
        }
        std::cout << std::dec << std::endl;
    }
}
